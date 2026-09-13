/**
 * Xero connector worker for the Newcastle Automotive Solutions app.
 *
 * This is a small Cloudflare Worker that does the parts a browser page can't
 * safely do itself: hold the Xero app's client secret, complete the OAuth2
 * login, and call Xero's Accounting API to create real invoices.
 *
 * There is no per-user login in the app itself, so this worker manages a
 * single shared Xero connection (one Xero organisation) in a KV namespace —
 * that matches the app's own "anyone with the link can use it" design.
 *
 * Endpoints:
 *   GET  /connect?return=<url>   -> redirects the browser into Xero's login
 *   GET  /callback               -> Xero redirects back here after login
 *   GET  /status                 -> { connected, tenantName, connectedAt }
 *   POST /disconnect             -> forgets the stored connection
 *   POST /invoices               -> creates a draft invoice in Xero
 *
 * Required bindings (see SETUP.md):
 *   KV secret/vars   XERO_CLIENT_ID, XERO_CLIENT_SECRET
 *   KV namespace     XERO_KV
 *   optional var     ALLOWED_ORIGIN (defaults to "*")
 *   optional var     DEFAULT_ACCOUNT_CODE (defaults to "200")
 */

const XERO_AUTHORIZE_URL = 'https://login.xero.com/identity/connect/authorize';
const XERO_TOKEN_URL = 'https://identity.xero.com/connect/token';
const XERO_CONNECTIONS_URL = 'https://api.xero.com/connections';
const XERO_API_BASE = 'https://api.xero.com/api.xro/2.0';
const SCOPES = 'openid profile email accounting.transactions accounting.contacts offline_access';
const CONNECTION_KEY = 'connection';
const STATE_TTL_SECONDS = 600; // 10 minutes to complete the Xero login

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);

    if (request.method === 'OPTIONS') {
      return corsResponse(env, new Response(null, { status: 204 }));
    }

    try {
      if (url.pathname === '/connect' && request.method === 'GET') {
        return await handleConnect(url, env);
      }
      if (url.pathname === '/callback' && request.method === 'GET') {
        return await handleCallback(url, env);
      }
      if (url.pathname === '/status' && request.method === 'GET') {
        return await handleStatus(env);
      }
      if (url.pathname === '/disconnect' && request.method === 'POST') {
        return await handleDisconnect(env);
      }
      if (url.pathname === '/invoices' && request.method === 'POST') {
        return await handleCreateInvoice(request, env);
      }
      return corsResponse(env, json({ error: 'not_found' }, 404));
    } catch (err) {
      return corsResponse(env, json({ error: 'server_error', message: String((err && err.message) || err) }, 500));
    }
  },
};

/* ---------------------------- OAuth: connect ---------------------------- */

async function handleConnect(url, env) {
  requireEnv(env, ['XERO_CLIENT_ID', 'XERO_CLIENT_SECRET']);
  const returnUrl = url.searchParams.get('return') || '';
  const state = randomToken();
  await env.XERO_KV.put('state:' + state, JSON.stringify({ returnUrl }), {
    expirationTtl: STATE_TTL_SECONDS,
  });

  const redirectUri = url.origin + '/callback';
  const authorizeUrl = new URL(XERO_AUTHORIZE_URL);
  authorizeUrl.searchParams.set('response_type', 'code');
  authorizeUrl.searchParams.set('client_id', env.XERO_CLIENT_ID);
  authorizeUrl.searchParams.set('redirect_uri', redirectUri);
  authorizeUrl.searchParams.set('scope', SCOPES);
  authorizeUrl.searchParams.set('state', state);

  return Response.redirect(authorizeUrl.toString(), 302);
}

/* --------------------------- OAuth: callback ---------------------------- */

async function handleCallback(url, env) {
  const code = url.searchParams.get('code');
  const state = url.searchParams.get('state');
  const errorParam = url.searchParams.get('error');

  const stateRaw = state ? await env.XERO_KV.get('state:' + state) : null;
  const stateData = stateRaw ? JSON.parse(stateRaw) : { returnUrl: '' };
  if (state) await env.XERO_KV.delete('state:' + state);

  if (errorParam || !code || !stateRaw) {
    return bounceBack(stateData.returnUrl, 'error', errorParam || 'missing_code_or_state');
  }

  const redirectUri = url.origin + '/callback';
  let tokenRes;
  try {
    tokenRes = await exchangeCodeForTokens(env, code, redirectUri);
  } catch (err) {
    return bounceBack(stateData.returnUrl, 'error', 'token_exchange_failed');
  }

  let tenant;
  try {
    tenant = await fetchPrimaryTenant(tokenRes.access_token);
  } catch (err) {
    return bounceBack(stateData.returnUrl, 'error', 'no_xero_organisation');
  }

  await env.XERO_KV.put(
    CONNECTION_KEY,
    JSON.stringify({
      tenantId: tenant.tenantId,
      tenantName: tenant.tenantName,
      refreshToken: tokenRes.refresh_token,
      connectedAt: Date.now(),
    })
  );

  return bounceBack(stateData.returnUrl, 'connected', tenant.tenantName);
}

function bounceBack(returnUrl, xeroParam, extra) {
  if (!returnUrl) {
    return json({ xero: xeroParam, detail: extra });
  }
  const dest = new URL(returnUrl);
  dest.searchParams.set('xero', xeroParam);
  if (extra) dest.searchParams.set('xeroDetail', extra);
  return Response.redirect(dest.toString(), 302);
}

async function exchangeCodeForTokens(env, code, redirectUri) {
  const body = new URLSearchParams({
    grant_type: 'authorization_code',
    code,
    redirect_uri: redirectUri,
  });
  const res = await fetch(XERO_TOKEN_URL, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/x-www-form-urlencoded',
      Authorization: basicAuth(env.XERO_CLIENT_ID, env.XERO_CLIENT_SECRET),
    },
    body: body.toString(),
  });
  if (!res.ok) throw new Error('token exchange failed: ' + res.status);
  return res.json();
}

async function fetchPrimaryTenant(accessToken) {
  const res = await fetch(XERO_CONNECTIONS_URL, {
    headers: { Authorization: 'Bearer ' + accessToken },
  });
  if (!res.ok) throw new Error('connections lookup failed: ' + res.status);
  const connections = await res.json();
  if (!connections || !connections.length) throw new Error('no tenants');
  return { tenantId: connections[0].tenantId, tenantName: connections[0].tenantName };
}

/* ------------------------------- status --------------------------------- */

async function handleStatus(env) {
  const raw = await env.XERO_KV.get(CONNECTION_KEY);
  if (!raw) return corsResponse(env, json({ connected: false }));
  const conn = JSON.parse(raw);
  return corsResponse(
    env,
    json({ connected: true, tenantName: conn.tenantName, connectedAt: conn.connectedAt })
  );
}

async function handleDisconnect(env) {
  await env.XERO_KV.delete(CONNECTION_KEY);
  return corsResponse(env, json({ ok: true }));
}

/* ----------------------------- invoices ---------------------------------- */

async function handleCreateInvoice(request, env) {
  requireEnv(env, ['XERO_CLIENT_ID', 'XERO_CLIENT_SECRET']);
  const raw = await env.XERO_KV.get(CONNECTION_KEY);
  if (!raw) return corsResponse(env, json({ ok: false, error: 'not_connected' }, 409));
  const conn = JSON.parse(raw);

  let payload;
  try {
    payload = await request.json();
  } catch (err) {
    return corsResponse(env, json({ ok: false, error: 'invalid_json' }, 400));
  }

  const customerName = (payload.customerName || '').trim() || 'Unknown customer';
  const lineItems = Array.isArray(payload.lineItems) ? payload.lineItems : [];
  if (!lineItems.length) {
    return corsResponse(env, json({ ok: false, error: 'no_line_items' }, 400));
  }
  const accountCode = payload.accountCode || env.DEFAULT_ACCOUNT_CODE || '200';
  const invoiceDate = payload.date || new Date().toISOString().slice(0, 10);
  const dueDate = payload.dueDate || invoiceDate;

  let accessToken;
  try {
    const refreshed = await refreshAccessToken(env, conn.refreshToken);
    accessToken = refreshed.access_token;
    // Xero rotates refresh tokens on every use — persist the new one or the
    // next call will fail.
    conn.refreshToken = refreshed.refresh_token;
    await env.XERO_KV.put(CONNECTION_KEY, JSON.stringify(conn));
  } catch (err) {
    return corsResponse(env, json({ ok: false, error: 'reauth_required' }, 401));
  }

  let contactId;
  try {
    contactId = await ensureContact(accessToken, conn.tenantId, customerName);
  } catch (err) {
    return corsResponse(env, json({ ok: false, error: 'contact_failed', message: String(err.message || err) }, 502));
  }

  const invoiceBody = {
    Type: 'ACCREC',
    Contact: { ContactID: contactId },
    Date: invoiceDate,
    DueDate: dueDate,
    Reference: payload.reference || '',
    LineAmountType: 'Exclusive',
    Status: payload.authorise ? 'AUTHORISED' : 'DRAFT',
    LineItems: lineItems.map((li) => ({
      Description: String(li.description || 'Item').slice(0, 4000),
      Quantity: li.quantity != null ? li.quantity : 1,
      UnitAmount: Number(li.amount) || 0,
      AccountCode: li.accountCode || accountCode,
      TaxType: 'OUTPUT',
    })),
  };

  let createRes;
  try {
    createRes = await xeroApiFetch(accessToken, conn.tenantId, '/Invoices', {
      method: 'POST',
      body: JSON.stringify({ Invoices: [invoiceBody] }),
    });
  } catch (err) {
    return corsResponse(env, json({ ok: false, error: 'invoice_failed', message: String(err.message || err) }, 502));
  }

  const created = (createRes.Invoices || [])[0];
  if (!created) {
    return corsResponse(env, json({ ok: false, error: 'invoice_not_returned' }, 502));
  }

  return corsResponse(
    env,
    json({
      ok: true,
      invoiceId: created.InvoiceID,
      invoiceNumber: created.InvoiceNumber,
      invoiceUrl: 'https://go.xero.com/AccountsReceivable/View.aspx?InvoiceID=' + created.InvoiceID,
    })
  );
}

async function refreshAccessToken(env, refreshToken) {
  const body = new URLSearchParams({ grant_type: 'refresh_token', refresh_token: refreshToken });
  const res = await fetch(XERO_TOKEN_URL, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/x-www-form-urlencoded',
      Authorization: basicAuth(env.XERO_CLIENT_ID, env.XERO_CLIENT_SECRET),
    },
    body: body.toString(),
  });
  if (!res.ok) throw new Error('refresh failed: ' + res.status);
  return res.json();
}

async function ensureContact(accessToken, tenantId, name) {
  const escaped = name.replace(/"/g, '\\"');
  const query = 'Name=="' + escaped + '"';
  const found = await xeroApiFetch(accessToken, tenantId, '/Contacts?where=' + encodeURIComponent(query));
  const existing = (found.Contacts || [])[0];
  if (existing) return existing.ContactID;

  const createdRes = await xeroApiFetch(accessToken, tenantId, '/Contacts', {
    method: 'PUT',
    body: JSON.stringify({ Contacts: [{ Name: name }] }),
  });
  const created = (createdRes.Contacts || [])[0];
  if (!created) throw new Error('contact not returned');
  return created.ContactID;
}

async function xeroApiFetch(accessToken, tenantId, path, opts) {
  const res = await fetch(XERO_API_BASE + path, {
    method: (opts && opts.method) || 'GET',
    headers: {
      Authorization: 'Bearer ' + accessToken,
      'Xero-tenant-id': tenantId,
      'Content-Type': 'application/json',
      Accept: 'application/json',
    },
    body: opts && opts.body,
  });
  if (!res.ok) {
    const text = await res.text().catch(() => '');
    throw new Error('Xero API ' + path + ' -> ' + res.status + ' ' + text.slice(0, 300));
  }
  return res.json();
}

/* -------------------------------- utils ---------------------------------- */

function basicAuth(id, secret) {
  return 'Basic ' + btoa(id + ':' + secret);
}
function randomToken() {
  const bytes = crypto.getRandomValues(new Uint8Array(24));
  return Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('');
}
function json(obj, status) {
  return new Response(JSON.stringify(obj), {
    status: status || 200,
    headers: { 'Content-Type': 'application/json' },
  });
}
function corsResponse(env, res) {
  const headers = new Headers(res.headers);
  headers.set('Access-Control-Allow-Origin', env.ALLOWED_ORIGIN || '*');
  headers.set('Access-Control-Allow-Methods', 'GET,POST,OPTIONS');
  headers.set('Access-Control-Allow-Headers', 'Content-Type');
  return new Response(res.body, { status: res.status, headers });
}
function requireEnv(env, keys) {
  const missing = keys.filter((k) => !env[k]);
  if (missing.length) throw new Error('Missing worker config: ' + missing.join(', '));
}
{
  "name": "nas-xero-connector",
  "private": true,
  "devDependencies": {
    "wrangler": "^3.0.0"
  }
}name = "nas-xero-connector"
main = "worker.js"
compatibility_date = "2024-09-01"

# Cloudflare creates and manages this KV namespace automatically on the
# first deploy, because no "id" is given below — you don't need to create
# it yourself or add a binding by hand in the dashboard.
kv_namespaces = [
  { binding = "XERO_KV" }
]

[vars]
# Optional: restrict which site can call this worker once you know your
# published artifact's exact origin. "*" (the default if you omit this)
# works fine since the app itself has no login/auth either.
ALLOWED_ORIGIN = "*"
# The Xero Chart of Accounts code invoice lines should use. "200" is Xero's
# default demo "Sales" account code — check yours in Xero under
# Accounting > Chart of Accounts if invoices come back rejected. To change
# this later, edit this file on GitHub and commit — Cloudflare redeploys
# automatically within a minute or two.
DEFAULT_ACCOUNT_CODE = "200"

# Secrets (XERO_CLIENT_ID, XERO_CLIENT_SECRET) are NOT set here — never
# commit secrets to a file. Add them once via the Cloudflare dashboard
# instead (Settings -> Variables and Secrets) — see SETUP.md Part 2.4.
# Unlike the plain variables above, dashboard secrets survive every future
# deploy triggered by a GitHub push.
