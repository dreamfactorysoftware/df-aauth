// @dreamfactory/aauth-agent/provider: the Agent Provider side of AAuth.
//
// An agent's identity is an https origin (the Agent Provider, "AP") that publishes two documents:
//
//   {issuer}/.well-known/aauth-agent.json   { issuer, jwks_uri, name, callback_endpoint? }
//   {issuer}/jwks.json                      the public key(s) that sign agent tokens
//
// The AP signs agent tokens (typ aa-agent+jwt) that bind an agent id (sub = aauth:<name>@<host>)
// to the key the agent signs its requests with (cnf.jwk). DreamFactory discovers the AP from the
// token's iss, checks the signature against the JWKS, and then checks every request signature
// against cnf.jwk. Host the two documents anywhere that serves https (a static bucket works), or
// mount createProviderHandler() in your own server, or run `aauth serve`.
import http from 'node:http';
import { publicJwk, signJwt, randomId, now, escapeHtml, jwkThumbprint } from './aauth.mjs';

/** The aauth-agent.json document. callback: true (= {issuer}/callback), a URL, or false. */
export function providerMetadata({ issuer, name, callback = false, extra = {} }) {
  const iss = String(issuer).replace(/\/+$/, '');
  const meta = { issuer: iss, jwks_uri: `${iss}/jwks.json` };
  if (name) meta.name = name;
  const cb = callback === true ? `${iss}/callback` : callback || null;
  if (cb) meta.callback_endpoint = cb;
  return { ...meta, ...extra };
}

/** The JWKS document: the current signing key first, then any previous keys still being verified. */
export function providerJwks(apKey, previousKeys = []) {
  return { keys: [apKey, ...previousKeys].filter(Boolean).map(publicJwk) };
}

/** Both public documents, keyed by the path they are served at. */
export function providerDocuments({ issuer, name, apKey, previousKeys = [], callback = false }) {
  return {
    '/.well-known/aauth-agent.json': providerMetadata({ issuer, name, callback }),
    '/jwks.json': providerJwks(apKey, previousKeys),
  };
}

/**
 * Mint an agent token for an agent instance's public key. Use this in your AP when agent
 * instances hold only their own request key: the instance sends its public JWK, the AP (after
 * authenticating the instance its own way) answers with this token. Lifetime at most 24 h.
 */
export function mintAgentToken({ issuer, apKey, sub, agentJwk, ps, ttl = 3600, extra = {} }) {
  if (!agentJwk) throw new Error('agentJwk is required');
  if (ttl > 86_400) throw new Error('agent tokens live at most 24 h');
  const t = now();
  const payload = { iss: String(issuer).replace(/\/+$/, ''), dwk: 'aauth-agent.json', sub, cnf: { jwk: publicJwk(agentJwk) }, ...extra, jti: randomId(), iat: t, exp: t + ttl };
  if (ps) payload.ps = ps;
  return signJwt({ typ: 'aa-agent+jwt', jwk: apKey, payload });
}

const page = (title, inner) => `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>${escapeHtml(title)}</title>
<style>
:root{--bg:#f6f6f9;--card:#fff;--fg:#1d1b2e;--muted:#5d5a73;--accent:#5c5699;--line:#e3e1ee}
@media (prefers-color-scheme:dark){:root{--bg:#141320;--card:#1e1c2d;--fg:#ecebf5;--muted:#a9a6c0;--accent:#a49ff0;--line:#2e2b44}}
*{box-sizing:border-box}body{margin:0;min-height:100vh;display:grid;place-items:center;background:var(--bg);color:var(--fg);
font:15px/1.5 Inter,system-ui,-apple-system,"Segoe UI",sans-serif;padding:16px}
main{background:var(--card);border:1px solid var(--line);border-radius:12px;padding:28px;max-width:440px;width:100%}
h1{font-size:20px;margin:0 0 12px}p{margin:8px 0}a{color:var(--accent)}code{font:13px ui-monospace,SFMono-Regular,Menlo,monospace}
dl{display:grid;grid-template-columns:auto 1fr;gap:6px 14px;margin:16px 0 0}dt{color:var(--muted)}dd{margin:0;word-break:break-all}
</style></head><body><main>${inner}</main></body></html>`;

function send(res, status, body, type, extra = {}) {
  res.writeHead(status, { 'content-type': type, 'x-content-type-options': 'nosniff', 'referrer-policy': 'no-referrer', ...extra });
  res.end(body);
}
const sendJson = (res, obj, extra = {}) =>
  send(res, 200, JSON.stringify(obj, null, 2), 'application/json', { 'access-control-allow-origin': '*', 'cache-control': 'public, max-age=300', ...extra });
const sendHtml = (res, status, html) =>
  send(res, status, html, 'text/html; charset=utf-8', {
    'content-security-policy': "default-src 'none'; style-src 'unsafe-inline'; frame-ancestors 'none'",
    'x-frame-options': 'DENY',
    'cache-control': 'no-store',
  });

/**
 * A Node request handler `(req, res) => boolean` for the AP documents plus a small /callback
 * page (where a Person Server sends the browser after the person decides) and /healthz.
 * Returns false for paths it does not own, so you can chain it in front of your own routes.
 * options.routes: extra { path: jsonDocument } (the reference deployment adds a test identity).
 * options.home: serve a small page at / (default true); options.about: its one-line text.
 */
export function createProviderHandler({ issuer, name = 'AAuth agent', apKey, previousKeys = [], callback = true, routes = {}, home = true, about = 'AAuth agent provider.' }) {
  const iss = String(issuer).replace(/\/+$/, '');
  const docs = { ...providerDocuments({ issuer: iss, name, apKey, previousKeys, callback }), ...routes };
  return function handle(req, res) {
    const url = new URL(req.url, iss);
    const owned = url.pathname in docs || ['/callback', '/healthz'].includes(url.pathname) || (home && url.pathname === '/');
    if (!owned) return false;
    if (req.method === 'OPTIONS') {
      send(res, 204, '', 'text/plain', { 'access-control-allow-origin': '*', 'access-control-allow-methods': 'GET', 'access-control-allow-headers': '*' });
      return true;
    }
    if (req.method !== 'GET' && req.method !== 'HEAD') {
      send(res, 405, 'Method not allowed', 'text/plain', { allow: 'GET, HEAD' });
      return true;
    }
    if (url.pathname in docs) {
      sendJson(res, docs[url.pathname]);
      return true;
    }
    if (url.pathname === '/healthz') {
      send(res, 200, 'ok', 'text/plain', { 'cache-control': 'no-store' });
      return true;
    }
    if (url.pathname === '/callback') {
      // Without ?error the browser may be back after only the identity step (the scope consent can
      // still follow), so the page says nothing about the outcome; the agent learns it by polling.
      const error = url.searchParams.get('error');
      sendHtml(
        res,
        200,
        error
          ? page('Not approved', `<h1>Not approved</h1><p><code>${escapeHtml(error)}</code></p><p>Return to your terminal.</p>`)
          : page('Done', '<h1>Done</h1><p>Return to your terminal.</p>'),
      );
      return true;
    }
    sendHtml(
      res,
      200,
      page(
        name,
        `<h1>${escapeHtml(name)}</h1><p>${escapeHtml(about)}</p>
<dl><dt>Issuer</dt><dd><code>${escapeHtml(iss)}</code></dd>
<dt>Metadata</dt><dd><a href="/.well-known/aauth-agent.json">aauth-agent.json</a></dd>
<dt>Keys</dt><dd><a href="/jwks.json">jwks.json</a></dd></dl>`,
      ),
    );
    return true;
  };
}

/** Run the AP as a standalone server. Resolves with the listening http.Server. */
export function startProvider({ port = 8799, host = '0.0.0.0', ...opts }) {
  const handle = createProviderHandler(opts);
  const server = http.createServer((req, res) => {
    if (!handle(req, res)) send(res, 404, JSON.stringify({ error: 'not_found' }), 'application/json');
  });
  return new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(port, host, () => resolve(server));
  });
}

/** Check that the published documents match the local key (what DreamFactory will see). */
export async function checkProvider({ issuer, apKey, sub, fetchImpl = fetch, timeoutMs = 8000 }) {
  const iss = String(issuer).replace(/\/+$/, '');
  const out = { issuer: iss, ok: false, checks: [] };
  const add = (ok, label, detail) => out.checks.push({ ok, label, ...(detail !== undefined ? { detail } : {}) });
  const get = async (u) => {
    const r = await fetchImpl(u, { headers: { accept: 'application/json' }, redirect: 'error', signal: AbortSignal.timeout(timeoutMs) });
    if (!r.ok) throw new Error(`HTTP ${r.status}`);
    return r.json();
  };
  try {
    const u = new URL(iss);
    add(u.protocol === 'https:' && !u.port && u.origin === iss, 'issuer is a bare https origin', iss);
  } catch {
    add(false, 'issuer is a URL', iss);
    return out;
  }
  if (sub) add(String(sub).endsWith(`@${new URL(iss).host}`), 'agent id uses the issuer host', sub);
  let meta;
  try {
    meta = await get(`${iss}/.well-known/aauth-agent.json`);
    add(meta.issuer === iss, 'aauth-agent.json issuer matches', meta.issuer);
  } catch (e) {
    add(false, `GET ${iss}/.well-known/aauth-agent.json`, e.message);
    return out;
  }
  try {
    const jwks = await get(meta.jwks_uri);
    const k = (jwks.keys || []).find((x) => x.kid === apKey.kid);
    add(!!k, `JWKS has key ${apKey.kid}`, meta.jwks_uri);
    if (k) add(jwkThumbprint(k) === jwkThumbprint(apKey) && !!k.alg, 'published key matches the local signing key');
  } catch (e) {
    add(false, `GET ${meta.jwks_uri}`, e.message);
  }
  out.metadata = meta;
  out.ok = out.checks.every((c) => c.ok);
  return out;
}
