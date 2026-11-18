// A mock AAuth resource + Person Server on one origin (http://127.0.0.1:<port>, insecure mode),
// for offline tests of the agent library and the CLI. Not part of the published package.
//
//   const mock = await startMock(apKey, { apIssuer })   // apKey: the agent provider's signing key
//   GET  {mock.ORIGIN}/approve?code=XXXX-XXXX[&decision=deny][&always=1]   plays the person
//   resource: /api/data (GET needs scope "read", anything else "write"), /authorize (§6.6)
import assert from 'node:assert/strict';
import http from 'node:http';
import { Discovery, generateJwk, publicJwk, signJwt, decodeJwt, verifySignedRequest, randomId, now } from './aauth.mjs';

export async function startMock(apKey, { apIssuer = 'https://agent.example' } = {}) {
  const AP = apIssuer;
  const rKey = generateJwk();
  const pKey = generateJwk();
  const pending = new Map(); // id -> {kind, code, status, jkt, token, scope, ...}
  const grants = new Set();
  const server = http.createServer();
  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  const ORIGIN = `http://127.0.0.1:${server.address().port}`;
  const disc = new Discovery({ insecure: true });
  disc.seed(AP, 'aauth-agent.json', { issuer: AP, jwks_uri: `${AP}/jwks.json` }, { keys: [publicJwk(apKey)] });
  disc.seed(ORIGIN, 'aauth-resource.json', { issuer: ORIGIN }, { keys: [publicJwk(rKey)] });
  disc.seed(ORIGIN, 'aauth-person.json', { issuer: ORIGIN }, { keys: [publicJwk(pKey)] });
  const log = [];

  const json = (res, status, body, headers = {}) => {
    res.writeHead(status, { 'content-type': status >= 400 ? 'application/problem+json' : 'application/json', ...headers });
    res.end(JSON.stringify(body));
  };
  const mint = (typ, key, payload) => signJwt({ typ, jwk: key, payload: { jti: randomId(), iat: now(), exp: now() + 600, ...payload } });
  const defer = (res, kind, agentTok, extra) => {
    const id = randomId(12);
    const code = `${randomId(3).toUpperCase().slice(0, 4)}-${randomId(3).toUpperCase().slice(0, 4)}`;
    pending.set(id, { kind, code, status: 'pending', jkt: agentTok.jkt, ...extra });
    json(res, 202, { status: 'pending' }, {
      location: `/pending/${id}`,
      'retry-after': '0',
      'cache-control': 'no-store',
      'aauth-requirement': `requirement=interaction; url="${ORIGIN}/interact"; code="${code}"`,
    });
  };

  server.on('request', async (req, res) => {
    const url = new URL(req.url, ORIGIN);
    const chunks = [];
    for await (const c of req) chunks.push(c);
    const body = Buffer.concat(chunks).toString();
    const p = url.pathname;
    log.push(`${req.method} ${p}`);
    try {
      if (p === '/.well-known/aauth-resource.json')
        return json(res, 200, { issuer: ORIGIN, jwks_uri: `${ORIGIN}/jwks/r`, authorization_endpoint: `${ORIGIN}/authorize`, scope_descriptions: { read: 'Read', write: 'Write' } });
      if (p === '/.well-known/aauth-person.json')
        return json(res, 200, { issuer: ORIGIN, jwks_uri: `${ORIGIN}/jwks/p`, person_token_endpoint: `${ORIGIN}/person`, auth_token_endpoint: `${ORIGIN}/token`, interaction_endpoint: `${ORIGIN}/interact` });
      if (p === '/jwks/r') return json(res, 200, { keys: [publicJwk(rKey)] });
      if (p === '/jwks/p') return json(res, 200, { keys: [publicJwk(pKey)] });
      if (p === '/approve') {
        const entry = [...pending.values()].find((x) => x.code === url.searchParams.get('code'));
        if (!entry) return json(res, 404, { error: 'invalid_code' });
        entry.status = url.searchParams.get('decision') === 'deny' ? 'denied' : 'approved';
        if (entry.status === 'approved' && url.searchParams.get('always')) grants.add(entry.grantKey);
        return json(res, 200, { ok: true });
      }
      const v = await verifySignedRequest({ method: req.method, url: `${ORIGIN}${req.url}`, headers: req.headers, body }, { discovery: disc, requireQuery: true });
      if (p.startsWith('/pending/')) {
        const e = pending.get(p.split('/')[2]);
        if (!e || e.jkt !== v.jkt) return json(res, 404, { error: 'not_found' });
        if (req.method === 'DELETE') {
          pending.delete(p.split('/')[2]);
          return json(res, 200, { status: 'cancelled' });
        }
        if (e.status === 'pending') return json(res, 202, { status: 'pending' }, { 'retry-after': '0', 'cache-control': 'no-store' });
        if (e.status === 'denied') return json(res, 403, { error: 'denied' });
        if (e.status === 'delivered') return json(res, 410, { error: 'invalid_code' });
        e.status = 'delivered';
        return json(res, 200, { [`${e.kind}_token`]: e.token });
      }
      if (p === '/person') {
        const b = JSON.parse(body);
        const token = mint('aa-person+jwt', pKey, { iss: ORIGIN, dwk: 'aauth-person.json', aud: b.resource, sub: 'pairwise-1', cnf: { jwk: v.jwk } });
        return defer(res, 'person', v, { token });
      }
      if (p === '/token') {
        const b = JSON.parse(body);
        const rt = (await disc.verifyJwt(b.resource_token, 'aa-resource+jwt')).payload;
        const presented = decodeJwt(b.presented_token).payload;
        assert.equal(rt.presented_jti, presented.jti);
        assert.equal(rt.agent_jkt, v.jkt);
        const token = mint('aa-auth+jwt', pKey, { iss: ORIGIN, dwk: 'aauth-person.json', aud: rt.iss, ps: ORIGIN, sub: rt.sub, scope: rt.scope, cnf: { jwk: v.jwk } });
        const grantKey = `${rt.sub}|${v.payload.sub}|${rt.scope}`;
        if (grants.has(grantKey)) return json(res, 200, { auth_token: token, expires_in: 600 });
        return defer(res, 'auth', v, { token, grantKey });
      }
      if (p === '/authorize') {
        if (v.header.typ === 'aa-agent+jwt') return json(res, 401, { error: 'person_token_required' }, { 'aauth-requirement': 'requirement=person-token' });
        const scope = String(JSON.parse(body || '{}').scope || '').trim();
        if (!scope) return json(res, 400, { error: 'invalid_request', detail: 'scope is required' });
        const unknown = scope.split(' ').filter((s) => !['read', 'write'].includes(s));
        if (unknown.length) return json(res, 400, { error: 'invalid_scope', detail: `Unknown scope: ${unknown.join(' ')}` });
        const rt = mint('aa-resource+jwt', rKey, { iss: ORIGIN, dwk: 'aauth-resource.json', aud: v.header.typ === 'aa-auth+jwt' ? v.payload.ps : v.payload.iss, ps: ORIGIN, sub: v.payload.sub, presented_jti: v.payload.jti, agent_jkt: v.jkt, scope });
        return json(res, 200, { resource_token: rt });
      }
      if (p === '/api/data') {
        const need = req.method === 'GET' ? 'read' : 'write';
        if (v.header.typ === 'aa-agent+jwt') return json(res, 401, { error: 'person_token_required' }, { 'aauth-requirement': 'requirement=person-token' });
        const granted = v.header.typ === 'aa-auth+jwt' ? (v.payload.scope || '').split(' ') : [];
        if (granted.includes(need)) return json(res, 200, { ok: true, method: req.method, scope: need });
        const scope = [...new Set([...granted, need])].join(' ');
        const rt = mint('aa-resource+jwt', rKey, { iss: ORIGIN, dwk: 'aauth-resource.json', aud: v.header.typ === 'aa-auth+jwt' ? v.payload.ps : v.payload.iss, ps: ORIGIN, sub: v.payload.sub, presented_jti: v.payload.jti, agent_jkt: v.jkt, scope });
        return json(res, 401, { error: 'auth_token_required' }, { 'aauth-requirement': `requirement=auth-token; resource-token="${rt}"` });
      }
      json(res, 404, { error: 'not_found' });
    } catch (e) {
      json(res, e.status || 500, { error: e.error || 'server_error', detail: e.detail || e.message }, e.status === 401 ? { 'signature-error': `error=${e.error}` } : {});
    }
  });
  return { ORIGIN, server, log, pending, close: () => new Promise((r) => server.close(r)) };
}

