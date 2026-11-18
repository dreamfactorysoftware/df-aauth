// Interop with the AAuth reference demo's own library (shared/aauth.mjs of a local checkout of
// https://github.com/wjgilmore/aauth-demo, path in $AAUTH_DEMO_LIB; the tests are skipped without it).
//
//   node --test agent/interop.test.mjs                  offline checks (+ live ones when DF is up)
//   AAUTH_WRITE_FIXTURE=1 node --test agent/interop.test.mjs   regenerate tests/fixtures/*.json
//
// Offline:
//   1. demo signedFetch -> our verifier; our signRequest -> demo verifySignedRequest
//   2. tests/fixtures/demo-signed-request.json + demo-jwt.json: produced with the demo's code at a
//      fixed `now` (written when missing or AAUTH_WRITE_FIXTURE=1), then re-verified by both verifiers.
// Live (skipped, with the reason, unless DF_URL is set and $DF_URL/.well-known/aauth-resource.json answers):
//   (a) demo signedFetch with a demo-generated agent key + an agent token minted by OUR AP key -> DF
//       accepts the signature (401 requirement=person-token, no Signature-Error).
//   (b) DF-issued resource / person / auth tokens verify with the demo's verifyJwt (needs admin
//       credentials; the person is played by person.mjs).
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { Agent, Discovery, verifySignedRequest, signRequest, publicJwk, loadKeys, setClock, claims, DEFAULT_ISSUER } from './aauth.mjs';
import { Browser, personAct, credentials } from './person.mjs';

// The reference demo library is optional: every test here is skipped when it is not installed.
const DEMO_LIB = process.env.AAUTH_DEMO_LIB || '';
let demo = null;
try {
  if (DEMO_LIB) demo = await import(DEMO_LIB);
} catch {}
function dtest(name, a, b) {
  const [opts, fn] = typeof a === 'function' ? [{}, a] : [a, b];
  if (demo) return test(name, opts, fn);
  const missing = DEMO_LIB ? `reference demo library not found at ${DEMO_LIB}` : 'set AAUTH_DEMO_LIB to the reference demo library';
  return test(name, { skip: typeof opts.skip === 'string' ? `${missing}; ${opts.skip}` : missing }, fn);
}

const HERE = path.dirname(new URL(import.meta.url).pathname);
const FIXTURES = path.resolve(HERE, '../tests/fixtures');
const DF = (process.env.DF_URL || '').replace(/\/+$/, '');
const FIXED_NOW = 1794268800; // 2026-11-10T00:00:00Z

const AP_ISS = 'https://agent.example';
const RES_ISS = 'https://df.example';

/** Run fn with Date.now() pinned and global fetch replaced. */
async function withStubs({ nowSec, routes = {}, capture }, fn) {
  const realNow = Date.now;
  const realFetch = globalThis.fetch;
  if (nowSec) Date.now = () => nowSec * 1000;
  globalThis.fetch = async (url, init = {}) => {
    const u = String(url instanceof URL ? url.href : url);
    if (routes[u]) return new Response(JSON.stringify(routes[u]), { status: 200, headers: { 'content-type': 'application/json' } });
    if (capture) {
      capture.push({ url: u, init });
      return new Response('{}', { status: 200, headers: { 'content-type': 'application/json' } });
    }
    return realFetch(url, init);
  };
  try {
    return await fn();
  } finally {
    Date.now = realNow;
    globalThis.fetch = realFetch;
  }
}

const apRoutes = (apKey) => ({
  [`${AP_ISS}/.well-known/aauth-agent.json`]: { issuer: AP_ISS, jwks_uri: `${AP_ISS}/jwks.json`, name: 'Fixture Agent' },
  [`${AP_ISS}/jwks.json`]: { keys: [demo.publicJwk(apKey)] },
});

function headersObj(h) {
  const out = {};
  new Headers(h).forEach((v, k) => (out[k] = v));
  return out;
}

/** Build the fixture with the demo's own code. */
async function buildFixture() {
  const apKey = demo.generateJwk();
  const agentKey = demo.generateJwk();
  const agentToken = await withStubs({ nowSec: FIXED_NOW }, async () =>
    demo.signJwt({
      typ: 'aa-agent+jwt',
      jwk: apKey,
      payload: {
        iss: AP_ISS,
        dwk: 'aauth-agent.json',
        sub: 'aauth:fixture@agent.example',
        cnf: { jwk: demo.publicJwk(agentKey) },
        ps: 'https://ps.example',
        jti: demo.randomId(),
        iat: FIXED_NOW,
        exp: FIXED_NOW + 3600,
      },
    }),
  );
  const capture = [];
  const body = { resource: [{ customer_id: 3, total: 42.5, status: 'new' }] };
  await withStubs({ nowSec: FIXED_NOW, capture }, async () => {
    await demo.signedFetch(`${RES_ISS}/api/v2/sales/_table/orders`, { method: 'POST', body, token: agentToken, jwk: agentKey });
    await demo.signedFetch(`${RES_ISS}/api/v2/sales/_table/customers`, { method: 'GET', token: agentToken, jwk: agentKey });
  });
  const toReq = ({ url, init }) => {
    const u = new URL(url);
    return { method: init.method, url, authority: u.host, path: u.pathname, query: u.search ? u.search.slice(1) : null, headers: headersObj(init.headers), body: init.body ?? '' };
  };
  const post = toReq(capture[0]);
  const get = toReq(capture[1]);
  const meta = apRoutes(apKey);

  // A demo-signed JWT of each kind a DF verifier sees from outside (person token from a PS).
  const psKey = demo.generateJwk();
  const PS = 'https://ps.example';
  const personToken = demo.signJwt({
    typ: 'aa-person+jwt',
    jwk: psKey,
    payload: { iss: PS, dwk: 'aauth-person.json', aud: RES_ISS, sub: 'pairwise-fixture', cnf: { jwk: demo.publicJwk(agentKey) }, jti: demo.randomId(), iat: FIXED_NOW, exp: FIXED_NOW + 3600 },
  });

  const signed = {
    description: 'Requests signed by the AAuth reference demo (shared/aauth.mjs signedFetch) at a fixed time. Verify with now = "now" and a static key resolver built from agent_provider.',
    generator: 'df-aauth/agent/interop.test.mjs using the aauth-demo shared/aauth.mjs library',
    now: FIXED_NOW,
    window: 60,
    agent_provider: {
      issuer: AP_ISS,
      dwk: 'aauth-agent.json',
      metadata: meta[`${AP_ISS}/.well-known/aauth-agent.json`],
      jwks: meta[`${AP_ISS}/jwks.json`],
    },
    agent_token: agentToken,
    agent_token_header: demo.decodeJwt(agentToken).header,
    agent_token_claims: demo.decodeJwt(agentToken).payload,
    agent_public_jwk: demo.publicJwk(agentKey),
    agent_jkt: demo.jwkThumbprint(agentKey),
    request: post,
    get_request: get,
    expect: {
      valid: true,
      typ: 'aa-agent+jwt',
      created: FIXED_NOW,
      components: ['@method', '@authority', '@path', 'signature-key', 'content-type', 'content-digest'],
      get_components: ['@method', '@authority', '@path', 'signature-key'],
    },
    negative: [
      { name: 'body_tampered', target: 'request', change: { body: post.body.replace('42.5', '99.5') }, error: 'invalid_signature' },
      { name: 'authority_changed', target: 'request', change: { authority: 'df2.example' }, error: 'invalid_signature' },
      { name: 'path_changed', target: 'request', change: { path: '/api/v2/sales/_table/customers' }, error: 'invalid_signature' },
      { name: 'method_changed', target: 'get_request', change: { method: 'DELETE' }, error: 'invalid_signature' },
      { name: 'query_added', target: 'get_request', change: { query: 'limit=1' }, error: 'invalid_input', require_query: true, note: '@query is required (requireQuery=true) because the request now has a query, and the signature does not cover it' },
      { name: 'stale', target: 'request', now: FIXED_NOW + 120, error: 'invalid_signature' },
      { name: 'future', target: 'request', now: FIXED_NOW - 120, error: 'clock_skew' },
    ],
  };
  const jwt = {
    description: 'A person token signed by the demo signJwt (Ed25519, header alg,typ,kid). Verify at "now" with the static key below.',
    now: FIXED_NOW,
    issuer: PS,
    dwk: 'aauth-person.json',
    metadata: { issuer: PS, jwks_uri: `${PS}/jwks.json` },
    jwks: { keys: [demo.publicJwk(psKey)] },
    jwt: personToken,
    typ: 'aa-person+jwt',
    header: demo.decodeJwt(personToken).header,
    payload: demo.decodeJwt(personToken).payload,
    cnf_jkt: demo.jwkThumbprint(agentKey),
  };
  return { signed, jwt };
}

function loadOrWriteFixtures() {
  const sp = path.join(FIXTURES, 'demo-signed-request.json');
  const jp = path.join(FIXTURES, 'demo-jwt.json');
  return { sp, jp, exists: fs.existsSync(sp) && fs.existsSync(jp) };
}

const ourDiscoveryFor = (f) => {
  const d = new Discovery();
  d.seed(f.agent_provider.issuer, 'aauth-agent.json', f.agent_provider.metadata, f.agent_provider.jwks);
  return d;
};
const asMsg = (r) => ({ method: r.method, url: `https://${r.authority}${r.path}${r.query !== null && r.query !== undefined ? `?${r.query}` : ''}`, headers: r.headers, body: r.body });

dtest('fixture: demo-signed request + JWT (written by the demo library, verified by both)', async () => {
  const { sp, jp, exists } = loadOrWriteFixtures();
  if (!exists || process.env.AAUTH_WRITE_FIXTURE) {
    const { signed, jwt } = await buildFixture();
    fs.mkdirSync(FIXTURES, { recursive: true });
    fs.writeFileSync(sp, `${JSON.stringify(signed, null, 2)}\n`);
    fs.writeFileSync(jp, `${JSON.stringify(jwt, null, 2)}\n`);
  }
  const f = JSON.parse(fs.readFileSync(sp, 'utf8'));
  const j = JSON.parse(fs.readFileSync(jp, 'utf8'));

  setClock(() => f.now);
  try {
    const d = ourDiscoveryFor(f);
    const v = await verifySignedRequest(asMsg(f.request), { discovery: d });
    assert.deepEqual(v.components, f.expect.components);
    assert.equal(v.created, f.expect.created);
    assert.equal(v.jkt, f.agent_jkt);
    const g = await verifySignedRequest(asMsg(f.get_request), { discovery: d });
    assert.deepEqual(g.components, f.expect.get_components);
    for (const n of f.negative) {
      const base = { ...f[n.target], ...(n.change || {}) };
      if (n.now) setClock(() => n.now);
      await assert.rejects(verifySignedRequest(asMsg(base), { discovery: d, requireQuery: true }), (e) => e.error === n.error, n.name);
      setClock(() => f.now);
    }
    const dj = new Discovery();
    dj.seed(j.issuer, j.dwk, j.metadata, j.jwks);
    assert.equal((await dj.verifyJwt(j.jwt, j.typ)).payload.sub, j.payload.sub);
  } finally {
    setClock(null);
  }

  // The demo's own verifier accepts its fixture at the fixed time.
  await withStubs({ nowSec: f.now, routes: { [`${AP_ISS}/.well-known/aauth-agent.json`]: f.agent_provider.metadata, [f.agent_provider.metadata.jwks_uri]: f.agent_provider.jwks } }, async () => {
    const m = asMsg(f.request);
    const req = new Request(m.url, { method: m.method, headers: m.headers, body: m.body });
    const out = await demo.verifySignedRequest(req, { accept: ['aa-agent+jwt'] });
    assert.equal(out.payload.sub, f.agent_token_claims.sub);
  });
});

dtest('our signRequest is accepted by the demo verifier', async () => {
  const apKey = demo.generateJwk();
  const agentKey = demo.generateJwk();
  const t = Math.floor(Date.now() / 1000);
  const token = demo.signJwt({ typ: 'aa-agent+jwt', jwk: apKey, payload: { iss: AP_ISS, dwk: 'aauth-agent.json', sub: 'aauth:x@agent.example', cnf: { jwk: demo.publicJwk(agentKey) }, jti: 'j1', iat: t, exp: t + 600 } });
  await withStubs({ routes: apRoutes(apKey) }, async () => {
    for (const [method, body] of [
      ['POST', { a: 1, s: 'x"y' }],
      ['GET', undefined],
    ]) {
      const s = signRequest(`${RES_ISS}/api/v2/x`, { method, body, token, jwk: agentKey });
      const req = new Request(s.url, { method: s.method, headers: s.headers, body: s.body });
      const out = await demo.verifySignedRequest(req, { accept: ['aa-agent+jwt'] });
      assert.equal(out.jkt, demo.jwkThumbprint(agentKey), method);
    }
  });
});

dtest('demo signedFetch is accepted by our verifier', async () => {
  const apKey = demo.generateJwk();
  const agentKey = demo.generateJwk();
  const t = Math.floor(Date.now() / 1000);
  const token = demo.signJwt({ typ: 'aa-agent+jwt', jwk: apKey, payload: { iss: AP_ISS, dwk: 'aauth-agent.json', sub: 'aauth:x@agent.example', cnf: { jwk: demo.publicJwk(agentKey) }, jti: 'j2', iat: t, exp: t + 600 } });
  const capture = [];
  await withStubs({ capture }, () => demo.signedFetch(`${RES_ISS}/api/v2/y`, { method: 'PUT', body: { z: [1, 2] }, token, jwk: agentKey }));
  const { url, init } = capture[0];
  const d = new Discovery();
  d.seed(AP_ISS, 'aauth-agent.json', { issuer: AP_ISS, jwks_uri: `${AP_ISS}/jwks.json` }, { keys: [demo.publicJwk(apKey)] });
  const v = await verifySignedRequest({ method: init.method, url, headers: headersObj(init.headers), body: init.body }, { discovery: d });
  assert.equal(v.payload.sub, 'aauth:x@agent.example');
});

// ---------------------------------------------------------------------------
// Live
// ---------------------------------------------------------------------------
let live = false;
let liveSkip = 'DF_URL is not set: set DF_URL to a DreamFactory with AAuth on to run the live interop checks';
if (DF) {
  liveSkip = `AAuth is not answering at ${DF} (GET ${DF}/.well-known/aauth-resource.json did not return this issuer)`;
  try {
    const r = await fetch(`${DF}/.well-known/aauth-resource.json`, { signal: AbortSignal.timeout(5000) });
    live = r.ok && (await r.json()).issuer === DF;
  } catch {}
}
const liveOpts = { skip: live ? false : liveSkip };

dtest('(a) live: demo signedFetch + our AP agent token -> DF accepts the signature', liveOpts, async () => {
  const keys = loadKeys();
  const ap = (process.env.AAUTH_AGENT_ISSUER || DEFAULT_ISSUER).replace(/\/+$/, '');
  const agentKey = demo.generateJwk();
  const t = demo.now();
  const token = demo.signJwt({
    typ: 'aa-agent+jwt',
    jwk: keys.ap,
    payload: { iss: ap, dwk: 'aauth-agent.json', sub: `aauth:e2e-interop@${new URL(ap).host}`, cnf: { jwk: demo.publicJwk(agentKey) }, ps: DF, jti: demo.randomId(), iat: t, exp: t + 600 },
  });
  for (const [method, body] of [
    ['GET', undefined],
    ['POST', { resource: [] }],
  ]) {
    const { response } = await demo.signedFetch(`${DF}/api/v2/sales/_table/orders`, { method, body, token, jwk: agentKey });
    const text = await response.text();
    assert.equal(response.headers.get('signature-error'), null, `${method}: ${response.headers.get('signature-error')} ${text}`);
    assert.equal(response.status, 401, `${method}: ${text}`);
    assert.equal(demo.parseRequirement(response.headers.get('aauth-requirement')).requirement, 'person-token');
  }
});

dtest('(b) live: DF-issued resource/person/auth tokens verify with the demo verifyJwt', liveOpts, async (t) => {
  const { adminPassword } = credentials();
  if (!adminPassword) return t.skip('admin credentials not available');
  const keys = loadKeys();
  const ap = (process.env.AAUTH_AGENT_ISSUER || DEFAULT_ISSUER).replace(/\/+$/, '');
  const agent = new Agent({ issuer: ap, apKey: keys.ap, agentKey: demo.generateJwk(), sub: `aauth:e2e-interop@${new URL(ap).host}`, callback: false });
  const browser = new Browser('admin');
  const r = await agent.request('GET', `${DF}/api/v2/sales/_table/orders?limit=1`, {
    pollTimeoutMs: 60_000,
    onInteraction: (i) => personAct(browser, i.url, i.code, { email: process.env.DF_ADMIN_EMAIL || 'admin@example.com', password: adminPassword, decision: 'allow' }),
  });
  assert.equal(r.status, 200, JSON.stringify(r.body).slice(0, 300));
  const rt = r.steps.flatMap((s) => s.tokens || []).find((x) => demo.decodeJwt(x).header.typ === 'aa-resource+jwt');
  const pt = r.steps.map((s) => s.response?.body?.person_token).find(Boolean);
  const at = r.steps.map((s) => s.response?.body?.auth_token).find(Boolean);
  assert.ok(rt && pt && at, 'collected all three tokens');
  const vr = await demo.verifyJwt(rt, { typ: 'aa-resource+jwt', dwk: 'aauth-resource.json' });
  const vp = await demo.verifyJwt(pt, { typ: 'aa-person+jwt', dwk: 'aauth-person.json' });
  const va = await demo.verifyJwt(at, { typ: 'aa-auth+jwt', dwk: 'aauth-person.json' });
  assert.equal(vr.payload.iss, DF);
  assert.equal(vp.payload.iss, DF);
  assert.equal(va.payload.aud, DF);
  assert.equal(vr.header.alg, 'Ed25519');
  assert.equal(claims(at).cnf.jwk.alg, 'Ed25519');
  assert.equal(vr.payload.sub, vp.payload.sub);
  assert.equal(va.payload.sub, vp.payload.sub);
  void publicJwk;
});
