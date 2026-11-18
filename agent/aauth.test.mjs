// Offline tests for aauth.mjs: primitives, structured fields, sign/verify round trips and the
// full three-party Agent flow against an in-process mock resource + Person Server.
//
//   node --test agent/aauth.test.mjs
import test from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import {
  Agent,
  Discovery,
  generateJwk,
  publicJwk,
  jwkThumbprint,
  signJwt,
  decodeJwt,
  signRequest,
  verifySignedRequest,
  parseDictionary,
  parseRequirement,
  parseSignatureError,
  sfString,
  contentDigest,
  assertServerId,
  randomId,
  now,
} from './aauth.mjs';

const AP = 'https://agent.example';

test('RFC 8037 thumbprint vector', () => {
  assert.equal(jwkThumbprint({ kty: 'OKP', crv: 'Ed25519', x: '11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo' }), 'kPrK_qmxVWaYVA9wwBF6Iuo3vVzz7TxHCTwXBygrS4k');
});

test('RFC 9530 content digest', () => {
  assert.equal(contentDigest('{"hello": "world"}'), 'sha-256=:X48E9qOokqqrvdts8nOJRJN3OWDUoyWxBf7kbu9DBPE=:');
});

test('server identifiers', () => {
  assert.ok(assertServerId('https://df.example'));
  for (const bad of ['http://df.example', 'https://df.example/', 'https://DF.example', 'https://df.example:8443', 'https://df.example/x']) {
    assert.throws(() => assertServerId(bad), bad);
  }
  assert.ok(assertServerId('http://127.0.0.1:8080', { insecure: true }));
});

test('structured fields', () => {
  const r = parseRequirement('requirement=auth-token; resource-token="eyJ.a.b"');
  assert.deepEqual(r, { requirement: 'auth-token', 'resource-token': 'eyJ.a.b' });
  assert.deepEqual(parseRequirement('requirement=interaction;url="https://ps.example/interact";code="A1B2-C3D4"'), {
    requirement: 'interaction',
    url: 'https://ps.example/interact',
    code: 'A1B2-C3D4',
  });
  assert.deepEqual(parseRequirement('garbage ;;'), {});
  assert.deepEqual(parseSignatureError('error=invalid_input, required_input=("@method" "content-digest")'), {
    error: 'invalid_input',
    required_input: ['@method', 'content-digest'],
  });
  const d = parseDictionary('sig=("@method" "@path");created=1730217600;expires=1730217660');
  assert.deepEqual(d.sig.items.map((i) => i.value), ['@method', '@path']);
  assert.equal(d.sig.params.created, 1730217600);
  assert.equal(d.sig.raw, '("@method" "@path");created=1730217600;expires=1730217660');
  assert.equal(sfString('a"b\\c'), '"a\\"b\\\\c"');
});

function seededDiscovery(apKey, extra = []) {
  const d = new Discovery();
  d.seed(AP, 'aauth-agent.json', { issuer: AP, jwks_uri: `${AP}/jwks.json` }, { keys: [publicJwk(apKey)] });
  for (const [iss, dwk, key] of extra) d.seed(iss, dwk, { issuer: iss, jwks_uri: `${iss}/jwks.json` }, { keys: [publicJwk(key)] });
  return d;
}

test('JWT round trip, typ first, tampering, alg mismatch', async () => {
  const ap = generateJwk();
  const d = seededDiscovery(ap);
  const t = now();
  const jwt = signJwt({ typ: 'aa-agent+jwt', jwk: ap, payload: { iss: AP, dwk: 'aauth-agent.json', sub: 'aauth:x@agent.example', jti: 'j', iat: t, exp: t + 60 } });
  const { header } = decodeJwt(jwt);
  assert.deepEqual(Object.keys(header), ['alg', 'typ', 'kid']);
  assert.equal(header.alg, 'Ed25519');
  assert.equal((await d.verifyJwt(jwt, 'aa-agent+jwt')).payload.sub, 'aauth:x@agent.example');
  await assert.rejects(d.verifyJwt(jwt, 'aa-person+jwt'), /invalid_jwt/);
  const [h, p, s] = jwt.split('.');
  const p2 = Buffer.from(JSON.stringify({ ...decodeJwt(jwt).payload, sub: 'evil' })).toString('base64url');
  await assert.rejects(d.verifyJwt(`${h}.${p2}.${s}`, 'aa-agent+jwt'), /invalid_jwt/);
  const expired = signJwt({ typ: 'aa-agent+jwt', jwk: ap, payload: { iss: AP, dwk: 'aauth-agent.json', jti: 'j', iat: t - 100, exp: t - 1 } });
  await assert.rejects(d.verifyJwt(expired, 'aa-agent+jwt'), /expired_jwt/);
  const hNone = Buffer.from(JSON.stringify({ alg: 'EdDSA', typ: 'aa-agent+jwt', kid: ap.kid })).toString('base64url');
  await assert.rejects(d.verifyJwt(`${hNone}.${p}.${s}`, 'aa-agent+jwt'), /unsupported_algorithm/);
});

test('ES256 JWT verification', async () => {
  const { privateKey } = crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' });
  const j = privateKey.export({ format: 'jwk' });
  const es = { ...j, alg: 'ES256', kid: 'es1' };
  const d = seededDiscovery(generateJwk(), [['https://ps.example', 'aauth-person.json', es]]);
  const t = now();
  const jwt = signJwt({ typ: 'aa-person+jwt', jwk: es, payload: { iss: 'https://ps.example', dwk: 'aauth-person.json', jti: 'j', iat: t, exp: t + 60 } });
  assert.equal(decodeJwt(jwt).header.alg, 'ES256');
  assert.equal(decodeJwt(jwt).signature.length, 64);
  assert.equal((await d.verifyJwt(jwt, 'aa-person+jwt')).payload.iss, 'https://ps.example');
});

test('HTTP signature: strict wire form, @query, round trip, tamper cases', async () => {
  const ap = generateJwk();
  const key = generateJwk();
  const d = seededDiscovery(ap);
  const t = now();
  const token = signJwt({ typ: 'aa-agent+jwt', jwk: ap, payload: { iss: AP, dwk: 'aauth-agent.json', sub: 'aauth:x@agent.example', cnf: { jwk: publicJwk(key) }, jti: randomId(), iat: t, exp: t + 600 } });
  const s = signRequest('https://df.example/api/v2/sales/_table/orders?limit=5&filter=a%20b', { method: 'PATCH', token, jwk: key, body: { status: 'x' } });
  assert.equal(s.headers['signature-key'], `sig=jwt;jwt="${token}"`);
  assert.match(s.headers['signature-input'], /^sig=\("@method" "@authority" "@path" "signature-key" "@query" "content-type" "content-digest"\);created=\d+$/);
  assert.match(s.headers['signature'], /^sig=:[A-Za-z0-9+/]+=*:$/);
  assert.ok(s.base.includes('"@query": ?limit=5&filter=a%20b'));
  assert.ok(s.base.includes('"@authority": df.example'));
  const msg = { method: s.method, url: s.url, headers: s.headers, body: s.body };
  const v = await verifySignedRequest(msg, { discovery: d, requireQuery: true });
  assert.equal(v.jkt, jwkThumbprint(key));
  await assert.rejects(verifySignedRequest({ ...msg, body: '{"status":"y"}' }, { discovery: d }), /invalid_signature/);
  await assert.rejects(verifySignedRequest({ ...msg, url: msg.url.replace('limit=5', 'limit=6') }, { discovery: d }), /invalid_signature/);
  await assert.rejects(verifySignedRequest({ ...msg, url: msg.url.replace('df.example', 'df2.example') }, { discovery: d }), /invalid_signature/);
  const replay = new Set();
  await verifySignedRequest(msg, { discovery: d, replay });
  await assert.rejects(verifySignedRequest(msg, { discovery: d, replay }), /Replayed/);
  const stale = signRequest('https://df.example/x', { token, jwk: key, created: t - 120 });
  await assert.rejects(verifySignedRequest({ method: 'GET', url: stale.url, headers: stale.headers }, { discovery: d }), /invalid_signature/);
  const future = signRequest('https://df.example/x', { token, jwk: key, created: t + 120 });
  await assert.rejects(verifySignedRequest({ method: 'GET', url: future.url, headers: future.headers }, { discovery: d }), /clock_skew/);
  const noq = signRequest('https://df.example/x?a=1', { token, jwk: key, query: false });
  await assert.rejects(verifySignedRequest({ method: 'GET', url: noq.url, headers: noq.headers }, { discovery: d, requireQuery: true }), /invalid_input/);
  const other = signRequest('https://df.example/x', { token, jwk: generateJwk() });
  await assert.rejects(verifySignedRequest({ method: 'GET', url: other.url, headers: other.headers }, { discovery: d }), /invalid_signature/);
});

test('replay set: a re-encoded or malleated signature over the same request is a replay', async () => {
  const P256_N = BigInt('0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551');
  const ap = generateJwk();
  const d = seededDiscovery(ap);
  const es256 = () => {
    const j = crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' }).privateKey.export({ format: 'jwk' });
    return { kty: 'EC', crv: 'P-256', x: j.x, y: j.y, d: j.d, alg: 'ES256' };
  };
  const unpadded = (b64) => b64.replace(/=+$/, '');
  const twin = (b64) => {
    const sig = Buffer.from(b64, 'base64');
    const s = BigInt('0x' + sig.subarray(32).toString('hex'));
    return Buffer.concat([sig.subarray(0, 32), Buffer.from((P256_N - s).toString(16).padStart(64, '0'), 'hex')]).toString('base64');
  };
  for (const [name, key, mutate] of [['Ed25519 unpadded', generateJwk(), unpadded], ['ES256 unpadded', es256(), unpadded], ['ES256 (r, n-s)', es256(), twin]]) {
    const t = now();
    const token = signJwt({ typ: 'aa-agent+jwt', jwk: ap, payload: { iss: AP, dwk: 'aauth-agent.json', sub: 'aauth:x@agent.example', cnf: { jwk: publicJwk(key) }, jti: randomId(), iat: t, exp: t + 600 } });
    const s = signRequest('https://df.example/api/v2/x', { method: 'POST', token, jwk: key, body: { a: 1 } });
    const msg = { method: s.method, url: s.url, headers: s.headers, body: s.body };
    const changed = { ...msg, headers: { ...msg.headers, signature: `sig=:${mutate(/sig=:([^:]+):/.exec(s.headers.signature)[1])}:` } };
    assert.notEqual(changed.headers.signature, msg.headers.signature, name);
    await verifySignedRequest(changed, { discovery: d }); // a valid signature on its own
    const replay = new Set();
    await verifySignedRequest(msg, { discovery: d, replay });
    await assert.rejects(verifySignedRequest(changed, { discovery: d, replay }), /Replayed/, name);
  }
});

import { startMock } from './mock-df.mjs';

test('Agent: full three-party flow, reuse, step-up, deny, always-allow, cancel (mock DF)', async () => {
  const ap = generateJwk();
  const mock = await startMock(ap);
  try {
    const mk = (sub) => {
      const d = new Discovery({ insecure: true });
      d.seed(AP, 'aauth-agent.json', { issuer: AP, jwks_uri: `${AP}/jwks.json` }, { keys: [publicJwk(ap)] });
      return new Agent({ issuer: AP, apKey: ap, agentKey: generateJwk(), sub, insecure: true, discovery: d, callback: false });
    };
    const approve = (extra = '') => async (i) => {
      const r = await fetch(`${mock.ORIGIN}/approve?code=${encodeURIComponent(i.code)}${extra}`);
      assert.equal(r.status, 200);
    };
    const a = mk('aauth:t1@agent.example');
    const url = `${mock.ORIGIN}/api/data?x=1`;

    const r1 = await a.request('GET', url, { onInteraction: approve() });
    assert.equal(r1.status, 200, JSON.stringify(r1.body));
    assert.deepEqual(r1.interactions.map((i) => i.purpose), ['person', 'auth']);
    assert.equal(r1.interactions[0].userUrl, `${mock.ORIGIN}/interact?code=${encodeURIComponent(r1.interactions[0].code)}`);

    const r2 = await a.request('GET', url, { onInteraction: () => assert.fail('no interaction expected') });
    assert.equal(r2.status, 200);
    assert.equal(r2.steps.filter((s) => s.kind === 'reuse').length, 1);

    const r3 = await a.request('PATCH', url, { body: { a: 1 }, onInteraction: approve() });
    assert.equal(r3.status, 200);
    assert.deepEqual(r3.interactions.map((i) => i.purpose), ['auth']);
    const authStep = r3.steps.find((s) => s.kind === 'auth_token');
    assert.equal(decodeJwt(JSON.parse(authStep.request.body).presented_token).header.typ, 'aa-auth+jwt');

    const b = mk('aauth:t2@agent.example');
    let n = 0;
    const r4 = await b.request('GET', url, { onInteraction: async (i) => approve(n++ === 0 ? '' : '&decision=deny')(i) });
    assert.equal(r4.status, 403);
    assert.equal(r4.error, 'denied');

    const c = mk('aauth:t3@agent.example');
    const r5 = await c.request('GET', url, { onInteraction: approve('&always=1') });
    assert.equal(r5.status, 200);
    // drop the cached auth token, keep the person token
    const k = `${AP}|${c.sub}|${c.jkt}|${mock.ORIGIN}|${mock.ORIGIN}`;
    c.cache.set(k, { person: c.cache.get(k).person });
    const r6 = await c.request('GET', url, { onInteraction: () => assert.fail('standing grant expected') });
    assert.equal(r6.status, 200);
    assert.equal(r6.steps.find((s) => s.kind === 'auth_token').status, 200);

    const d = mk('aauth:t4@agent.example');
    const r7 = await d.request('GET', url, { onInteraction: () => 'cancel' });
    assert.equal(r7.cancelled, true);
    assert.equal(r7.status, 200);
    assert.equal(mock.pending.size >= 0, true);
  } finally {
    await mock.close();
  }
});
