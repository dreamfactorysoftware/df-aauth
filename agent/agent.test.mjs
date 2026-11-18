// Offline tests for the Agent options added for library use: up-front scopes, an external
// agent-token source, generated request keys, callback URLs, extra headers and cancellation.
//
//   node --test agent/agent.test.mjs
import test from 'node:test';
import assert from 'node:assert/strict';
import { Agent, Discovery, generateJwk, publicJwk, decodeJwt, claims, scopesOf, assertAgentId, defaultAgentId } from './aauth.mjs';
import { mintAgentToken } from './provider.mjs';
import { startMock } from './mock-df.mjs';

const AP = 'https://agent.example';

function seeded(ap) {
  const d = new Discovery({ insecure: true });
  d.seed(AP, 'aauth-agent.json', { issuer: AP, jwks_uri: `${AP}/jwks.json` }, { keys: [publicJwk(ap)] });
  return d;
}
const approve = (mock, extra = '') => async (i) => {
  const r = await fetch(`${mock.ORIGIN}/approve?code=${encodeURIComponent(i.code)}${extra}`);
  assert.equal(r.status, 200);
};

test('scopesOf / agent ids', () => {
  assert.deepEqual(scopesOf('a b,c'), ['a', 'b', 'c']);
  assert.deepEqual(scopesOf(['a b', 'c']), ['a', 'b', 'c']);
  assert.deepEqual(scopesOf(undefined), []);
  assert.equal(defaultAgentId('https://agents.example.com'), 'aauth:agent@agents.example.com');
  assert.equal(defaultAgentId('https://agents.example.com', 'reports'), 'aauth:reports@agents.example.com');
  assert.ok(assertAgentId('aauth:a.b_c-d@x.example', 'https://x.example'));
  assert.throws(() => assertAgentId('aauth:bad name@x.example'));
  assert.throws(() => assertAgentId('aauth:a@other.example', 'https://x.example'), /host/);
});

test('scope up front: authorization_endpoint -> one consent -> call; widening keeps earlier scopes', async () => {
  const ap = generateJwk();
  const mock = await startMock(ap);
  try {
    const a = new Agent({ issuer: AP, apKey: ap, sub: 'aauth:s1@agent.example', insecure: true, discovery: seeded(ap), callback: false });
    const url = `${mock.ORIGIN}/api/data`;
    const r1 = await a.request('GET', url, { scope: 'read', onInteraction: approve(mock) });
    assert.equal(r1.status, 200, JSON.stringify(r1.body));
    assert.deepEqual(r1.interactions.map((i) => i.purpose), ['person', 'auth']);
    const kinds = r1.steps.map((s) => s.kind);
    assert.ok(kinds.includes('authorize'), kinds.join(','));
    assert.ok(!r1.steps.some((s) => s.kind === 'call' && s.title === 'Call with agent token'), 'no 401 round trip before the PS');
    const az = r1.steps.find((s) => s.kind === 'authorize');
    assert.equal(JSON.parse(az.request.body).scope, 'read');
    assert.equal(decodeJwt(az.request.headers['signature-key'].match(/jwt="([^"]+)"/)[1]).header.typ, 'aa-person+jwt');

    // already covered: no PS round trip
    const r2 = await a.request('GET', url, { scope: 'read', onInteraction: () => assert.fail('no interaction expected') });
    assert.equal(r2.status, 200);
    assert.ok(!r2.steps.some((s) => s.kind === 'authorize'));

    // widen: presents the auth token, asks for the union
    const r3 = await a.request('PATCH', url, { scope: 'write', body: { x: 1 }, onInteraction: approve(mock) });
    assert.equal(r3.status, 200, JSON.stringify(r3.body));
    const az3 = r3.steps.find((s) => s.kind === 'authorize');
    assert.equal(JSON.parse(az3.request.body).scope, 'read write');
    assert.equal(decodeJwt(az3.request.headers['signature-key'].match(/jwt="([^"]+)"/)[1]).header.typ, 'aa-auth+jwt');
    const auth = a.cache.get(a.cacheKey(mock.ORIGIN, mock.ORIGIN)).auth;
    assert.deepEqual(scopesOf(auth).sort(), ['read', 'write']);

    // unknown scope: the resource's error comes back, no interaction
    const r4 = await a.request('GET', url, { scope: 'nope', onInteraction: () => assert.fail('no interaction expected') });
    assert.equal(r4.status, 400);
    assert.equal(r4.error, 'invalid_scope');
  } finally {
    await mock.close();
  }
});

test('agentToken(ps) source instead of apKey; generated agentKey; callback URL; extra headers', async () => {
  const ap = generateJwk();
  const mock = await startMock(ap);
  try {
    const agentKey = generateJwk();
    let calls = 0;
    const a = new Agent({
      issuer: AP,
      sub: 'aauth:remote@agent.example',
      agentKey,
      insecure: true,
      discovery: seeded(ap),
      callback: 'https://agent.example/done',
      agentToken: async (ps) => {
        calls++;
        return mintAgentToken({ issuer: AP, apKey: ap, sub: 'aauth:remote@agent.example', agentJwk: agentKey, ps, ttl: 600 });
      },
    });
    assert.throws(() => a.agentToken(), /apKey/);
    const seen = [];
    const r = await a.request('GET', `${mock.ORIGIN}/api/data?x=1`, {
      headers: { 'x-request-id': 'abc' },
      onInteraction: async (i) => {
        seen.push(i.userUrl);
        await approve(mock)(i);
      },
    });
    assert.equal(r.status, 200, JSON.stringify(r.body));
    assert.ok(calls >= 1);
    assert.ok(seen[0].endsWith(`&callback=${encodeURIComponent('https://agent.example/done')}`), seen[0]);
    assert.ok(r.steps.filter((s) => s.request).every((s) => s.request.url.includes('/pending/') || s.request.url.includes('/person') || s.request.url.includes('/token') || s.request.headers['x-request-id'] === 'abc'));

    // a token for some other key is refused before it is used
    const wrong = new Agent({ issuer: AP, sub: 'aauth:remote@agent.example', insecure: true, discovery: seeded(ap), agentToken: async (ps) => mintAgentToken({ issuer: AP, apKey: ap, sub: 'aauth:remote@agent.example', agentJwk: generateJwk(), ps }) });
    await assert.rejects(wrong.request('GET', `${mock.ORIGIN}/api/data`), /invalid_agent_token/);

    // no agentKey given: one is generated
    const g = new Agent({ issuer: AP, apKey: ap });
    assert.equal(g.sub, 'aauth:agent@agent.example');
    assert.equal(claims(g.agentToken()).cnf.jwk.x, g.agentKey.x);
    assert.equal(new Agent({ issuer: AP, apKey: ap, callback: true }).callbackUrl, `${AP}/callback`);
    assert.equal(new Agent({ issuer: AP, apKey: ap, callback: false }).callbackUrl, null);
  } finally {
    await mock.close();
  }
});

test('abort while waiting for the person cancels the pending request', async () => {
  const ap = generateJwk();
  const mock = await startMock(ap);
  try {
    const a = new Agent({ issuer: AP, apKey: ap, sub: 'aauth:abort@agent.example', insecure: true, discovery: seeded(ap), callback: false });
    const ac = new AbortController();
    const r = await a.request('GET', `${mock.ORIGIN}/api/data`, {
      signal: ac.signal,
      onInteraction: () => {
        setTimeout(() => ac.abort(), 50);
      },
    });
    assert.equal(r.cancelled, true);
    assert.ok(mock.log.some((l) => l.startsWith('DELETE /pending/')), mock.log.join(','));
  } finally {
    await mock.close();
  }
});

test('concurrent requests on one Agent keep their own onStep callbacks', async () => {
  const ap = generateJwk();
  const mock = await startMock(ap);
  try {
    const a = new Agent({ issuer: AP, apKey: ap, sub: 'aauth:par@agent.example', insecure: true, discovery: seeded(ap), callback: false });
    const first = await a.request('GET', `${mock.ORIGIN}/api/data?n=0`, { onInteraction: approve(mock) });
    assert.equal(first.status, 200);
    const logs = [[], [], []];
    const rs = await Promise.all(logs.map((log, n) => a.request('GET', `${mock.ORIGIN}/api/data?n=${n + 1}`, { onStep: (s) => log.push(s.request?.url || s.title) })));
    assert.deepEqual(rs.map((r) => r.status), [200, 200, 200]);
    logs.forEach((log, n) => {
      const urls = log.filter((x) => x.startsWith('http'));
      assert.ok(urls.length >= 1 && urls.every((u) => u.endsWith(`?n=${n + 1}`)), JSON.stringify(log));
    });
  } finally {
    await mock.close();
  }
});
