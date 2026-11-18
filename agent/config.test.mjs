// Offline tests for config.mjs (identity files) and provider.mjs (Agent Provider documents).
//
//   node --test agent/config.test.mjs
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { Discovery, claims, jwkThumbprint, generateJwk, publicJwk } from './aauth.mjs';
import { initIdentity, loadIdentity, createAgent, ConfigError, slug } from './config.mjs';
import { providerDocuments, createProviderHandler, startProvider, mintAgentToken, checkProvider } from './provider.mjs';

const tmp = () => fs.mkdtempSync(path.join(os.tmpdir(), 'aauth-cfg-'));

test('init creates a private identity + public provider files; loading it back', () => {
  const dir = tmp();
  try {
    const file = path.join(dir, 'agent.json');
    const r = initIdentity({ issuer: 'https://agents.example.com', name: 'Acme Reports', file });
    assert.equal(r.created, true);
    assert.equal(r.identity.sub, 'aauth:acme-reports@agents.example.com');
    assert.equal(fs.statSync(file).mode & 0o777, 0o600);
    const j = JSON.parse(fs.readFileSync(file, 'utf8'));
    assert.equal(j.version, 1);
    assert.ok(j.ap.d && j.agent.d, 'private keys stored');
    assert.equal(j.callback_endpoint, undefined);

    const meta = JSON.parse(fs.readFileSync(path.join(dir, 'public/.well-known/aauth-agent.json'), 'utf8'));
    assert.deepEqual(meta, { issuer: 'https://agents.example.com', jwks_uri: 'https://agents.example.com/jwks.json', name: 'Acme Reports' });
    const jwks = JSON.parse(fs.readFileSync(path.join(dir, 'public/jwks.json'), 'utf8'));
    assert.equal(jwks.keys.length, 1);
    assert.equal(jwks.keys[0].d, undefined, 'no private material published');
    assert.equal(jwks.keys[0].kid, j.ap.kid);
    assert.deepEqual(Object.keys(r.published), ['https://agents.example.com/.well-known/aauth-agent.json', 'https://agents.example.com/jwks.json']);

    // idempotent: same keys, files refreshed
    const again = initIdentity({ issuer: 'https://agents.example.com', file });
    assert.equal(again.created, false);
    assert.equal(again.identity.ap.kid, j.ap.kid);
    assert.throws(() => initIdentity({ issuer: 'https://other.example.com', file }), ConfigError);

    const id = loadIdentity({ file, env: {} });
    assert.equal(id.issuer, 'https://agents.example.com');
    assert.equal(id.name, 'Acme Reports');
    assert.equal(id.tokensFile, path.join(dir, 'tokens.json'));
    const env = loadIdentity({ env: { AAUTH_CONFIG: file, AAUTH_AGENT_ID: 'aauth:x@agents.example.com', AAUTH_PS: 'https://ps.example', AAUTH_TOKENS: path.join(dir, 't.json') } });
    assert.equal(env.sub, 'aauth:x@agents.example.com');
    assert.equal(env.ps, 'https://ps.example');
    assert.equal(env.tokensFile, path.join(dir, 't.json'));

    const agent = createAgent(id);
    assert.equal(agent.sub, id.sub);
    assert.equal(agent.callbackUrl, null);
    const c = claims(agent.agentToken('https://df.example.com'));
    assert.equal(c.iss, 'https://agents.example.com');
    assert.equal(c.sub, 'aauth:acme-reports@agents.example.com');
    assert.equal(c.ps, 'https://df.example.com');
    assert.equal(jwkThumbprint(c.cnf.jwk), jwkThumbprint(j.agent));
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('init validation, --callback, legacy keys files, the default location', () => {
  const dir = tmp();
  try {
    for (const bad of ['http://agents.example.com', 'https://agents.example.com/path', 'https://agents.example.com:8443', 'agents.example.com']) {
      assert.throws(() => initIdentity({ issuer: bad, file: path.join(dir, 'x.json') }), ConfigError, bad);
    }
    assert.throws(() => initIdentity({ file: path.join(dir, 'y.json') }), /--issuer is required/);
    assert.throws(() => initIdentity({ issuer: 'https://a.example', id: 'has space', file: path.join(dir, 'z.json') }), ConfigError);
    const cb = initIdentity({ issuer: 'https://a.example', id: 'bot', callback: true, file: path.join(dir, 'cb.json'), publicDir: path.join(dir, 'www') });
    assert.equal(cb.identity.sub, 'aauth:bot@a.example');
    assert.equal(cb.documents['/.well-known/aauth-agent.json'].callback_endpoint, 'https://a.example/callback');
    assert.ok(fs.existsSync(path.join(dir, 'www/jwks.json')));

    // the reference deployment's keys file: { ap, agent } with the issuer from the environment
    const keys = path.join(dir, 'keys.json');
    fs.writeFileSync(keys, JSON.stringify({ ap: generateJwk(), agent: generateJwk() }));
    const legacy = loadIdentity({ env: { AAUTH_KEYS: keys, AAUTH_AGENT_ISSUER: 'https://legacy.example' } });
    assert.equal(legacy.sub, 'aauth:agent@legacy.example');
    assert.equal(legacy.callback, true);

    // $AAUTH_HOME/agent.json is the default; a missing explicit file is an error, never a fallback
    initIdentity({ issuer: 'https://home.example', name: 'Home', env: { AAUTH_HOME: path.join(dir, 'home') } });
    assert.equal(loadIdentity({ env: { AAUTH_HOME: path.join(dir, 'home') } }).issuer, 'https://home.example');
    assert.throws(() => loadIdentity({ env: { AAUTH_CONFIG: path.join(dir, 'missing.json') } }), ConfigError);
    assert.throws(() => loadIdentity({ env: { AAUTH_HOME: path.join(dir, 'empty'), AAUTH_AGENT_ISSUER: 'https://nobody.example' }, reference: false }), /aauth init/);
    assert.equal(slug('Acme Reports!'), 'acme-reports');
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('provider: documents, handler, mintAgentToken verifies through discovery, checkProvider', async () => {
  const ap = generateJwk();
  const old = generateJwk();
  const docs = providerDocuments({ issuer: 'https://agents.example.com/', name: 'Bot', apKey: ap, previousKeys: [old], callback: true });
  assert.equal(docs['/.well-known/aauth-agent.json'].issuer, 'https://agents.example.com');
  assert.equal(docs['/.well-known/aauth-agent.json'].callback_endpoint, 'https://agents.example.com/callback');
  assert.deepEqual(docs['/jwks.json'].keys.map((k) => k.kid), [ap.kid, old.kid]);

  const server = await startProvider({ issuer: 'https://agents.example.com', name: 'Bot', apKey: ap, port: 0, host: '127.0.0.1' });
  try {
    const base = `http://127.0.0.1:${server.address().port}`;
    const meta = await (await fetch(`${base}/.well-known/aauth-agent.json`)).json();
    assert.equal(meta.jwks_uri, 'https://agents.example.com/jwks.json');
    const jwks = await (await fetch(`${base}/jwks.json`)).json();
    assert.deepEqual(jwks.keys, [publicJwk(ap)]);
    const denied = await fetch(`${base}/callback?error=access_denied`);
    assert.equal(denied.status, 200);
    const deniedHtml = await denied.text();
    assert.match(deniedHtml, /<title>Not approved<\/title>/);
    assert.match(deniedHtml, /<h1>Not approved<\/h1><p><code>access_denied<\/code><\/p><p>Return to your terminal\.<\/p>/);
    // the browser can come back after the identity step only: neutral wording, never "Approved"
    const back = await (await fetch(`${base}/callback`)).text();
    assert.match(back, /<title>Done<\/title>/);
    assert.match(back, /<h1>Done<\/h1><p>Return to your terminal\.<\/p>/);
    assert.doesNotMatch(back, /Approved/);
    assert.equal((await fetch(`${base}/nope`)).status, 404);
    assert.equal((await fetch(`${base}/jwks.json`, { method: 'POST' })).status, 405);

    // checkProvider against the running server (fetch rewritten from the issuer to the local port)
    const viaLocal = (u, init) => fetch(String(u).replace('https://agents.example.com', base), init);
    const ok = await checkProvider({ issuer: 'https://agents.example.com', apKey: ap, sub: 'aauth:bot@agents.example.com', fetchImpl: viaLocal });
    assert.equal(ok.ok, true, JSON.stringify(ok.checks));
    const bad = await checkProvider({ issuer: 'https://agents.example.com', apKey: generateJwk(), fetchImpl: viaLocal });
    assert.equal(bad.ok, false);
  } finally {
    await new Promise((r) => server.close(r));
  }

  // chaining: the handler leaves unknown paths alone
  const handle = createProviderHandler({ issuer: 'https://agents.example.com', apKey: ap, home: false });
  assert.equal(handle({ url: '/', method: 'GET' }, {}), false);

  const agentKey = generateJwk();
  const token = mintAgentToken({ issuer: 'https://agents.example.com', apKey: ap, sub: 'aauth:bot@agents.example.com', agentJwk: agentKey, ps: 'https://df.example.com' });
  const d = new Discovery();
  d.seed('https://agents.example.com', 'aauth-agent.json', docs['/.well-known/aauth-agent.json'], docs['/jwks.json']);
  const v = await d.verifyJwt(token, 'aa-agent+jwt');
  assert.equal(v.payload.sub, 'aauth:bot@agents.example.com');
  assert.equal(v.payload.cnf.jwk.d, undefined, 'only the public agent key goes into cnf');
  assert.throws(() => mintAgentToken({ issuer: 'https://a.example', apKey: ap, sub: 'aauth:x@a.example', agentJwk: agentKey, ttl: 90_000 }), /24 h/);
});
