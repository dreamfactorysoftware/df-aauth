// person.mjs against a mock consent UI that follows README.md "Consent page contract".
//   node --test agent/person.test.mjs
import test from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import crypto from 'node:crypto';
import { Browser, personAct, scan } from './person.mjs';

function mockPs() {
  const sessions = new Map(); // sid -> { csrf, user }
  const pending = new Map(); // code -> { kind, status, scopes:[{scope,grantable}] }
  const server = http.createServer(async (req, res) => {
    const url = new URL(req.url, 'http://x');
    let body = '';
    for await (const c of req) body += c;
    const form = new URLSearchParams(body);
    let sid = /sid=([^;]+)/.exec(req.headers.cookie || '')?.[1];
    let sess = sid && sessions.get(sid);
    const headers = {};
    if (!sess) {
      sid = crypto.randomUUID();
      sess = { csrf: crypto.randomUUID(), user: null };
      sessions.set(sid, sess);
      headers['set-cookie'] = `sid=${sid}; Path=/; HttpOnly; SameSite=Lax`;
    }
    const code = url.searchParams.get('code') || form.get('code');
    const p = code && pending.get(code.toUpperCase());
    const card = (state, inner, extra = '') => {
      res.writeHead(200, { 'content-type': 'text/html', ...headers });
      res.end(`<!doctype html><main class="card" data-aauth-state="${state}" ${extra}>${inner}</main>`);
    };
    const hidden = `<input type="hidden" name="_token" value="${sess.csrf}"><input type='hidden' name="code" value="${code || ''}">`;
    if (req.method === 'POST' && form.get('_token') !== sess.csrf) {
      res.writeHead(419);
      return res.end('csrf');
    }
    if (!p) return card('code', `<form method="post" action="/aauth/interact">${hidden}<input name="code"><button>Continue</button></form>`);
    if (p.status !== 'pending') return card('done', '', `data-aauth-result="${p.status}"`);
    if (req.method === 'POST' && form.has('password')) {
      if (form.get('password') !== 'pw') return card('signin', `<p data-aauth-error>Wrong email or password</p><form method="post">${hidden}<input name="email"><input name="password" type="password"></form>`);
      sess.user = form.get('email');
      if (p.kind === 'person') {
        p.status = 'approved';
        res.writeHead(303, { location: `/aauth/interact?code=${code}`, ...headers });
        return res.end();
      }
      res.writeHead(302, { location: `/aauth/interact?code=${code}`, ...headers });
      return res.end();
    }
    if (req.method === 'POST' && form.has('decision')) {
      const d = form.get('decision');
      if (d === 'switch') {
        sess.user = null;
      } else {
        p.status = d === 'allow' ? 'approved' : 'denied';
        p.always = form.get('always') === '1';
        p.granted = form.getAll('scopes[]');
      }
      res.writeHead(303, { location: `/aauth/interact?code=${code}`, ...headers });
      return res.end();
    }
    if (!sess.user) return card('signin', `<h1>Acme &amp; Co</h1><form method="post" action="">${hidden}<input name="email" type="email"><input name="password" type="password"><button type="submit">Sign in</button></form>`);
    if (p.kind === 'person')
      return card('identity', `<form method="post">${hidden}<button name="decision" value="switch">Not you?</button><button name="decision" value="allow">Continue</button><button name="decision" value="deny">Deny</button></form>`);
    const list = p.scopes.map((s) => `<li data-aauth-scope="${s.scope}" data-aauth-grantable="${s.grantable ? 1 : 0}">${s.scope}${s.grantable ? `<input type="checkbox" name="scopes[]" value="${s.scope}" checked>` : ''}</li>`).join('');
    const none = !p.scopes.some((s) => s.grantable);
    return card('consent', `<ul>${list}</ul><form method="post">${hidden}<label><input type="checkbox" name="always" value="1"> Always allow</label><button name="decision" value="deny">Deny</button><button name="decision" value="allow"${none ? ' disabled' : ''}>Allow</button></form>`);
  });
  return { server, pending };
}

test('scan() reads the contract attributes', () => {
  const s = scan(`<div data-aauth-state=consent><p data-aauth-error>Nope &amp; no</p><li data-aauth-scope='a.b' data-aauth-grantable="0"></li><form method=post><input type=hidden name=_token value="t&quot;1"><button name="decision" value="allow" disabled>Allow</button></form></div>`);
  assert.equal(s.state, 'consent');
  assert.equal(s.error, 'Nope & no');
  assert.deepEqual(s.scopes, [{ scope: 'a.b', grantable: false }]);
  assert.equal(s.forms[0].inputs[0].value, 't"1');
  assert.ok('disabled' in s.forms[0].buttons[0]);
});

test('personAct: sign-in, identity, consent (allow/deny/always/non-grantable), bad password', async () => {
  const { server, pending } = mockPs();
  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  const base = `http://127.0.0.1:${server.address().port}/aauth/interact`;
  try {
    const b = new Browser('p');
    pending.set('AAAA-0001', { kind: 'person', status: 'pending' });
    let r = await personAct(b, base, 'AAAA-0001', { email: 'a@x', password: 'pw' });
    assert.equal(r.result, 'approved');
    assert.deepEqual(r.trail, ['signin', 'done']);

    pending.set('AAAA-0002', { kind: 'person', status: 'pending' });
    r = await personAct(b, base, 'AAAA-0002', { email: 'a@x', password: 'pw' });
    assert.deepEqual(r.trail, ['identity', 'done']);

    pending.set('AAAA-0003', { kind: 'auth', status: 'pending', scopes: [{ scope: 'sales.read', grantable: true }, { scope: 'sales.refund', grantable: false }] });
    r = await personAct(b, base, 'AAAA-0003', { decision: 'allow', always: true });
    assert.equal(r.result, 'approved');
    assert.equal(pending.get('AAAA-0003').always, true);
    assert.deepEqual(pending.get('AAAA-0003').granted, ['sales.read']);
    assert.deepEqual(r.consents[0].scopes, [{ scope: 'sales.read', grantable: true }, { scope: 'sales.refund', grantable: false }]);

    pending.set('AAAA-0004', { kind: 'auth', status: 'pending', scopes: [{ scope: 'sales.refund', grantable: false }] });
    r = await personAct(b, base, 'AAAA-0004', { onConsent: (i) => (i.allowDisabled ? 'deny' : 'allow') });
    assert.equal(r.result, 'denied');
    assert.equal(r.consents[0].allowDisabled, true);

    const b2 = new Browser('q');
    pending.set('AAAA-0005', { kind: 'person', status: 'pending' });
    await assert.rejects(personAct(b2, base, 'AAAA-0005', { email: 'a@x', password: 'bad' }), /sign-in failed: Wrong email or password/);
    await assert.rejects(personAct(b2, base, 'ZZZZ-9999', {}), /code rejected/);
  } finally {
    server.close();
  }
});
