#!/usr/bin/env node
// End-to-end checks for AAuth on DreamFactory. Plays both the agent (aauth.mjs) and the
// person (plain HTTP against /aauth/interact with a cookie jar and CSRF tokens), and uses
// the admin API for setup and assertions. See README.md "Consent page contract".
//
//   DF_URL=https://df.example.com node e2e.mjs [--only 1,3,8] [--verbose]
//   node e2e.mjs --target https://df.example.com ...
//
// It CHANGES the target instance (toggles AAuth, patches an order, blocks/unblocks agents) and
// restores it at the end, also on Ctrl-C / SIGTERM. There is deliberately no default target.
// Env: DF_URL (or --target), DF_ALT_URL (the same DF by another authority, for the wrong-authority
// check; skipped when unset), AAUTH_AGENT_ISSUER, AAUTH_KEYS.
// Credentials: DF_ADMIN_PASSWORD / DF_USER_PASSWORD, else --creds-stdin (two lines:
// admin password, user password), else the password files named in agent/reference.json (a local,
// git-ignored file; see DEVELOPMENT.md). They are never printed. Accounts: DF_ADMIN_EMAIL and
// DF_USER_EMAIL (defaults match bin/demo-seed.sh).
import { Browser, personAct, credentials, setLogger } from './person.mjs';
import {
  Agent,
  Discovery,
  loadKeys,
  generateJwk,
  publicJwk,
  signJwt,
  signRequest,
  toRecord,
  randomId,
  now,
  claims,
  DEFAULT_ISSUER,
} from './aauth.mjs';

const args = process.argv.slice(2);
async function usage(code) {
  const lines = (await import('node:fs')).readFileSync(new URL(import.meta.url), 'utf8').split('\n').slice(1);
  const header = [];
  for (const l of lines) {
    if (!l.startsWith('//')) break;
    header.push(l.replace(/^\/\/ ?/, ''));
  }
  (code ? process.stderr : process.stdout).write(`${header.join('\n')}\n`);
  process.exit(code);
}
const KNOWN = { '--only': 1, '--target': 1, '--verbose': 0, '-v': 0, '--creds-stdin': 0, '--help': 0, '-h': 0 };
for (let i = 0; i < args.length; i++) {
  if (!(args[i] in KNOWN)) {
    process.stderr.write(`unknown argument ${args[i]}\n\n`);
    await usage(2);
  }
  i += KNOWN[args[i]];
}
const flag = (n) => args.includes(n);
const opt = (n) => {
  const i = args.indexOf(n);
  return i >= 0 ? args[i + 1] : undefined;
};
if (flag('--help') || flag('-h')) await usage(0);
const VERBOSE = flag('--verbose') || flag('-v');
const ONLY = (opt('--only') || '').split(',').filter(Boolean).map(Number);

const TARGET = opt('--target') || process.env.DF_URL;
if (!TARGET) {
  process.stderr.write('Set DF_URL or pass --target <url>: this suite changes the instance it runs against.\n\n');
  await usage(2);
}
const DF = TARGET.replace(/\/+$/, '');
const ALT = (process.env.DF_ALT_URL || '').replace(/\/+$/, '');
const AP = String(process.env.AAUTH_AGENT_ISSUER || DEFAULT_ISSUER || '').replace(/\/+$/, '');
if (!AP) {
  process.stderr.write('Set AAUTH_AGENT_ISSUER to the Agent Provider the suite signs as (server.mjs with AAUTH_KEYS).\n\n');
  await usage(2);
}
const AP_HOST = new URL(AP).host;
const ADMIN_EMAIL = process.env.DF_ADMIN_EMAIL || 'admin@example.com';
const USER_EMAIL = process.env.DF_USER_EMAIL || 'jordan@example.com';
const ORDERS = `${DF}/api/v2/sales/_table/orders`;

const { adminPassword: ADMIN_PW, userPassword: USER_PW } = credentials({ stdin: flag('--creds-stdin') });

// ---------------------------------------------------------------------------
// Reporting
// ---------------------------------------------------------------------------
const results = [];
let current = null;
function check(cond, label, detail) {
  current.checks.push({ ok: !!cond, label, detail });
  if (VERBOSE || !cond) console.log(`    ${cond ? 'ok  ' : 'FAIL'} ${label}${!cond && detail !== undefined ? `  -> ${typeof detail === 'string' ? detail : JSON.stringify(detail).slice(0, 400)}` : ''}`);
  return !!cond;
}
async function scenario(n, title, fn) {
  if (ONLY.length && !ONLY.includes(n)) return;
  current = { n, title, checks: [] };
  console.log(`\n[${n}] ${title}`);
  try {
    await fn();
  } catch (e) {
    check(false, 'threw', e.stack ? e.stack.split('\n').slice(0, 3).join(' | ') : String(e));
  }
  const pass = current.checks.length > 0 && current.checks.every((c) => c.ok);
  results.push({ n, title, pass });
  console.log(`${pass ? 'PASS' : 'FAIL'} ${n}. ${title}`);
}
const vlog = (...a) => VERBOSE && console.log('     ', ...a);
setLogger(vlog);

// ---------------------------------------------------------------------------
// DF admin API
// ---------------------------------------------------------------------------
let SESSION;
async function login() {
  const res = await fetch(`${DF}/api/v2/system/admin/session`, {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded', accept: 'application/json' },
    body: new URLSearchParams({ email: ADMIN_EMAIL, password: ADMIN_PW }).toString(),
  });
  const j = await res.json().catch(() => ({}));
  if (!j.session_token) throw new Error(`admin login failed (HTTP ${res.status})`);
  SESSION = j.session_token;
}
async function api(method, p, body) {
  const res = await fetch(`${DF}/api/v2${p}`, {
    method,
    headers: { 'x-dreamfactory-session-token': SESSION, accept: 'application/json', ...(body ? { 'content-type': 'application/json' } : {}) },
    body: body ? JSON.stringify(body) : undefined,
  });
  const text = await res.text();
  let json;
  try {
    json = JSON.parse(text);
  } catch {
    json = text;
  }
  return { status: res.status, body: json, headers: res.headers };
}

// ---------------------------------------------------------------------------
// Agents
// ---------------------------------------------------------------------------
const keys = loadKeys();
const discovery = new Discovery();
function makeAgent(name) {
  const cache = new Map();
  const agent = new Agent({
    issuer: AP,
    apKey: keys.ap,
    agentKey: generateJwk(),
    sub: `aauth:e2e-${name}@${AP_HOST}`,
    discovery,
    callback: false,
    cache: { get: (k) => cache.get(k), set: (k, v) => cache.set(k, v), delete: (k) => cache.delete(k) },
  });
  agent.dropAuth = () => {
    for (const [k, v] of cache) cache.set(k, { person: v.person });
  };
  agent.tokens = () => [...cache.values()][0] || {};
  return agent;
}
const admin = new Browser('admin');
const jordan = new Browser('jordan');

/** Run an agent request, acting as `who` on every interaction with the given plan. */
async function run(agent, method, url, { body, browser = admin, plan = {}, cancel = false } = {}) {
  const acts = [];
  const result = await agent.request(method, url, {
    body,
    why: 'e2e check',
    pollTimeoutMs: 60_000,
    onStep: (s) => vlog(`agent ${s.kind}: ${s.request ? `${s.request.method} ${s.request.url}` : s.title} -> ${s.status}`),
    onInteraction: async (info) => {
      vlog(`interaction ${info.purpose} code=${info.code}`);
      if (cancel) return 'cancel';
      if (!info.code || !info.url) throw new Error(`202 without interaction url/code: ${JSON.stringify(info)}`);
      const p = { email: browser === jordan ? USER_EMAIL : ADMIN_EMAIL, password: browser === jordan ? USER_PW : ADMIN_PW, ...plan };
      const act = await personAct(browser, info.url, info.code, p);
      acts.push({ purpose: info.purpose, ...act });
      vlog(`person result ${act.result} via ${act.trail.join(' > ')}`);
    },
  });
  result.acts = acts;
  return result;
}
const brief = (r) => ({ status: r.status, error: r.error, detail: r.detail, body: typeof r.body === 'string' ? r.body.slice(0, 200) : r.body, acts: r.acts?.map((a) => `${a.purpose}:${a.result}`) });

/** Send a hand-built signed request (for tampering tests). */
async function rawSend(signed, override = {}) {
  const res = await fetch(override.url || signed.url, {
    method: signed.method,
    headers: { ...signed.headers, ...(override.headers || {}) },
    body: override.body !== undefined ? override.body : signed.body,
    redirect: 'manual',
  });
  return toRecord(res, signed);
}

// ---------------------------------------------------------------------------
// Preflight
// ---------------------------------------------------------------------------
console.log(`DF ${DF}   agent provider ${AP}`);
if (!ADMIN_PW) {
  console.log('FAIL preflight: admin credentials not available (see header of e2e.mjs)');
  process.exit(1);
}
const metaRes = await fetch(`${DF}/.well-known/aauth-resource.json`).catch((e) => ({ status: 0, e }));
await login();
const initial = await api('GET', '/system/aauth');
if (initial.status !== 200) {
  console.log(`FAIL preflight: GET /api/v2/system/aauth -> ${initial.status} (is df-aauth installed?)`);
  process.exit(1);
}
const wasEnabled = !!initial.body.enabled;
// Restore on Ctrl-C / SIGTERM too: unblock e2e agents, put the enabled switch back, remove e2e agents.
const restoreSteps = [];
let restoring = false;
async function restore() {
  if (restoring) return;
  restoring = true;
  for (const step of restoreSteps.splice(0).reverse()) {
    try {
      await step();
    } catch (e) {
      console.log(`restore step failed: ${e.message}`);
    }
  }
}
for (const sig of ['SIGINT', 'SIGTERM']) {
  process.once(sig, async () => {
    console.log(`\n${sig}: restoring the instance before exit...`);
    await restore();
    process.exit(130);
  });
}
async function e2eAgents() {
  return ((await api('GET', '/system/aauth/agents')).body?.resource || []).filter((a) => String(a.agent_id || '').startsWith('aauth:e2e-'));
}
restoreSteps.push(async () => {
  for (const a of await e2eAgents()) {
    if (a.status === 'blocked') await api('PATCH', `/system/aauth/agents/${a.id}`, { status: 'allowed' });
    await api('DELETE', `/system/aauth/agents/${a.id}?purge_activity=true`);
  }
  for (const g of (await api('GET', '/system/aauth/grants')).body?.resource || []) {
    if (String(g.agent_sub || '').startsWith('aauth:e2e-')) await api('DELETE', `/system/aauth/grants/${g.id}`);
  }
});
restoreSteps.push(async () => {
  const st = await api('GET', '/system/aauth');
  if (st.status === 200 && !!st.body.enabled !== wasEnabled) await api('PATCH', '/system/aauth', { enabled: wasEnabled });
});
if (!wasEnabled) {
  const r = await api('PATCH', '/system/aauth', { enabled: true });
  if (r.status !== 200) {
    console.log(`FAIL preflight: enabling AAuth -> ${r.status} ${JSON.stringify(r.body).slice(0, 300)}`);
    process.exit(1);
  }
}
vlog(`metadata status before enable: ${metaRes.status}`);
const scopesRes = await api('GET', '/system/aauth/scopes');
const scopeRows = scopesRes.body?.resource || [];
for (const s of ['sales.read', 'sales.refund']) {
  if (!scopeRows.some((r) => r.scope === s && r.enabled)) {
    console.log(`FAIL preflight: scope ${s} is not configured/enabled (run bin/demo-seed.sh)`);
    process.exit(1);
  }
}
// Leftovers from earlier runs: grants and blocks for e2e agents.
for (const g of (await api('GET', '/system/aauth/grants')).body?.resource || []) {
  if (String(g.agent_sub || '').startsWith('aauth:e2e-')) await api('DELETE', `/system/aauth/grants/${g.id}`);
}
for (const a of (await api('GET', '/system/aauth/agents')).body?.resource || []) {
  if (String(a.agent_id || '').startsWith('aauth:e2e-') && a.status === 'blocked') await api('PATCH', `/system/aauth/agents/${a.id}`, { status: 'allowed' });
}

const main = makeAgent('main');
let orderId;
let orderStatus;

// ---------------------------------------------------------------------------
// Scenarios
// ---------------------------------------------------------------------------
await scenario(1, 'Full three-party flow as the admin: GET orders -> 200', async () => {
  const r = await run(main, 'GET', `${ORDERS}?limit=3`);
  check(r.status === 200, 'final status 200', brief(r));
  const rows = r.body?.resource;
  check(Array.isArray(rows) && rows.length > 0, 'orders returned', brief(r));
  check(r.acts.length >= 1, 'the person was asked', r.acts);
  check(r.acts.every((a) => a.result === 'approved'), 'every interaction approved', r.acts.map((a) => a.result));
  const consent = r.acts.flatMap((a) => a.consents)[0];
  check(consent && consent.scopes.some((s) => s.scope === 'sales.read' && s.grantable), 'consent listed sales.read as grantable', consent);
  const t = main.tokens();
  check(t.auth && claims(t.auth).scope?.split(' ').includes('sales.read'), 'auth token carries sales.read', t.auth && claims(t.auth).scope);
  check(r.headers?.['aauth-scope'] === undefined || r.headers['aauth-scope'] === 'sales.read', 'AAuth-Scope header (if sent) is sales.read', r.headers?.['aauth-scope']);
  if (rows?.length) {
    orderId = rows[0].id;
    orderStatus = rows[0].status;
  }
});

await scenario(2, 'Second call reuses the auth token (no interaction)', async () => {
  const r = await run(main, 'GET', `${ORDERS}?limit=1`);
  check(r.status === 200, 'status 200', brief(r));
  check(r.interactions.length === 0, 'no interaction', r.interactions);
  check(r.steps.some((s) => s.kind === 'reuse'), 'used the cached auth token');
  check(!r.steps.some((s) => s.kind === 'person_token' || s.kind === 'auth_token'), 'no PS round trip');
});

await scenario(3, 'Step-up: PATCH an order needs sales.refund -> new consent -> 200', async () => {
  if (!check(orderId !== undefined, 'have an order id from scenario 1')) return;
  const r = await run(main, 'PATCH', `${ORDERS}/${orderId}`, { body: { status: 'refunded' } });
  check(r.status === 200, 'status 200', brief(r));
  check(r.acts.length === 1 && r.acts[0].purpose === 'auth', 'exactly one new consent (auth)', r.acts.map((a) => a.purpose));
  const scopes = r.acts[0]?.consents[0]?.scopes || [];
  check(scopes.some((s) => s.scope === 'sales.refund' && s.grantable), 'consent listed sales.refund as grantable', scopes);
  check(claims(main.tokens().auth).scope?.split(' ').includes('sales.refund'), 'new auth token carries sales.refund');
  const auth = r.steps.find((s) => s.kind === 'auth_token');
  const presented = auth?.request?.body && JSON.parse(auth.request.body).presented_token;
  check(presented && claims(presented).dwk === 'aauth-person.json' && decodeTyp(presented) === 'aa-auth+jwt', 'step-up presented the previous auth token');
  // design 4.2: a resource token is single-use at the PS. Re-send the same body, freshly signed.
  if (auth?.request?.body) {
    const again = await rawSend(signRequest(auth.request.url, { method: 'POST', token: main.agentToken(DF), jwk: main.agentKey, body: JSON.parse(auth.request.body) }));
    check(again.status === 400 && again.body?.error === 'invalid_resource_token', 'replayed resource token -> 400 invalid_resource_token', { status: again.status, body: again.body });
  }
  // restore (should reuse the new token)
  const back = await run(main, 'PATCH', `${ORDERS}/${orderId}`, { body: { status: orderStatus ?? 'paid' } });
  check(back.status === 200 && back.interactions.length === 0, 'restoring the status reuses the token', brief(back));
});
function decodeTyp(jwt) {
  return JSON.parse(Buffer.from(jwt.split('.')[0], 'base64url')).typ;
}

await scenario(4, 'Jordan (non-admin) can grant sales.read but not sales.refund', async () => {
  if (!check(USER_PW, `password for ${USER_EMAIL} available (bin/demo-seed.sh writes it)`)) return;
  const a = makeAgent('jordan');
  const r1 = await run(a, 'GET', `${ORDERS}?limit=2`, { browser: jordan });
  check(r1.status === 200, 'GET with sales.read -> 200', brief(r1));
  const c1 = r1.acts.flatMap((x) => x.consents)[0];
  check(c1?.scopes.some((s) => s.scope === 'sales.read' && s.grantable), 'sales.read grantable for Jordan', c1);
  if (orderId === undefined) return check(false, 'have an order id from scenario 1');
  const r2 = await run(a, 'PATCH', `${ORDERS}/${orderId}`, {
    body: { status: 'refunded' },
    browser: jordan,
    plan: { onConsent: () => 'deny' },
  });
  const c2 = r2.acts.flatMap((x) => x.consents)[0];
  const blocked = c2 ? c2.scopes.find((s) => s.scope === 'sales.refund') : null;
  check(r2.acts.length === 1, 'Jordan saw the step-up request', r2.acts);
  check(!c2 || (blocked && !blocked.grantable), 'sales.refund shown as not grantable (data-aauth-grantable="0")', c2);
  check(r2.status === 403 && r2.error === 'denied', 'agent gets 403 denied at poll', brief(r2));
});

await scenario(5, 'Deny -> the agent gets 403 at poll', async () => {
  const a = makeAgent('deny');
  const r = await run(a, 'GET', `${ORDERS}?limit=1`, { plan: { onConsent: () => 'deny' } });
  check(r.status === 403, 'status 403', brief(r));
  check(r.error === 'denied', 'error denied', r.error);
  const last = r.acts[r.acts.length - 1];
  check(last && last.result === 'denied', 'consent page ended in done/denied', last);
});

await scenario(6, '"Always allow" -> next auth token is immediate; revoke -> back to 202', async () => {
  const a = makeAgent('always');
  const r1 = await run(a, 'GET', `${ORDERS}?limit=1`, { plan: { always: true } });
  check(r1.status === 200, 'first call 200 after consent with always=1', brief(r1));
  a.dropAuth();
  const r2 = await run(a, 'GET', `${ORDERS}?limit=1`);
  const at2 = r2.steps.find((s) => s.kind === 'auth_token');
  check(r2.status === 200, 'second call 200', brief(r2));
  check(r2.interactions.length === 0 && at2?.status === 200, 'auth token endpoint answered 200 immediately', { interactions: r2.interactions.length, status: at2?.status });
  const grants = (await api('GET', '/system/aauth/grants')).body?.resource || [];
  const g = grants.find((x) => x.agent_sub === a.sub);
  check(g, 'grant listed in the admin API', grants.map((x) => x.agent_sub));
  if (g) {
    check(String(g.scope).split(' ').includes('sales.read'), 'grant covers sales.read', g.scope);
    const del = await api('DELETE', `/system/aauth/grants/${g.id}`);
    check(del.status === 200, 'revoke via admin API -> 200', del.status);
  }
  a.dropAuth();
  const r3 = await run(a, 'GET', `${ORDERS}?limit=1`, { cancel: true });
  const at3 = r3.steps.find((s) => s.kind === 'auth_token');
  check(at3?.status === 202, 'after revoke the auth token request is 202 again', at3?.status);
  check(r3.cancelled && r3.status >= 200 && r3.status < 300, 'pending request cancelled with DELETE', { cancelled: r3.cancelled, status: r3.status });
});

await scenario(7, 'Blocked agent -> 403 agent_blocked; unblock -> 200', async () => {
  const rows = (await api('GET', '/system/aauth/agents')).body?.resource || [];
  const row = rows.find((x) => x.agent_id === main.sub && x.issuer === AP);
  if (!check(row, 'agent row present', rows.map((x) => `${x.agent_id} ${x.issuer}`))) return;
  check(row.request_count > 0 && row.last_seen_at, 'agent row has activity', row);
  const b = await api('PATCH', `/system/aauth/agents/${row.id}`, { status: 'blocked' });
  check(b.status === 200, 'block -> 200', b.status);
  try {
    const r = await run(main, 'GET', `${ORDERS}?limit=1`);
    check(r.status === 403 && r.body?.error === 'agent_blocked', '403 agent_blocked', brief(r));
    check(!r.headers['signature-error'], 'no Signature-Error on a 403');
  } finally {
    const u = await api('PATCH', `/system/aauth/agents/${row.id}`, { status: 'allowed' });
    check(u.status === 200, 'unblock -> 200', u.status);
  }
  const r2 = await run(main, 'GET', `${ORDERS}?limit=1`);
  check(r2.status === 200 && r2.interactions.length === 0, 'after unblock 200 without interaction', brief(r2));
});

await scenario(8, 'Tampering is rejected with 401 invalid_signature', async () => {
  const token = main.agentToken(DF);
  const jwk = main.agentKey;
  const isSigFail = (r, codes = ['invalid_signature']) => r.status === 401 && codes.includes(r.signatureError?.error);
  const show = (r) => ({ status: r.status, sigerr: r.headers['signature-error'], req: r.headers['aauth-requirement'], body: r.body });

  const control = await rawSend(signRequest(`${ORDERS}?limit=1`, { token, jwk }));
  check(control.status === 401 && control.requirement.requirement === 'person-token' && !control.signatureError, 'control: valid agent-token request -> 401 person-token', show(control));

  const post = signRequest(ORDERS, { method: 'POST', token, jwk, body: { resource: [{ customer_id: 1, total: 1, status: 'new' }] } });
  const digest = await rawSend(post, { body: JSON.stringify({ resource: [{ customer_id: 1, total: 999, status: 'new' }] }) });
  check(isSigFail(digest), 'body changed after signing (Content-Digest mismatch)', show(digest));

  const once = signRequest(ORDERS, { method: 'POST', token, jwk, body: { resource: [] } });
  const first = await rawSend(once);
  check(first.status === 401 && first.requirement.requirement === 'person-token', 'POST first use accepted (401 person-token)', show(first));
  const replay = await rawSend(once);
  check(isSigFail(replay), 'replayed POST signature', show(replay));

  const stale = await rawSend(signRequest(`${ORDERS}?limit=1`, { token, jwk, created: now() - 300 }));
  check(isSigFail(stale), 'created 300 s in the past', show(stale));

  const future = await rawSend(signRequest(`${ORDERS}?limit=1`, { token, jwk, created: now() + 300 }));
  check(isSigFail(future, ['clock_skew', 'invalid_signature']), 'created 300 s in the future (clock_skew)', show(future));

  const q = signRequest(`${ORDERS}?limit=1`, { token, jwk });
  const qChanged = await rawSend(q, { url: `${ORDERS}?limit=2` });
  check(isSigFail(qChanged), 'query changed after signing', show(qChanged));

  const noQuery = await rawSend(signRequest(`${ORDERS}?limit=1`, { token, jwk, query: false }));
  check(noQuery.status === 401 && noQuery.signatureError, 'query present but @query not covered', show(noQuery));

  if (ALT) {
    const altUrl = `${ALT}/api/v2/sales/_table/orders?limit=1`;
    const alt = await rawSend(signRequest(altUrl, { token, jwk }));
    check(isSigFail(alt), `wrong authority (${new URL(ALT).host})`, show(alt));
  } else vlog('DF_ALT_URL unset: wrong-authority check skipped');

  const otherKey = generateJwk();
  const wrongKey = await rawSend(signRequest(`${ORDERS}?limit=1`, { token, jwk: otherKey }));
  check(isSigFail(wrongKey), 'signed with a key other than cnf.jwk', show(wrongKey));
});

await scenario(9, 'Person token from an untrusted Person Server -> 401 invalid_jwt (refused before discovery)', async () => {
  if (!check(keys.test_ps, 'test PS key available')) return;
  const t = now();
  const pt = signJwt({
    typ: 'aa-person+jwt',
    jwk: keys.test_ps,
    payload: { iss: AP, dwk: 'aauth-person.json', aud: DF, sub: randomId(12), cnf: { jwk: publicJwk(main.agentKey) }, jti: randomId(), iat: t, exp: t + 600 },
  });
  const r = await rawSend(signRequest(`${ORDERS}?limit=1`, { token: pt, jwk: main.agentKey }));
  check(r.status === 401 && r.signatureError?.error === 'invalid_jwt', '401 Signature-Error invalid_jwt', { status: r.status, sigerr: r.headers['signature-error'], body: r.body });
  check(r.body?.error !== 'untrusted_person_server', 'does not reveal the trust list as a 403');
});

let unsignedEnabled;
await scenario(10, 'No credentials while enabled: DF error unchanged + discovery hints', async () => {
  const res = await fetch(`${ORDERS}?limit=1`, { headers: { accept: 'application/json' } });
  unsignedEnabled = { status: res.status, text: await res.text(), headers: Object.fromEntries(res.headers) };
  check([400, 401].includes(res.status), 'status is DF\'s usual 400/401', res.status);
  if (res.status === 401) check(res.headers.get('aauth-requirement') === 'requirement=agent-token', 'AAuth-Requirement: requirement=agent-token on 401', res.headers.get('aauth-requirement'));
  else check(!res.headers.get('aauth-requirement'), 'no AAuth-Requirement on DF\'s 400 (agent-token pairs with 401)', res.headers.get('aauth-requirement'));
  check(/aauth-resource\.json/.test(res.headers.get('link') || ''), 'Link to aauth-resource.json', res.headers.get('link'));
  let j;
  try {
    j = JSON.parse(unsignedEnabled.text);
  } catch {}
  check(j?.error && !j.error.error, 'body is DF\'s normal error envelope', unsignedEnabled.text.slice(0, 200));
});

await scenario(11, 'Disabled: signed requests pass through to DF\'s normal error; metadata 404', async () => {
  const off = await api('PATCH', '/system/aauth', { enabled: false });
  check(off.status === 200 && off.body?.enabled === false, 'disable -> 200', off.status);
  try {
    const meta = await fetch(`${DF}/.well-known/aauth-resource.json`);
    check(meta.status === 404, 'resource metadata 404', meta.status);
    const ps = await fetch(`${DF}/.well-known/aauth-person.json`);
    check(ps.status === 404, 'person metadata 404', ps.status);
    const plainRes = await fetch(`${ORDERS}?limit=1`, { headers: { accept: 'application/json' } });
    const plainText = await plainRes.text();
    check(!plainRes.headers.get('aauth-requirement'), 'no AAuth-Requirement when disabled');
    if (unsignedEnabled) check(plainRes.status === unsignedEnabled.status && plainText === unsignedEnabled.text, 'unsigned body/status identical to the enabled case', { off: plainText.slice(0, 150), on: unsignedEnabled.text.slice(0, 150) });
    const signed = await rawSend(signRequest(`${ORDERS}?limit=1`, { token: main.agentToken(DF), jwk: main.agentKey }));
    check(signed.status === plainRes.status && signed.text === plainText, 'signed request gets the same DF error', { status: signed.status, body: signed.text.slice(0, 150) });
    check(!signed.headers['signature-error'] && !signed.headers['aauth-requirement'], 'no AAuth headers on the pass-through');
  } finally {
    const on = await api('PATCH', '/system/aauth', { enabled: true });
    check(on.status === 200 && on.body?.enabled === true, 're-enable -> 200', on.status);
  }
  const back = await fetch(`${DF}/.well-known/aauth-resource.json`);
  const j = await back.json().catch(() => ({}));
  check(back.status === 200 && j.issuer === DF, 'metadata back with issuer', { status: back.status, issuer: j.issuer });
});

await scenario(12, 'Regression: admin session flows still work', async () => {
  const env = await api('GET', '/system/environment');
  check(env.status === 200, 'GET /api/v2/system/environment with the session token -> 200', env.status);
  const st = await api('GET', '/system/aauth');
  check(st.status === 200 && typeof st.body.issuer === 'string', 'GET /api/v2/system/aauth -> 200', st.status);
  const svc = await api('GET', '/system/service?fields=name&limit=100');
  check(svc.status === 200, 'GET /api/v2/system/service -> 200', svc.status);
  const tbl = await api('GET', '/sales/_table/orders?limit=1');
  check(tbl.status === 200, 'GET sales orders with the admin session -> 200', tbl.status);
  const status = await fetch(`${DF}/status`);
  check(status.status === 200, '/status -> 200', status.status);
});

await scenario(13, 'Forged auth tokens: AS-style (dwk aauth-access.json, ps=DF) and ps != iss -> 401, never data', async () => {
  if (!check(keys.test_ps, 'test PS key available')) return;
  const t = now();
  const base = { aud: DF, sub: randomId(12), scope: 'sales.read sales.refund', cnf: { jwk: publicJwk(main.agentKey) }, iat: t, exp: t + 600 };
  const forgedAs = signJwt({ typ: 'aa-auth+jwt', jwk: keys.test_ps, payload: { ...base, iss: AP, dwk: 'aauth-access.json', ps: DF, jti: randomId() } });
  const r1 = await rawSend(signRequest(`${ORDERS}?limit=1`, { token: forgedAs, jwk: main.agentKey }));
  check(r1.status === 401 && r1.signatureError?.error === 'invalid_jwt', 'AS-style token naming ps=DF -> 401 invalid_jwt', { status: r1.status, body: r1.body });
  const psMismatch = signJwt({ typ: 'aa-auth+jwt', jwk: keys.test_ps, payload: { ...base, iss: AP, dwk: 'aauth-person.json', ps: DF, jti: randomId() } });
  const r2 = await rawSend(signRequest(`${ORDERS}?limit=1`, { token: psMismatch, jwk: main.agentKey }));
  check(r2.status === 401 && r2.signatureError?.error === 'invalid_jwt', 'person-dwk token with ps != iss -> 401 invalid_jwt', { status: r2.status, body: r2.body });
  const az = await rawSend(signRequest(`${DF}/aauth/authorize`, { method: 'POST', token: psMismatch, jwk: main.agentKey, body: { scope: 'sales.refund' } }));
  check(az.status === 401 && !az.body?.resource_token, '/aauth/authorize refuses it too (no resource token)', { status: az.status, body: az.body });
});

await scenario(14, 'Blocked agent cannot get a person token at the Person Server', async () => {
  const a = makeAgent('blockps');
  const first = await rawSend(signRequest(ORDERS, { token: a.agentToken(DF), jwk: a.agentKey }));
  check(first.status === 401, 'agent token at the resource -> 401 person-token (agent row created)', first.status);
  const row = (await e2eAgents()).find((x) => x.agent_id === a.sub);
  if (!check(row, 'agent row present')) return;
  await api('PATCH', `/system/aauth/agents/${row.id}`, { status: 'blocked' });
  try {
    const pt = await rawSend(signRequest(`${DF}/aauth/person`, { method: 'POST', token: a.agentToken(DF), jwk: a.agentKey, body: { resource: DF, capabilities: ['interaction'] } }));
    check(pt.status === 403 && pt.body?.error === 'agent_blocked', 'POST /aauth/person -> 403 agent_blocked', { status: pt.status, body: pt.body });
  } finally {
    await api('PATCH', `/system/aauth/agents/${row.id}`, { status: 'allowed' });
  }
  const ok = await rawSend(signRequest(`${DF}/aauth/person`, { method: 'POST', token: a.agentToken(DF), jwk: a.agentKey, body: { resource: DF, capabilities: ['interaction'] } }));
  check(ok.status === 202 && ok.headers.location, 'after unblock -> 202 with Location', { status: ok.status, body: ok.body });
  if (ok.headers.location) {
    const poll = await rawSend(signRequest(ok.headers.location, { token: a.agentToken(DF), jwk: a.agentKey }));
    check(poll.status === 202 && poll.headers.location === ok.headers.location, 'poll 202 repeats Location', { status: poll.status, location: poll.headers.location });
    await rawSend(signRequest(ok.headers.location, { method: 'DELETE', token: a.agentToken(DF), jwk: a.agentKey }));
  }
});

// ---------------------------------------------------------------------------
await restore();
const left = await e2eAgents();
console.log(`cleanup: ${left.length === 0 ? 'no aauth:e2e-* agents left' : `${left.length} aauth:e2e-* agents left`}`);
const failed = results.filter((r) => !r.pass);
console.log(`\n${results.length - failed.length}/${results.length} scenarios passed${failed.length ? `; failed: ${failed.map((f) => f.n).join(', ')}` : ''}`);
process.exit(failed.length ? 1 : 0);
