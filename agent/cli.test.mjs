// Offline tests for the `aauth` CLI, driven as a subprocess against the mock DF (mock-df.mjs).
// The "person" approves by reading the code the CLI prints on stderr.
//
//   node --test agent/cli.test.mjs
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawn } from 'node:child_process';
import { initIdentity } from './config.mjs';
import { startMock } from './mock-df.mjs';

const CLI = new URL('./cli.mjs', import.meta.url).pathname;

function run(args, { env, approve, stdin } = {}) {
  return new Promise((resolve) => {
    const child = spawn(process.execPath, [CLI, ...args], { env, stdio: ['pipe', 'pipe', 'pipe'] });
    let stdout = '';
    let stderr = '';
    const seen = new Set();
    child.stdout.on('data', (d) => (stdout += d));
    child.stderr.on('data', async (d) => {
      stderr += d;
      for (const m of stderr.matchAll(/^\s+code\s+(\S+)$/gm)) {
        if (seen.has(m[1]) || !approve) continue;
        seen.add(m[1]);
        await approve(m[1], seen.size);
      }
    });
    if (stdin !== undefined) child.stdin.end(stdin);
    else child.stdin.end();
    child.on('close', (code) => resolve({ code, stdout, stderr }));
  });
}

test('aauth CLI: request (legacy form too), whoami, scope, logout, deny, errors', async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'aauth-cli-'));
  const file = path.join(dir, 'agent.json');
  const { identity } = initIdentity({ issuer: 'https://agent.example', name: 'CLI Test', id: 'cli', file });
  const mock = await startMock(identity.ap);
  const env = { PATH: process.env.PATH, HOME: dir, NO_COLOR: '1', AAUTH_CONFIG: file };
  const approve = (extra = '') => async (code) => {
    const r = await fetch(`${mock.ORIGIN}/approve?code=${encodeURIComponent(code)}${extra}`);
    assert.equal(r.status, 200);
  };
  const url = `${mock.ORIGIN}/api/data?x=1`;
  try {
    const help = await run(['--help'], { env });
    assert.equal(help.code, 0);
    assert.match(help.stdout, /aauth request <METHOD> <URL>/);

    const r1 = await run(['request', 'GET', url, '--insecure'], { env, approve: approve() });
    assert.equal(r1.code, 0, r1.stderr);
    assert.deepEqual(JSON.parse(r1.stdout), { ok: true, method: 'GET', scope: 'read' });
    assert.match(r1.stderr, /401\s+person token required/);
    assert.match(r1.stderr, /approval needed: sign in/);
    assert.match(r1.stderr, /consent required for read/);
    assert.match(r1.stderr, /auth token\s+read/);
    assert.match(r1.stderr, /200 OK/);
    assert.match(r1.stderr, /as aauth:cli@agent\.example/);

    // cached: the legacy `cli.mjs GET <url>` form, no approval needed
    const r2 = await run(['GET', url, '--insecure', '-q'], { env, approve: () => assert.fail('no approval expected') });
    assert.equal(r2.code, 0, r2.stderr);
    assert.equal(r2.stderr, '');
    assert.equal(JSON.parse(r2.stdout).ok, true);

    const who = await run(['whoami', '--json'], { env });
    assert.equal(who.code, 0, who.stderr);
    const w = JSON.parse(who.stdout);
    assert.equal(w.agent_id, 'aauth:cli@agent.example');
    assert.equal(w.sessions.length, 1);
    assert.equal(w.sessions[0].resource, mock.ORIGIN);
    assert.equal(w.sessions[0].auth_scope, 'read');

    // step-up with an up-front scope and a body from stdin, plus -i
    const r3 = await run(['request', 'PATCH', `${mock.ORIGIN}/api/data`, '-s', 'write', '-d', '@-', '--insecure', '-i'], { env, approve: approve(), stdin: '{"status":"refunded"}' });
    assert.equal(r3.code, 0, r3.stderr);
    assert.match(r3.stdout, /^HTTP 200 OK\n/);
    assert.match(r3.stderr, /resource token for read write/);

    const json = await run(['request', 'GET', url, '--insecure', '--json'], { env });
    assert.equal(json.code, 0, json.stderr);
    const j = JSON.parse(json.stdout);
    assert.equal(j.status, 200);
    assert.ok(j.steps.some((s) => s.kind === 'reuse'));

    const out = await run(['logout', mock.ORIGIN], { env });
    assert.equal(out.code, 0);
    assert.match(out.stderr, /forgot 2 tokens/);
    const none = await run(['reset'], { env });
    assert.match(none.stderr, /no cached tokens/);

    // denied at the person server -> exit 3
    const denied = await run(['request', 'GET', url, '--insecure'], { env, approve: async (code, n) => approve(n === 1 ? '' : '&decision=deny')(code) });
    assert.equal(denied.code, 3, denied.stderr);
    assert.match(denied.stderr, /not approved: denied/);

    // error responses -> exit 1 with the problem on stderr
    const unknown = await run(['request', 'GET', url, '-s', 'nope', '--insecure'], { env });
    assert.equal(unknown.code, 1, unknown.stderr);
    assert.match(unknown.stderr, /400 Bad Request\s+invalid_scope/);

    // usage errors -> exit 2
    for (const args of [['request'], ['request', 'GET', url, '-d', 'not json'], ['frobnicate'], ['request', 'GET', url, '--nope']]) {
      const u = await run(args, { env });
      assert.equal(u.code, 2, `${args.join(' ')}: ${u.stderr}`);
    }

    // decode
    const at = await run(['agent-token', '--ps', 'https://df.example.com'], { env });
    const dec = await run(['decode', at.stdout.trim()], { env });
    assert.equal(JSON.parse(dec.stdout).payload.ps, 'https://df.example.com');
  } finally {
    await mock.close();
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('aauth init + whoami in a fresh home', async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'aauth-init-'));
  const env = { PATH: process.env.PATH, HOME: dir, NO_COLOR: '1', AAUTH_HOME: path.join(dir, 'cfg') };
  try {
    const missing = await run(['whoami'], { env: { ...env, AAUTH_AGENT_ISSUER: 'https://nobody.example' } });
    assert.equal(missing.code, 1);
    assert.match(missing.stderr, /aauth init --issuer/);
    const init = await run(['init', '--issuer', 'https://agents.example.com', '--name', 'Acme Reports'], { env });
    assert.equal(init.code, 0, init.stderr);
    assert.match(init.stdout, /aauth:acme-reports@agents\.example\.com/);
    assert.match(init.stdout, /https:\/\/agents\.example\.com\/\.well-known\/aauth-agent\.json/);
    assert.ok(fs.existsSync(path.join(dir, 'cfg/public/jwks.json')));
    const who = await run(['whoami'], { env });
    assert.equal(who.code, 0, who.stderr);
    assert.match(who.stdout, /agent\s+aauth:acme-reports@agents\.example\.com/);
    const bad = await run(['init', '--issuer', 'http://agents.example.com', '--config', path.join(dir, 'x.json')], { env });
    assert.equal(bad.code, 1);
    assert.match(bad.stderr, /https/);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});
