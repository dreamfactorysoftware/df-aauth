#!/usr/bin/env node
// aauth: call AAuth-protected APIs (such as DreamFactory) as an AI agent.
// Part of @dreamfactory/aauth-agent. Run `aauth --help`.
import fs from 'node:fs';
import os from 'node:os';
import { spawn } from 'node:child_process';
import { claims, decodeJwt, jwkThumbprint, parseRequirement, parseCacheKey, scopesOf, now, assertServerId } from './aauth.mjs';
import { loadIdentity, initIdentity, createAgent, ConfigError, defaultConfigFile } from './config.mjs';
import { startProvider, checkProvider } from './provider.mjs';

const VERSION = JSON.parse(fs.readFileSync(new URL('./package.json', import.meta.url), 'utf8')).version;

const HELP = `aauth ${VERSION}: call AAuth-protected APIs as an AI agent

Usage
  aauth request <METHOD> <URL> [options]   call an API; the person approves when needed
  aauth whoami [--check]                   this agent's identity (--check: is it published?)
  aauth logout [<URL>]                     forget cached tokens for one API, or all of them
  aauth reset                              forget every cached token of this agent
  aauth init --issuer <url> --name <name>  create an agent identity and its provider files
  aauth serve [--port <n>] [--host <h>]    serve the provider files (put TLS in front)
  aauth agent-token [--ps <url>]           print a fresh agent token
  aauth decode <jwt>                       print a token's header and claims

Request options
  -d, --data <json|@file|@->   JSON body (signed with Content-Digest)
  -s, --scope <scopes>         ask for these scopes up front, e.g. "sales.read sales.refund"
  -H, --header "Name: value"   extra request header (repeatable)
  -w, --why <text>             why the agent needs this, shown on the approval screen
  -i, --include                print the response status line and headers
  -v, --verbose                show every protocol step: requests, challenges, tokens
  -q, --quiet                  print only the response body (and any approval prompt)
      --json                   print {status, headers, body, steps} as JSON
      --open                   open the approval page in the default browser
      --fresh                  ignore cached tokens for this call
      --ps <url>               Person Server (default: the API's own)
      --timeout <seconds>      how long to wait for the person (default 600)

Init options
      --issuer <url>           https origin that will serve the provider files
      --name <name>            agent name shown to people on the approval screen
      --id <name>              agent id local part (default: from --name)
      --callback               add {issuer}/callback (served by aauth serve)
      --public <dir>           where to write the provider files (default: next to the identity)

Global options
  -c, --config <file>          identity file (default ${tildify(defaultConfigFile())}, env AAUTH_CONFIG)
      --insecure               allow http:// servers (local testing only)
      --no-color               plain output (also NO_COLOR=1)
  -h, --help, --version

Examples
  aauth init --issuer https://agents.example.com --name "Acme Reports"
  aauth request GET 'https://df.example.com/api/v2/sales/_table/orders?limit=5'
  aauth request PATCH https://df.example.com/api/v2/sales/_table/orders/7 -d '{"status":"refunded"}'
  aauth request GET https://df.example.com/api/v2/sales/_table/customers -s sales.read --why "Weekly report"

Exit status: 0 success (2xx), 1 error response or failure, 2 usage, 3 not approved, 130 interrupted
`;

function tildify(p) {
  const h = os.homedir();
  return h && p.startsWith(`${h}/`) ? `~${p.slice(h.length)}` : p;
}

// ---------------------------------------------------------------------------
// Arguments
// ---------------------------------------------------------------------------
const SPEC = {
  data: { short: 'd', value: true },
  scope: { short: 's', value: true, multi: true },
  header: { short: 'H', value: true, multi: true },
  why: { short: 'w', value: true },
  include: { short: 'i' },
  verbose: { short: 'v' },
  quiet: { short: 'q' },
  json: {},
  open: {},
  fresh: {},
  ps: { value: true },
  timeout: { value: true },
  config: { short: 'c', value: true },
  insecure: {},
  'no-color': {},
  'no-callback': {},
  help: { short: 'h' },
  version: {},
  check: {},
  issuer: { value: true },
  name: { value: true },
  id: { value: true },
  callback: {},
  'callback-url': { value: true },
  public: { value: true },
  port: { value: true },
  host: { value: true },
};
const SHORT = Object.fromEntries(Object.entries(SPEC).filter(([, v]) => v.short).map(([k, v]) => [v.short, k]));

class UsageError extends Error {}

function parseArgs(argv) {
  const o = {};
  const pos = [];
  const set = (k, v) => {
    if (SPEC[k].multi) (o[k] ||= []).push(v);
    else o[k] = v;
  };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === '--') {
      pos.push(...argv.slice(i + 1));
      break;
    }
    if (a.startsWith('--')) {
      const eq = a.indexOf('=');
      const k = eq > 0 ? a.slice(2, eq) : a.slice(2);
      if (!SPEC[k]) throw new UsageError(`unknown option --${k}`);
      if (SPEC[k].value) {
        const v = eq > 0 ? a.slice(eq + 1) : argv[++i];
        if (v === undefined) throw new UsageError(`--${k} needs a value`);
        set(k, v);
      } else {
        if (eq > 0) throw new UsageError(`--${k} takes no value`);
        set(k, true);
      }
    } else if (a.startsWith('-') && a.length > 1 && !/^-\d/.test(a)) {
      const letters = a.slice(1);
      for (let j = 0; j < letters.length; j++) {
        const k = SHORT[letters[j]];
        if (!k) throw new UsageError(`unknown option -${letters[j]}`);
        if (SPEC[k].value) {
          const rest = letters.slice(j + 1);
          const v = rest || argv[++i];
          if (v === undefined) throw new UsageError(`-${letters[j]} needs a value`);
          set(k, v);
          break;
        }
        set(k, true);
      }
    } else pos.push(a);
  }
  return { o, pos };
}

// ---------------------------------------------------------------------------
// Output
// ---------------------------------------------------------------------------
let color = false;
const paint = (code) => (s) => (color ? `\x1b[${code}m${s}\x1b[0m` : String(s));
const dim = paint('2');
const bold = paint('1');
const green = paint('32');
const red = paint('31');
const yellow = paint('33');
const cyan = paint('36');
const err = (s = '') => process.stderr.write(`${s}\n`);
const out = (s = '') => process.stdout.write(`${s}\n`);

function fmtDur(sec) {
  if (sec < 90) return `${Math.max(0, Math.round(sec))} s`;
  if (sec < 5400) return `${Math.round(sec / 60)} min`;
  if (sec < 172_800) return `${Math.round(sec / 3600)} h`;
  return `${Math.round(sec / 86_400)} d`;
}
const statusText = { 200: 'OK', 201: 'Created', 202: 'Accepted', 204: 'No Content', 400: 'Bad Request', 401: 'Unauthorized', 403: 'Forbidden', 404: 'Not Found', 408: 'Request Timeout', 409: 'Conflict', 410: 'Gone', 429: 'Too Many Requests', 500: 'Server Error' };
function statusLabel(s) {
  const t = `${s}${statusText[s] ? ` ${statusText[s]}` : ''}`;
  return s >= 200 && s < 300 ? green(t) : s === 401 || s === 202 ? yellow(t) : red(t);
}
const short = (u) => {
  try {
    const x = new URL(u);
    return `${x.host}${x.pathname}${x.search}`;
  } catch {
    return String(u);
  }
};
const clip = (s, n = 96) => (String(s).length > n ? `${String(s).slice(0, n - 1)}…` : String(s));
function tokenSummary(jwt) {
  try {
    const { header, payload: c } = decodeJwt(jwt);
    const parts = [header.typ, `iss ${c.iss}`];
    if (c.sub) parts.push(`sub ${clip(c.sub, 48)}`);
    if (c.aud) parts.push(`aud ${c.aud}`);
    if (c.scope) parts.push(`scope ${c.scope}`);
    if (c.exp) parts.push(`exp ${fmtDur(c.exp - now())}`);
    return parts.join('  ');
  } catch {
    return clip(jwt, 40);
  }
}
/** A DreamFactory or AAuth problem body as "code: message". */
function problem(body) {
  if (!body || typeof body !== 'object') return typeof body === 'string' && body ? clip(body.replace(/\s+/g, ' '), 160) : '';
  if (typeof body.error === 'string') return `${body.error}${body.detail ? `: ${body.detail}` : ''}`;
  if (body.error && typeof body.error === 'object') return `${body.error.code ?? ''}${body.error.message ? ` ${body.error.message}` : ''}`.trim();
  return '';
}

/** Waiting indicator: a ticking line on a TTY, one line otherwise. */
function waiter() {
  let timer = null;
  let started = 0;
  const tty = process.stderr.isTTY;
  return {
    start(label) {
      this.stop();
      started = Date.now();
      if (!tty) return err(dim(`    ${label}…`));
      const frames = ['⠋', '⠙', '⠹', '⠸', '⠼', '⠴', '⠦', '⠧', '⠇', '⠏'];
      let i = 0;
      const draw = () => process.stderr.write(`\r    ${cyan(frames[i++ % frames.length])} ${dim(`${label}… ${Math.floor((Date.now() - started) / 1000)}s`)}\x1b[K`);
      draw();
      timer = setInterval(draw, 120);
    },
    stop() {
      if (timer) {
        clearInterval(timer);
        timer = null;
        process.stderr.write('\r\x1b[K');
      }
    },
  };
}

function openBrowser(url) {
  const [cmd, args] = process.platform === 'darwin' ? ['open', [url]] : process.platform === 'win32' ? ['cmd', ['/c', 'start', '', url]] : ['xdg-open', [url]];
  try {
    spawn(cmd, args, { stdio: 'ignore', detached: true }).on('error', () => {}).unref();
  } catch {}
}

// ---------------------------------------------------------------------------
// Commands
// ---------------------------------------------------------------------------
function identityOrExit(o) {
  try {
    return loadIdentity({ file: o.config });
  } catch (e) {
    if (e instanceof ConfigError) {
      err(red(e.message));
      process.exit(1);
    }
    throw e;
  }
}

function readBody(o, positional) {
  let raw = o.data ?? positional;
  if (raw === undefined) return undefined;
  if (raw === '@-') raw = fs.readFileSync(0, 'utf8');
  else if (raw.startsWith('@')) raw = fs.readFileSync(raw.slice(1), 'utf8');
  try {
    return JSON.parse(raw);
  } catch {
    throw new UsageError('the request body (--data) must be JSON');
  }
}

function parseHeaders(list = []) {
  const h = {};
  for (const line of list) {
    const i = line.indexOf(':');
    if (i <= 0) throw new UsageError(`bad header "${line}" (use "Name: value")`);
    const k = line.slice(0, i).trim().toLowerCase();
    if (['signature', 'signature-input', 'signature-key', 'content-digest'].includes(k)) throw new UsageError(`${k} is set by the agent`);
    h[k] = line.slice(i + 1).trim();
  }
  return h;
}

const NOT_APPROVED = new Set(['denied', 'abandoned', 'expired', 'invalid_code', 'timeout', 'access_denied', 'user_unreachable']);

async function cmdRequest(o, pos) {
  let [method, url, positionalBody] = pos;
  if (method && /^https?:\/\//i.test(method)) [method, url, positionalBody] = ['GET', method, url];
  if (!method || !url) throw new UsageError('usage: aauth request <METHOD> <URL> [--data <json>]');
  method = method.toUpperCase();
  if (!/^[A-Z]+$/.test(method)) throw new UsageError(`not an HTTP method: ${method}`);
  try {
    new URL(url);
  } catch {
    throw new UsageError(`not a URL: ${url}`);
  }
  const body = readBody(o, positionalBody);
  const headers = parseHeaders(o.header);
  const scope = o.scope ? scopesOf(o.scope).join(' ') : undefined;
  const timeout = o.timeout !== undefined ? Number(o.timeout) : 600;
  if (!Number.isFinite(timeout) || timeout <= 0) throw new UsageError('--timeout must be a number of seconds');

  const id = identityOrExit(o);
  const agent = createAgent(id, { insecure: !!o.insecure, ...(o['no-callback'] ? { callback: false } : {}) });
  const narrate = !o.quiet && !o.json;
  const verbose = !!o.verbose;
  const wait = waiter();
  const t0 = Date.now();
  let lastScope = scope;

  if (narrate) {
    err(`${bold(method)} ${short(url)}`);
    err(dim(`  as ${agent.sub}`));
  }

  const onStep = (s) => {
    wait.stop();
    const rq = s.request;
    if (verbose && s.kind === 'discover') {
      const b = s.response?.body || {};
      err(dim(`  · ${s.title}: ${b.name ? `${b.name} ` : ''}${b.issuer || ''}`));
      return;
    }
    if (verbose && rq) {
      err(dim(`  · ${rq.method} ${short(rq.url)}  signed with ${tokenSummary(/jwt="([^"]+)"/.exec(rq.headers['signature-key'] || '')?.[1] || '').split('  ')[0]}`));
      err(dim(`      signature-input: ${clip(rq.headers['signature-input'] || '', 110)}`));
      const h = s.response?.headers || {};
      for (const k of ['aauth-requirement', 'signature-error', 'location', 'retry-after', 'aauth-scope']) if (h[k]) err(dim(`      ${k}: ${clip(h[k], 110)}`));
      if (s.status) err(dim(`      ← ${s.status}`));
    }
    if (!narrate) return;
    const req = parseRequirement(s.response?.headers?.['aauth-requirement']);
    if ((s.kind === 'call' || s.kind === 'reuse') && s.status === 401 && req.requirement === 'person-token') {
      err(`  ${yellow('401')}  person token required`);
    } else if ((s.kind === 'call' || s.kind === 'reuse') && (s.status === 401 || s.status === 202) && req.requirement === 'auth-token') {
      let sc = '';
      try {
        sc = claims(req['resource-token']).scope || '';
      } catch {}
      lastScope = sc || lastScope;
      err(`  ${yellow(String(s.status))}  ${s.kind === 'reuse' ? 'more access needed' : 'consent required'}${sc ? ` for ${bold(sc)}` : ''}`);
      if (verbose && req['resource-token']) err(dim(`      resource token  ${tokenSummary(req['resource-token'])}`));
    } else if (s.kind === 'authorize') {
      if (s.status === 200 && s.response?.body?.resource_token) {
        lastScope = claims(s.response.body.resource_token).scope || lastScope;
        err(`  ${green('✓')} resource token for ${bold(lastScope)}`);
        if (verbose) err(dim(`      ${tokenSummary(s.response.body.resource_token)}`));
      } else if (!s.status) err(dim(`  · ${s.title}`));
    } else if ((s.kind === 'person_token' || s.kind === 'auth_token' || s.kind === 'poll') && s.status === 200) {
      const b = s.response?.body || {};
      if (b.person_token) {
        err(`  ${green('✓')} person token${s.kind === 'person_token' ? dim(' (no approval needed)') : ''}`);
        if (verbose) err(dim(`      ${tokenSummary(b.person_token)}`));
      } else if (b.auth_token) {
        const c = claims(b.auth_token);
        err(`  ${green('✓')} auth token  ${bold(c.scope || '')}  ${dim(`expires in ${fmtDur(c.exp - now())}${s.kind === 'auth_token' ? ', standing grant' : ''}`)}`);
        if (verbose) err(dim(`      ${tokenSummary(b.auth_token)}`));
      }
    }
  };

  const onInteraction = (i) => {
    wait.stop();
    const what = i.purpose === 'person' ? 'sign in to identify the person' : `allow ${lastScope || 'access'}`;
    if (!i.userUrl) {
      err(`  ${yellow('…')} waiting for approval${i.requirement ? ` (${i.requirement})` : ''}`);
    } else {
      const plainUrl = `${i.url}?code=${encodeURIComponent(i.code)}`;
      err(`  ${yellow('!')} approval needed: ${what}`);
      err(`      open  ${cyan(plainUrl)}`);
      err(`      code  ${bold(i.code)}`);
      if (o.open) openBrowser(i.userUrl);
    }
    wait.start(i.purpose === 'person' ? 'waiting for the person' : 'waiting for consent');
  };

  const ac = new AbortController();
  let interrupted = false;
  process.on('SIGINT', () => {
    if (interrupted) process.exit(130);
    interrupted = true;
    wait.stop();
    err(dim('  interrupted: withdrawing the pending request (Ctrl-C again to quit now)'));
    ac.abort();
  });

  let result;
  try {
    result = await agent.request(method, url, { body, headers, scope, ps: o.ps || id.ps, why: o.why, fresh: !!o.fresh, pollTimeoutMs: timeout * 1000, onStep, onInteraction, signal: ac.signal });
  } finally {
    wait.stop();
  }
  const secs = ((Date.now() - t0) / 1000).toFixed(1);

  if (o.json) {
    out(JSON.stringify({ status: result.status, headers: result.headers, body: result.body, steps: result.steps, interactions: result.interactions, ...(result.error ? { error: result.error, detail: result.detail } : {}), ...(result.cancelled ? { cancelled: true } : {}) }, null, 2));
  }

  if (result.cancelled) {
    if (narrate || o.quiet) err(`  ${red('✗')} cancelled; the pending request was withdrawn`);
    return interrupted ? 130 : 3;
  }
  if (result.failed && NOT_APPROVED.has(result.error)) {
    if (!o.json) err(`  ${red('✗')} not approved: ${result.error}${result.detail ? dim(` (${result.detail})`) : ''}`);
    return 3;
  }
  if (result.failed && result.body === undefined) {
    if (!o.json) err(`  ${red('✗')} ${result.error}${result.detail ? `: ${result.detail}` : ''}${result.status ? dim(` [HTTP ${result.status}]`) : ''}`);
    return 1;
  }

  const ok = result.status >= 200 && result.status < 300 && !result.failed && !result.error;
  if (narrate) {
    const used = result.headers?.['aauth-scope'];
    const rows = Array.isArray(result.body?.resource) ? `${result.body.resource.length} record${result.body.resource.length === 1 ? '' : 's'}` : '';
    const info = [used && `scope ${used}`, rows, `${secs} s`].filter(Boolean).join(dim('  ·  '));
    const why = ok ? '' : problem(result.body) || result.error || '';
    err(`  ${ok ? green('✓') : red('✗')} ${statusLabel(result.status)}${why ? `  ${why}` : ''}  ${dim(info)}`);
  } else if (!ok && !o.json) {
    err(`${red('✗')} ${statusLabel(result.status)}  ${problem(result.body) || result.error || ''}`);
  }
  if (!o.json) {
    if (narrate) err('');
    if (o.include) {
      out(`HTTP ${result.status}${statusText[result.status] ? ` ${statusText[result.status]}` : ''}`);
      for (const [k, v] of Object.entries(result.headers || {})) out(`${k}: ${v}`);
      out('');
    }
    if (result.body !== undefined && result.body !== null && result.body !== '') {
      out(typeof result.body === 'string' ? result.body : JSON.stringify(result.body, null, 2));
    }
  }
  return ok ? 0 : 1;
}

function sessionsOf(id) {
  const agent = createAgent(id);
  const all = agent.cache.all?.() || {};
  const prefix = `${agent.issuer}|${agent.sub}|${agent.jkt}|`;
  return { agent, entries: Object.entries(all).filter(([k]) => k.startsWith(prefix)) };
}

async function cmdWhoami(o) {
  const id = identityOrExit(o);
  const { agent, entries } = sessionsOf(id);
  const sessions = entries.map(([k, v]) => {
    const { resource, ps } = parseCacheKey(k);
    const left = (t) => {
      try {
        return claims(t).exp - now();
      } catch {
        return -1;
      }
    };
    return { resource, ps, person_expires_in: v.person ? left(v.person) : null, auth_scope: v.auth ? scopesOf(v.auth).join(' ') : null, auth_expires_in: v.auth ? left(v.auth) : null };
  });
  const info = {
    agent_id: agent.sub,
    name: id.name || null,
    agent_provider: agent.issuer,
    metadata: `${agent.issuer}/.well-known/aauth-agent.json`,
    signing_key: { kid: id.ap.kid, alg: id.ap.alg },
    request_key: { alg: id.agent.alg, thumbprint: agent.jkt },
    identity: id.file || id.source,
    token_cache: id.tokensFile,
    sessions,
  };
  let check;
  if (o.check) check = await checkProvider({ issuer: agent.issuer, apKey: id.ap, sub: agent.sub });
  if (o.json) {
    out(JSON.stringify(check ? { ...info, check } : info, null, 2));
    return check && !check.ok ? 1 : 0;
  }
  const row = (k, v) => out(`  ${dim(k.padEnd(12))} ${v}`);
  row('agent', bold(info.agent_id));
  if (info.name) row('name', info.name);
  row('provider', info.agent_provider);
  row('signing key', `${info.signing_key.kid} ${dim(`(${info.signing_key.alg}, published in ${agent.issuer}/jwks.json)`)}`);
  row('request key', `${info.request_key.thumbprint.slice(0, 16)}… ${dim(`(${info.request_key.alg} thumbprint)`)}`);
  row('identity', tildify(String(info.identity)));
  row('tokens', tildify(String(info.token_cache)));
  if (sessions.length) {
    out('');
    out(`  ${dim('signed in at')}`);
    for (const s of sessions) {
      const p = s.person_expires_in > 0 ? `person ${fmtDur(s.person_expires_in)}` : dim('person expired');
      const a = s.auth_scope ? (s.auth_expires_in > 0 ? `auth ${bold(s.auth_scope)} ${fmtDur(s.auth_expires_in)}` : dim(`auth ${s.auth_scope} expired`)) : dim('no auth token');
      out(`    ${s.resource}  ${p}  ${dim('·')}  ${a}${s.ps !== s.resource ? dim(`  (person server ${s.ps})`) : ''}`);
    }
  }
  if (check) {
    out('');
    for (const c of check.checks) out(`  ${c.ok ? green('✓') : red('✗')} ${c.label}${!c.ok && c.detail ? dim(`  ${c.detail}`) : ''}`);
    return check.ok ? 0 : 1;
  }
  return 0;
}

function cmdLogout(o, pos, all) {
  const id = identityOrExit(o);
  const { agent, entries } = sessionsOf(id);
  let origin = null;
  if (!all && pos[0]) {
    try {
      origin = new URL(pos[0]).origin;
    } catch {
      throw new UsageError(`not a URL: ${pos[0]}`);
    }
  }
  const drop = entries.filter(([k]) => !origin || parseCacheKey(k).resource === origin);
  for (const [k] of drop) agent.cache.delete(k);
  const n = drop.reduce((m, [, v]) => m + (v.person ? 1 : 0) + (v.auth ? 1 : 0), 0);
  const where = origin || (drop.length === 1 ? parseCacheKey(drop[0][0]).resource : `${drop.length} API${drop.length === 1 ? '' : 's'}`);
  if (o.json) out(JSON.stringify({ removed: drop.map(([k]) => parseCacheKey(k).resource), tokens: n }));
  else if (!drop.length) err(dim(origin ? `no cached tokens for ${origin}` : 'no cached tokens'));
  else err(`${green('✓')} forgot ${n} token${n === 1 ? '' : 's'} for ${where}`);
  return 0;
}

function cmdInit(o) {
  if (o['callback-url']) {
    try {
      new URL(o['callback-url']);
    } catch {
      throw new UsageError('--callback-url must be a URL');
    }
  }
  let r;
  try {
    r = initIdentity({ issuer: o.issuer, name: o.name, id: o.id, file: o.config, publicDir: o.public, callback: o['callback-url'] || !!o.callback, insecure: !!o.insecure });
  } catch (e) {
    if (e instanceof ConfigError) {
      err(red(e.message));
      return 1;
    }
    throw e;
  }
  const { identity } = r;
  if (o.json) {
    out(JSON.stringify({ created: r.created, identity: r.file, agent_id: identity.sub, issuer: identity.issuer, name: identity.name, published: r.published }, null, 2));
    return 0;
  }
  out(`${green('✓')} ${r.created ? 'created' : 'using'} ${tildify(r.file)}`);
  out(`  ${dim('agent'.padEnd(9))}${bold(identity.sub)}`);
  out(`  ${dim('name'.padEnd(9))}${identity.name}`);
  out(`  ${dim('provider'.padEnd(9))}${identity.issuer}`);
  out('');
  out(`Publish these files over https (any static host), or run ${bold('aauth serve')} behind TLS:`);
  const w = Math.max(...Object.keys(r.published).map((u) => u.length));
  for (const [u, p] of Object.entries(r.published)) out(`  ${u.padEnd(w)}  ${dim('<-')}  ${tildify(p)}`);
  out('');
  out(`Then: ${bold('aauth whoami --check')}`);
  return 0;
}

async function cmdServe(o) {
  const id = identityOrExit(o);
  const port = Number(o.port || process.env.PORT || 8799);
  const host = o.host || process.env.HOST || '127.0.0.1';
  const server = await startProvider({ issuer: id.issuer, name: id.name || 'AAuth agent', apKey: id.ap, callback: id.callback || true, port, host });
  err(`${id.name || 'AAuth agent'} agent provider ${bold(id.issuer)} on http://${host}:${port}`);
  err(dim(`  ${id.issuer}/.well-known/aauth-agent.json and /jwks.json must reach this port over https`));
  for (const sig of ['SIGINT', 'SIGTERM']) process.on(sig, () => server.close(() => process.exit(0)));
  return new Promise(() => {});
}

function cmdAgentToken(o) {
  const id = identityOrExit(o);
  if (o.ps) assertServerId(o.ps.replace(/\/+$/, ''), { insecure: !!o.insecure });
  out(createAgent(id).agentToken(o.ps ? o.ps.replace(/\/+$/, '') : undefined));
  return 0;
}

function cmdDecode(pos) {
  const t = pos[0] === '-' || !pos[0] ? fs.readFileSync(0, 'utf8').trim() : pos[0];
  const { header, payload } = decodeJwt(t);
  out(JSON.stringify({ header, payload }, null, 2));
  if (payload.exp) err(dim(payload.exp > now() ? `expires in ${fmtDur(payload.exp - now())}` : `expired ${fmtDur(now() - payload.exp)} ago`));
  if (payload.cnf?.jwk) err(dim(`bound to key ${jwkThumbprint(payload.cnf.jwk)}`));
  return 0;
}

// ---------------------------------------------------------------------------
const COMMANDS = new Set(['request', 'whoami', 'logout', 'reset', 'init', 'serve', 'agent-token', 'decode', 'help']);

async function main(argv) {
  const { o, pos } = parseArgs(argv);
  color = !o['no-color'] && !process.env.NO_COLOR && (process.env.FORCE_COLOR ? process.env.FORCE_COLOR !== '0' : !!process.stderr.isTTY);
  if (o.version) {
    out(VERSION);
    return 0;
  }
  let cmd = pos[0];
  let rest = pos.slice(1);
  if (o.help || !cmd || cmd === 'help') {
    out(HELP);
    return 0;
  }
  // `aauth GET <url>` and `aauth <url>` are short for `aauth request ...`
  if (!COMMANDS.has(cmd)) {
    if (/^[A-Za-z]+$/.test(cmd) && pos[1] && /^https?:\/\//i.test(pos[1])) [cmd, rest] = ['request', pos];
    else if (/^https?:\/\//i.test(cmd)) [cmd, rest] = ['request', pos];
    else throw new UsageError(`unknown command ${cmd}`);
  }
  switch (cmd) {
    case 'request':
      return cmdRequest(o, rest);
    case 'whoami':
      return cmdWhoami(o);
    case 'logout':
      return cmdLogout(o, rest, false);
    case 'reset':
      return cmdLogout(o, rest, true);
    case 'init':
      return cmdInit(o);
    case 'serve':
      return cmdServe(o);
    case 'agent-token':
      return cmdAgentToken(o);
    case 'decode':
      return cmdDecode(rest);
  }
  return 0;
}

main(process.argv.slice(2)).then(
  (code) => process.exit(code ?? 0),
  (e) => {
    if (e instanceof UsageError) {
      err(`aauth: ${e.message}`);
      err(dim('run aauth --help for usage'));
      process.exit(2);
    }
    err(`${red('error')} ${e.error ? `${e.error}: ${e.detail || ''}` : e.message}`);
    if (process.env.AAUTH_DEBUG) err(e.stack);
    process.exit(1);
  },
);
