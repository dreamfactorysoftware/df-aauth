// @dreamfactory/aauth-agent/config: where an agent's identity lives, and how to create one.
//
// An identity file (agent.json, written by `aauth init`, mode 600) holds:
//   { version, issuer, agent_id, name, callback_endpoint?, ap: <private JWK>, agent: <private JWK>, created_at }
//   issuer     the Agent Provider origin; publishes /.well-known/aauth-agent.json and /jwks.json
//   agent_id   aauth:<name>@<issuer host> (the agent token `sub`; DreamFactory lists agents by it)
//   ap         signs agent tokens; its public half is what /jwks.json publishes
//   agent      signs every HTTP request; travels as cnf.jwk inside each token
// The Python client (clients/python) reads the same file.
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { execFileSync } from 'node:child_process';
import { Agent, fileCache, generateJwk, sha256, assertServerId, assertAgentId, defaultAgentId, DEFAULT_ISSUER, DEFAULT_CONTAINER, REFERENCE } from './aauth.mjs';
import { providerDocuments } from './provider.mjs';

const HERE = path.dirname(new URL(import.meta.url).pathname);

export class ConfigError extends Error {}

export function configHome(env = process.env) {
  return env.AAUTH_HOME || path.join(env.XDG_CONFIG_HOME || path.join(os.homedir(), '.config'), 'aauth');
}
export const defaultConfigFile = (env = process.env) => path.join(configHome(env), 'agent.json');

export const slug = (s) =>
  String(s || '')
    .toLowerCase()
    .replace(/[^a-z0-9._-]+/g, '-')
    .replace(/^-+|-+$/g, '')
    .slice(0, 64);

function writable(dir) {
  try {
    fs.accessSync(dir, fs.constants.W_OK);
    return true;
  } catch {
    return false;
  }
}

function readJson(file) {
  try {
    return JSON.parse(fs.readFileSync(file, 'utf8'));
  } catch (e) {
    if (e.code === 'ENOENT') throw new ConfigError(`${file} does not exist`);
    throw new ConfigError(`${file}: ${e.message}`);
  }
}

/** The pre-config token file location of the reference CLI (kept so existing caches keep working). */
function legacyTokensFile(env) {
  if (env.AAUTH_TOKENS) return env.AAUTH_TOKENS;
  return writable(HERE) ? path.join(HERE, '.tokens.json') : path.join(os.tmpdir(), 'aauth-tokens.json');
}

function tokensFileFor(file, env) {
  if (env.AAUTH_TOKENS) return env.AAUTH_TOKENS;
  const dir = path.dirname(file);
  return writable(dir) ? path.join(dir, 'tokens.json') : path.join(os.tmpdir(), `aauth-tokens-${sha256(file).toString('hex').slice(0, 12)}.json`);
}

function finish(id, env) {
  const issuer = String(env.AAUTH_AGENT_ISSUER || id.issuer || DEFAULT_ISSUER || '').replace(/\/+$/, '');
  if (!issuer) throw new ConfigError(`${id.file || id.source}: no agent provider issuer. Set AAUTH_AGENT_ISSUER, or create an identity with: aauth init --issuer https://<your agent provider host>`);
  const reference = Boolean(DEFAULT_ISSUER) && issuer === DEFAULT_ISSUER;
  const out = {
    ...id,
    issuer,
    sub: env.AAUTH_AGENT_ID || id.sub || defaultAgentId(issuer),
    name: env.AAUTH_AGENT_NAME || id.name || (reference ? REFERENCE.name || 'Acme Reports' : undefined),
    ps: env.AAUTH_PS || id.ps,
  };
  if (!out.ap?.d || !out.agent?.d) throw new ConfigError(`${out.file || out.source}: needs the private keys "ap" and "agent"`);
  return out;
}

function fromIdentityFile(file, env, source) {
  const j = readJson(file);
  return finish(
    {
      source,
      file,
      issuer: j.issuer,
      sub: j.agent_id || j.sub,
      name: j.name,
      callback: j.callback_endpoint || (j.callback === true ? true : false),
      ap: j.ap,
      agent: j.agent,
      tokensFile: tokensFileFor(file, env),
    },
    env,
  );
}

function fromKeysFile(file, env, source) {
  const j = readJson(file);
  // a keys file written by `aauth init` is an identity file too
  if (j.issuer || j.agent_id) return fromIdentityFile(file, env, source);
  return finish({ source, file, ap: j.ap, agent: j.agent, test_ps: j.test_ps, callback: true, tokensFile: legacyTokensFile(env) }, env);
}

/**
 * Find this agent's identity. Order:
 *   1. options.file or $AAUTH_CONFIG   an identity file (`aauth init`)
 *   2. $AAUTH_KEYS                     a keys file { ap, agent } (issuer from $AAUTH_AGENT_ISSUER)
 *   3. $AAUTH_HOME/agent.json          default ~/.config/aauth/agent.json
 *   4. agent/.keys.json                next to this package (reference deployment)
 *   5. the reference deployment's container, read with `sudo -n docker exec` (never printed);
 *      only in a development checkout that has agent/reference.json (never in an installed copy)
 * reference: false skips 4 and 5 (they exist for the df-aauth demo host only).
 * Environment overrides: AAUTH_AGENT_ISSUER, AAUTH_AGENT_ID, AAUTH_AGENT_NAME, AAUTH_PS, AAUTH_TOKENS.
 * Returns { issuer, sub, name, ap, agent, callback, ps, file, source, tokensFile }.
 */
export function loadIdentity({ file, env = process.env, reference = true } = {}) {
  const explicit = file || env.AAUTH_CONFIG;
  if (explicit) return fromIdentityFile(path.resolve(explicit), env, 'config');
  if (env.AAUTH_KEYS) return fromKeysFile(path.resolve(env.AAUTH_KEYS), env, 'keys');
  const home = defaultConfigFile(env);
  if (fs.existsSync(home)) return fromIdentityFile(home, env, 'config');
  const legacy = path.join(HERE, '.keys.json');
  if (reference && fs.existsSync(legacy)) return fromKeysFile(legacy, env, 'keys');
  if (reference && DEFAULT_ISSUER && DEFAULT_CONTAINER && (env.AAUTH_AGENT_ISSUER || DEFAULT_ISSUER) === DEFAULT_ISSUER) {
    const container = env.AAUTH_CONTAINER || DEFAULT_CONTAINER;
    let raw;
    try {
      raw = execFileSync('sudo', ['-n', 'docker', 'exec', container, 'cat', '/data/keys.json'], { stdio: ['ignore', 'pipe', 'ignore'], timeout: 10_000 });
    } catch {}
    if (raw) {
      const j = JSON.parse(raw.toString('utf8'));
      return finish({ source: `container ${container}`, ap: j.ap, agent: j.agent, test_ps: j.test_ps, callback: true, tokensFile: legacyTokensFile(env) }, env);
    }
  }
  throw new ConfigError(`No agent identity found (looked at ${home}). Create one with: aauth init --issuer https://<your agent provider host> --name "<Agent name>"`);
}

/**
 * Create an identity (or reuse the existing one at `file`) and (re)write the two public Agent
 * Provider documents under `publicDir` (default: <config dir>/public) for static hosting.
 *   issuer    https origin you will serve the documents from (no path, no port)
 *   id        the agent id's local part (default: slug of the name, else "agent")
 *   callback  true (= {issuer}/callback, served by `aauth serve`), a URL, or false (default)
 * Returns { identity, file, created, publicDir, documents, published: { url: localPath } }.
 */
export function initIdentity({ issuer, name, id, file, publicDir, callback = false, insecure = false, env = process.env }) {
  const target = path.resolve(file || env.AAUTH_CONFIG || defaultConfigFile(env));
  let created = false;
  let j;
  if (fs.existsSync(target)) {
    j = readJson(target);
    if (issuer && j.issuer && j.issuer !== String(issuer).replace(/\/+$/, '')) {
      throw new ConfigError(`${target} already holds the identity for ${j.issuer}. Use --config <file> for another agent.`);
    }
  } else {
    if (!issuer) throw new ConfigError('--issuer is required: the https origin that will serve /.well-known/aauth-agent.json');
    const iss = String(issuer).replace(/\/+$/, '');
    try {
      assertServerId(iss, { insecure });
    } catch (e) {
      throw new ConfigError(`${e.detail || e.message}. The issuer is a bare origin, e.g. https://agents.example.com`);
    }
    const local = id || slug(name) || 'agent';
    const sub = `aauth:${local}@${new URL(iss).host}`;
    try {
      assertAgentId(sub, iss);
    } catch (e) {
      throw new ConfigError(e.message);
    }
    const cb = callback === true ? `${iss}/callback` : callback || undefined;
    j = { version: 1, issuer: iss, agent_id: sub, name: name || local, ...(cb ? { callback_endpoint: cb } : {}), ap: generateJwk(), agent: generateJwk(), created_at: new Date().toISOString() };
    fs.mkdirSync(path.dirname(target), { recursive: true, mode: 0o700 });
    fs.writeFileSync(target, `${JSON.stringify(j, null, 2)}\n`, { mode: 0o600, flag: 'wx' });
    created = true;
  }
  const identity = fromIdentityFile(target, {}, 'config');
  const docs = providerDocuments({ issuer: identity.issuer, name: identity.name, apKey: identity.ap, callback: identity.callback });
  const outDir = path.resolve(publicDir || path.join(path.dirname(target), 'public'));
  const published = {};
  for (const [p, doc] of Object.entries(docs)) {
    const local = path.join(outDir, p);
    fs.mkdirSync(path.dirname(local), { recursive: true });
    fs.writeFileSync(local, `${JSON.stringify(doc, null, 2)}\n`);
    published[`${identity.issuer}${p}`] = local;
  }
  return { identity, file: target, created, publicDir: outDir, documents: docs, published };
}

/** An Agent for an identity, with the identity's token cache. Extra options go to new Agent(). */
export function createAgent(identity, options = {}) {
  return new Agent({
    issuer: identity.issuer,
    apKey: identity.ap,
    agentKey: identity.agent,
    sub: identity.sub,
    callback: identity.callback,
    cache: fileCache(identity.tokensFile),
    ...options,
  });
}
