// @dreamfactory/aauth-agent: the AAuth agent library (import from "@dreamfactory/aauth-agent").
//
// Implements the agent side of draft-hardt-oauth-aauth-protocol-11 and
// draft-hardt-httpbis-signature-key-09: Ed25519/ES256 JWTs, RFC 9421 HTTP message
// signatures with the `jwt` Signature-Key scheme, issuer discovery, and the full
// three-party flow (agent token -> person token -> resource token -> auth token),
// including step-up, up-front scopes (authorization_endpoint) and deferred (202) responses.
// Node >= 20 built-ins only. See README.md.
//
// Derived from the AAuth reference demo's shared/aauth.mjs and agent/netlify/lib/agent.mjs
// (https://github.com/wjgilmore/aauth-demo), which carries this license:
//
//   MIT License
//
//   Copyright (c) 2026 Jason Gilmore
//
//   Permission is hereby granted, free of charge, to any person obtaining a copy
//   of this software and associated documentation files (the "Software"), to deal
//   in the Software without restriction, including without limitation the rights
//   to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
//   copies of the Software, and to permit persons to whom the Software is
//   furnished to do so, subject to the following conditions:
//
//   The above copyright notice and this permission notice shall be included in all
//   copies or substantial portions of the Software.
//
//   THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
//   IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
//   FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
//   AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
//   LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
//   OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
//   SOFTWARE.
//
// Changes from the demo: strict-but-spec-faithful parsing (RFC 8941 structured fields),
// `@query` coverage, ES256 verification, full resource/auth token checks (§6.7.3, §9.4.4),
// step-up, deferred-response handling (Retry-After, 403/408/410/429), token caching,
// https-only server identifiers (with an explicit insecure switch for local testing).

import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { execFileSync } from 'node:child_process';

// ---------------------------------------------------------------------------
// Encoding
// ---------------------------------------------------------------------------

export const b64url = (buf) => Buffer.from(buf).toString('base64url');
export const fromB64url = (s) => Buffer.from(String(s), 'base64url');
export const sha256 = (data) => crypto.createHash('sha256').update(data).digest();
export const randomId = (bytes = 16) => b64url(crypto.randomBytes(bytes));
let clock = () => Math.floor(Date.now() / 1000);
export const now = () => clock();
/** Test hook: fix the clock (pass null to restore). */
export function setClock(fn) {
  clock = fn || (() => Math.floor(Date.now() / 1000));
}

export class AAuthError extends Error {
  constructor(status, error, detail, extra = {}) {
    super(detail ? `${error}: ${detail}` : error);
    this.status = status;
    this.error = error;
    this.detail = detail;
    Object.assign(this, extra);
  }
}
const sigErr = (code, detail) => new AAuthError(401, code, detail);

// ---------------------------------------------------------------------------
// Keys
// ---------------------------------------------------------------------------

export function jwkThumbprint(jwk) {
  const members =
    jwk.kty === 'EC' ? { crv: jwk.crv, kty: jwk.kty, x: jwk.x, y: jwk.y } : { crv: jwk.crv, kty: jwk.kty, x: jwk.x };
  return b64url(sha256(JSON.stringify(members)));
}

export function generateJwk() {
  const { privateKey } = crypto.generateKeyPairSync('ed25519');
  const j = privateKey.export({ format: 'jwk' });
  return { kty: 'OKP', crv: 'Ed25519', x: j.x, d: j.d, alg: 'Ed25519', kid: jwkThumbprint(j).slice(0, 16) };
}

export function publicJwk(jwk) {
  const out = { kty: jwk.kty, crv: jwk.crv, x: jwk.x };
  if (jwk.y) out.y = jwk.y;
  out.alg = jwk.alg;
  if (jwk.kid) out.kid = jwk.kid;
  return out;
}

function algOf(jwk) {
  if (!jwk || typeof jwk !== 'object') throw sigErr('invalid_key', 'Missing JWK');
  if (!jwk.alg) throw sigErr('unsupported_algorithm', 'JWK has no alg');
  if (jwk.alg === 'Ed25519') {
    if (jwk.kty !== 'OKP' || jwk.crv !== 'Ed25519' || !jwk.x) throw sigErr('invalid_key', 'kty/crv do not match alg Ed25519');
    return 'Ed25519';
  }
  if (jwk.alg === 'ES256') {
    if (jwk.kty !== 'EC' || jwk.crv !== 'P-256' || !jwk.x || !jwk.y) throw sigErr('invalid_key', 'kty/crv do not match alg ES256');
    return 'ES256';
  }
  throw sigErr('unsupported_algorithm', `Unsupported alg ${jwk.alg}`);
}

function keyObject(jwk) {
  const alg = algOf(jwk);
  const material = alg === 'Ed25519' ? { kty: 'OKP', crv: 'Ed25519', x: jwk.x } : { kty: 'EC', crv: 'P-256', x: jwk.x, y: jwk.y };
  return jwk.d
    ? crypto.createPrivateKey({ key: { ...material, d: jwk.d }, format: 'jwk' })
    : crypto.createPublicKey({ key: material, format: 'jwk' });
}

export function signBytes(input, jwk) {
  const alg = algOf(jwk);
  const key = keyObject(jwk);
  return alg === 'Ed25519'
    ? crypto.sign(null, Buffer.from(input), key)
    : crypto.sign('sha256', Buffer.from(input), { key, dsaEncoding: 'ieee-p1363' });
}

export function verifyBytes(input, sig, jwk) {
  const alg = algOf(jwk);
  const key = keyObject(publicJwk(jwk));
  try {
    return alg === 'Ed25519'
      ? crypto.verify(null, Buffer.from(input), key, sig)
      : crypto.verify('sha256', Buffer.from(input), { key, dsaEncoding: 'ieee-p1363' }, sig);
  } catch {
    return false;
  }
}

// ---------------------------------------------------------------------------
// JWTs
// ---------------------------------------------------------------------------

export function signJwt({ typ, payload, jwk }) {
  const header = { alg: algOf(jwk), typ, kid: jwk.kid };
  const input = `${b64url(JSON.stringify(header))}.${b64url(JSON.stringify(payload))}`;
  return `${input}.${b64url(signBytes(input, jwk))}`;
}

export function decodeJwt(token) {
  const parts = String(token || '').split('.');
  if (parts.length !== 3) throw sigErr('invalid_jwt', 'Malformed JWT');
  try {
    return {
      header: JSON.parse(fromB64url(parts[0])),
      payload: JSON.parse(fromB64url(parts[1])),
      signingInput: `${parts[0]}.${parts[1]}`,
      signature: fromB64url(parts[2]),
    };
  } catch {
    throw sigErr('invalid_jwt', 'Malformed JWT');
  }
}

export const claims = (token) => decodeJwt(token).payload;

export const TOKEN_DWK = {
  'aa-agent+jwt': ['aauth-agent.json'],
  'aa-person+jwt': ['aauth-person.json'],
  // the protocol also allows AS-issued auth tokens (aauth-access.json); this agent talks to PSes only
  'aa-auth+jwt': ['aauth-person.json'],
  'aa-resource+jwt': ['aauth-resource.json'],
};

// ---------------------------------------------------------------------------
// Discovery
// ---------------------------------------------------------------------------

/** Server identifiers: https, lowercase host, no port/path/query/fragment/trailing slash (§11.1.1). */
export function assertServerId(id, { insecure = false } = {}) {
  let u;
  try {
    u = new URL(id);
  } catch {
    throw sigErr('issuer_missing', `Not a URL: ${id}`);
  }
  if (u.protocol !== 'https:' && !(insecure && u.protocol === 'http:')) {
    throw sigErr('issuer_mismatch', `Server identifiers must be https: ${id}`);
  }
  if (u.origin !== id || id !== id.toLowerCase()) throw sigErr('issuer_mismatch', `Server identifier must be a bare lowercase origin: ${id}`);
  if (u.port && !insecure) throw sigErr('issuer_mismatch', `Server identifier must not carry a port: ${id}`);
  return u;
}

export class Discovery {
  constructor({ insecure = false, fetchImpl = (...a) => fetch(...a), ttlMs = 300_000 } = {}) {
    this.insecure = insecure;
    this.fetch = fetchImpl;
    this.ttlMs = ttlMs;
    this.cache = new Map();
    this.local = new Map(); // `${iss}|${dwk}` -> { meta, jwks } (pre-seeded, no network)
  }

  seed(iss, dwk, meta, jwks) {
    this.local.set(`${iss}|${dwk}`, { meta, jwks });
  }

  async json(url, { fresh = false } = {}) {
    const hit = this.cache.get(url);
    if (!fresh && hit && hit.expires > Date.now()) return hit.value;
    const res = await this.fetch(url, { headers: { accept: 'application/json' }, redirect: 'error' });
    if (!res.ok) throw sigErr('unknown_key', `GET ${url} returned ${res.status}`);
    const value = await res.json();
    this.cache.set(url, { value, expires: Date.now() + this.ttlMs });
    return value;
  }

  async metadata(iss, dwk) {
    const seeded = this.local.get(`${iss}|${dwk}`);
    if (seeded) return seeded.meta;
    assertServerId(iss, { insecure: this.insecure });
    const meta = await this.json(`${iss}/.well-known/${dwk}`);
    if (!meta || typeof meta.issuer !== 'string') throw sigErr('issuer_missing', `${iss}/.well-known/${dwk} has no issuer`);
    if (meta.issuer !== iss) throw sigErr('issuer_mismatch', `Metadata issuer ${meta.issuer} != ${iss}`);
    return meta;
  }

  async key(iss, dwk, kid) {
    const seeded = this.local.get(`${iss}|${dwk}`);
    const meta = await this.metadata(iss, dwk);
    const pick = (jwks) => (jwks?.keys || []).find((k) => k.kid === kid);
    if (seeded) {
      const k = pick(seeded.jwks);
      if (!k) throw sigErr('unknown_key', `No key ${kid}`);
      return { key: k, meta };
    }
    let key = pick(await this.json(meta.jwks_uri));
    if (!key) key = pick(await this.json(meta.jwks_uri, { fresh: true }));
    if (!key) throw sigErr('unknown_key', `No key ${kid} in ${meta.jwks_uri}`);
    return { key, meta };
  }

  /** Verify a JWT by typ (checked first), dwk, discovery, signature, exp/iat. */
  async verifyJwt(token, typ) {
    const d = decodeJwt(token);
    const { header, payload } = d;
    if (header.typ !== typ) throw sigErr('invalid_jwt', `Expected typ ${typ}, got ${header.typ}`);
    const dwks = TOKEN_DWK[typ];
    if (!dwks || !dwks.includes(payload.dwk)) throw sigErr('invalid_jwt', `Unexpected dwk ${payload.dwk} for ${typ}`);
    if (!payload.iss) throw sigErr('issuer_missing', 'JWT has no iss');
    if (header.alg === 'none' || header.alg === 'EdDSA') throw sigErr('unsupported_algorithm', `alg ${header.alg}`);
    const { key, meta } = await this.key(payload.iss, payload.dwk, header.kid);
    if (header.alg !== key.alg) throw sigErr('unsupported_algorithm', 'JWT alg does not match key alg');
    if (!verifyBytes(d.signingInput, d.signature, key)) throw sigErr('invalid_jwt', 'JWT signature is invalid');
    const t = now();
    if (typeof payload.exp !== 'number' || payload.exp <= t) throw sigErr('expired_jwt', 'Token has expired');
    if (typeof payload.iat !== 'number') throw sigErr('invalid_jwt', 'Token has no iat');
    if (payload.iat > t + 60) throw sigErr('clock_skew', 'Token iat is in the future');
    return { header, payload, meta, key };
  }
}

// ---------------------------------------------------------------------------
// RFC 8941 structured fields (the subset AAuth headers use)
// ---------------------------------------------------------------------------

class SfParser {
  constructor(s) {
    this.s = String(s ?? '');
    this.i = 0;
  }
  ws() {
    while (this.s[this.i] === ' ' || this.s[this.i] === '\t') this.i++;
  }
  sp() {
    while (this.s[this.i] === ' ') this.i++;
  }
  fail(m) {
    throw new Error(`Structured field parse error at ${this.i}: ${m}`);
  }
  key() {
    const m = /^[a-z*][a-z0-9_.*-]*/.exec(this.s.slice(this.i));
    if (!m) this.fail('key');
    this.i += m[0].length;
    return m[0];
  }
  bare() {
    const c = this.s[this.i];
    if (c === '"') {
      let out = '';
      this.i++;
      for (;;) {
        const ch = this.s[this.i++];
        if (ch === undefined) this.fail('unterminated string');
        if (ch === '\\') {
          const n = this.s[this.i++];
          if (n !== '"' && n !== '\\') this.fail('bad escape');
          out += n;
        } else if (ch === '"') return out;
        else out += ch;
      }
    }
    if (c === ':') {
      const end = this.s.indexOf(':', this.i + 1);
      if (end < 0) this.fail('unterminated bytes');
      const b = this.s.slice(this.i + 1, end);
      if (!/^[A-Za-z0-9+/=]*$/.test(b)) this.fail('bad bytes');
      this.i = end + 1;
      return { bytes: Buffer.from(b, 'base64'), b64: b };
    }
    if (c === '?') {
      const v = this.s[this.i + 1];
      if (v !== '0' && v !== '1') this.fail('bad boolean');
      this.i += 2;
      return v === '1';
    }
    let m = /^-?\d+(\.\d+)?/.exec(this.s.slice(this.i));
    if (m) {
      this.i += m[0].length;
      return Number(m[0]);
    }
    m = /^[A-Za-z*][A-Za-z0-9!#$%&'*+\-.^_`|~:/]*/.exec(this.s.slice(this.i));
    if (m) {
      this.i += m[0].length;
      return { token: m[0] };
    }
    this.fail('bare item');
  }
  params() {
    const p = {};
    while (this.s[this.i] === ';') {
      this.i++;
      this.sp();
      const k = this.key();
      let v = true;
      if (this.s[this.i] === '=') {
        this.i++;
        v = this.bare();
      }
      p[k] = v;
    }
    return p;
  }
  item() {
    if (this.s[this.i] === '(') {
      this.i++;
      const items = [];
      for (;;) {
        this.sp();
        if (this.s[this.i] === ')') {
          this.i++;
          break;
        }
        const value = this.bare();
        items.push({ value, params: this.params() });
        if (this.s[this.i] !== ' ' && this.s[this.i] !== ')') this.fail('inner list');
      }
      return { items, params: this.params() };
    }
    const value = this.bare();
    return { value, params: this.params() };
  }
}

/** Parse an RFC 8941 Dictionary. Returns { key: {value|items, params} }, raw text of each member in .raw. */
export function parseDictionary(header) {
  const p = new SfParser(header);
  const out = {};
  p.sp();
  if (p.i >= p.s.length) return out;
  for (;;) {
    p.sp();
    const k = p.key();
    let member;
    const start = p.i;
    if (p.s[p.i] === '=') {
      p.i++;
      const rawStart = p.i;
      member = p.item();
      member.raw = p.s.slice(rawStart, p.i);
    } else {
      member = { value: true, params: p.params() };
      member.raw = p.s.slice(start, p.i);
    }
    out[k] = member;
    p.ws();
    if (p.i >= p.s.length) return out;
    if (p.s[p.i] !== ',') p.fail('expected ,');
    p.i++;
    p.ws();
  }
}

export const sfString = (s) => {
  if (/[\x00-\x1f\x7f]/.test(s)) throw new Error('Control characters cannot be serialized');
  return `"${String(s).replace(/[\\"]/g, (c) => `\\${c}`)}"`;
};

const plain = (v) => (v && typeof v === 'object' && 'token' in v ? v.token : v && typeof v === 'object' && 'b64' in v ? v.b64 : v);

/** AAuth-Requirement -> { requirement, ...params } (strings). Tolerant: returns {} on garbage. */
export function parseRequirement(value) {
  if (!value) return {};
  try {
    const d = parseDictionary(value);
    const m = d.requirement;
    if (!m) return {};
    const out = { requirement: plain(m.value) };
    for (const [k, v] of Object.entries(m.params || {})) out[k] = plain(v);
    return out;
  } catch {
    return {};
  }
}

/** Signature-Error: error=<token>[, required_input=(...)] -> { error, ... } */
export function parseSignatureError(value) {
  if (!value) return null;
  try {
    const d = parseDictionary(value);
    const out = {};
    for (const [k, v] of Object.entries(d)) out[k] = v.items ? v.items.map((i) => plain(i.value)) : plain(v.value);
    return out;
  } catch {
    return { error: String(value) };
  }
}

// ---------------------------------------------------------------------------
// HTTP message signatures (RFC 9421, AAuth profile, strict wire form)
// ---------------------------------------------------------------------------

export const BASE_COMPONENTS = ['@method', '@authority', '@path', 'signature-key'];
export const contentDigest = (body) => `sha-256=:${sha256(body).toString('base64')}:`;

function lowerHeaders(h) {
  const out = {};
  if (!h) return out;
  const entries = typeof h.entries === 'function' && !(h instanceof Map) && !Array.isArray(h) ? [...h.entries()] : Array.isArray(h) ? h : Object.entries(h);
  for (const [k, v] of entries) {
    const key = k.toLowerCase();
    out[key] = out[key] === undefined ? String(v) : `${out[key]}, ${v}`;
  }
  return out;
}

/** The signature base for a message. msg = { method, url (URL), headers (lowercase obj) } */
export function signatureBase(components, paramsSerialized, { method, url, headers }) {
  const lines = components.map((c) => {
    let v;
    switch (c) {
      case '@method':
        v = method.toUpperCase();
        break;
      case '@authority':
        v = url.host.toLowerCase();
        break;
      case '@path':
        v = url.pathname || '/';
        break;
      case '@query':
        v = url.search ? url.search : '?';
        break;
      case '@target-uri':
        v = url.href;
        break;
      default:
        if (c.startsWith('@')) throw sigErr('invalid_input', `Unsupported derived component ${c}`);
        if (headers[c] === undefined) throw sigErr('invalid_input', `Covered component ${c} is missing`);
        v = headers[c].trim();
    }
    return `"${c}": ${v}`;
  });
  lines.push(`"@signature-params": ${paramsSerialized}`);
  return lines.join('\n');
}

/**
 * Sign a request. Returns { url, method, headers (lowercase object), body (string|undefined), base }.
 * body: undefined | string | object (JSON-encoded). `@query` is covered whenever the URL has a query.
 * opts.additional: the resource's additional_signature_components; each one present on the request
 * is covered too (a declared @query is covered as "?" on a URL without a query).
 * opts.created overrides the timestamp (tests); opts.components overrides the covered list (tests).
 */
export function signRequest(url, { method = 'GET', body, token, jwk, headers: extra = {}, created, components: forced, query, additional = [] } = {}) {
  const u = new URL(url);
  const headers = lowerHeaders(extra);
  let bodyText;
  if (body !== undefined && body !== null) {
    bodyText = typeof body === 'string' ? body : JSON.stringify(body);
    if (!headers['content-type']) headers['content-type'] = 'application/json';
    headers['content-digest'] = contentDigest(bodyText);
  }
  headers['signature-key'] = `sig=jwt;jwt="${token}"`;
  const declared = (Array.isArray(additional) ? additional : []).map((c) => String(c).toLowerCase());
  const components = forced || [
    ...BASE_COMPONENTS,
    ...((query ?? (u.search !== '' || declared.includes('@query'))) ? ['@query'] : []),
    ...(bodyText !== undefined ? ['content-type', 'content-digest'] : []),
  ];
  if (!forced) {
    for (const c of declared) {
      if (components.includes(c) || c === 'signature-key' || c === 'signature' || c === 'signature-input') continue;
      if (c.startsWith('@')) {
        if (['@method', '@authority', '@path', '@target-uri'].includes(c)) components.push(c);
      } else if (headers[c] !== undefined) components.push(c);
    }
  }
  const params = `(${components.map((c) => `"${c}"`).join(' ')});created=${created ?? now()}`;
  const base = signatureBase(components, params, { method, url: u, headers });
  headers['signature-input'] = `sig=${params}`;
  headers['signature'] = `sig=:${signBytes(base, jwk).toString('base64')}:`;
  return { url: u.href, method: method.toUpperCase(), headers, body: bodyText, base };
}

/** Sign and send. Returns a plain response record { status, headers, text, body, request }. */
export async function signedFetch(url, opts = {}) {
  const req = signRequest(url, opts);
  const res = await (opts.fetchImpl || fetch)(req.url, { method: req.method, headers: req.headers, body: req.body, redirect: 'manual' });
  return toRecord(res, req);
}

export async function toRecord(res, request) {
  const text = await res.text();
  let body = text;
  try {
    body = text ? JSON.parse(text) : null;
  } catch {}
  const headers = {};
  res.headers.forEach((v, k) => (headers[k] = v));
  return {
    status: res.status,
    headers,
    text,
    body,
    request,
    requirement: parseRequirement(headers['aauth-requirement']),
    signatureError: parseSignatureError(headers['signature-error']),
  };
}

/**
 * Verify a signed request (server side; used by tests and the demo cross-check).
 * msg = { method, url, headers, body }. Returns { token, header, payload, jwk, jkt, components, created }.
 */
export async function verifySignedRequest(msg, { discovery, accept = Object.keys(TOKEN_DWK), window = 60, requireQuery = false, replay } = {}) {
  const headers = lowerHeaders(msg.headers);
  const url = new URL(msg.url);
  const method = msg.method.toUpperCase();
  const bodyText = msg.body ?? '';
  if (!headers['signature-key'] || !headers['signature-input'] || !headers['signature']) {
    throw sigErr('invalid_signature', 'Missing Signature, Signature-Input or Signature-Key');
  }
  let sk, si, sg;
  try {
    sk = parseDictionary(headers['signature-key']);
    si = parseDictionary(headers['signature-input']);
    sg = parseDictionary(headers['signature']);
  } catch (e) {
    throw sigErr('invalid_signature', e.message);
  }
  const label = Object.keys(si).find((l) => sk[l] && sg[l]);
  if (!label) throw sigErr('invalid_signature', 'No label present in all three signature headers');
  const keyMember = sk[label];
  if (plain(keyMember.value) !== 'jwt') {
    const e = sigErr('unsupported_scheme', 'Use the jwt Signature-Key scheme');
    e.headers = { 'accept-signature-scheme': 'jwt' };
    throw e;
  }
  const token = keyMember.params.jwt;
  if (typeof token !== 'string') throw sigErr('invalid_key', 'jwt parameter missing');
  const input = si[label];
  if (!input.items) throw sigErr('invalid_signature', 'Signature-Input member is not an inner list');
  const components = input.items.map((i) => i.value);
  if (components.some((c) => typeof c !== 'string')) throw sigErr('invalid_signature', 'Components must be strings');
  const required = [...BASE_COMPONENTS, ...(bodyText !== '' ? ['content-type', 'content-digest'] : []), ...(requireQuery && url.search ? ['@query'] : [])];
  const missing = required.filter((c) => !components.includes(c));
  if (missing.length) throw sigErr('invalid_input', `Signature must cover: ${missing.join(', ')}`);
  const created = input.params.created;
  const t = now();
  if (typeof created !== 'number') throw sigErr('invalid_signature', 'created missing');
  if (created < t - window) throw sigErr('invalid_signature', 'Signature is older than the window');
  if (created > t + window) throw sigErr('clock_skew', 'Signature created in the future');
  if (typeof input.params.expires === 'number' && input.params.expires < t) throw sigErr('invalid_signature', 'Signature expired');
  if (bodyText !== '' && headers['content-digest'] !== contentDigest(bodyText)) throw sigErr('invalid_signature', 'Content-Digest does not match the body');
  const { header } = decodeJwt(token);
  if (!accept.includes(header.typ)) throw sigErr('invalid_jwt', `Unexpected token type ${header.typ}`);
  const verified = await discovery.verifyJwt(token, header.typ);
  const jwk = verified.payload.cnf?.jwk;
  if (!jwk) throw sigErr('invalid_jwt', 'Token has no cnf.jwk');
  const sigVal = sg[label].value;
  if (!sigVal || !sigVal.bytes) throw sigErr('invalid_signature', 'Malformed Signature');
  const paramsRaw = input.raw;
  const base = signatureBase(components, paramsRaw, { method, url, headers });
  if (!verifyBytes(base, sigVal.bytes, jwk)) throw sigErr('invalid_signature', 'HTTP message signature is invalid');
  const jkt = jwkThumbprint(jwk);
  if (replay) {
    // keyed on what was signed (key + signature base), never on the signature's encoding: ES256
    // signatures are malleable ((r, s) and (r, n - s) both verify) and base64 padding is optional
    const k = sha256(`${jkt}\n${base}`).toString('hex');
    if (replay.has(k)) throw sigErr('invalid_signature', 'Replayed signature');
    replay.add(k);
  }
  return { token, ...verified, jwk, jkt, components, created };
}

// ---------------------------------------------------------------------------
// The reference deployment ("Acme Reports" on the df-aauth demo host): its issuer, its keys
// container and its test credentials, read from agent/reference.json. That file exists only in a
// development checkout of df-aauth (it is never shipped), so an installed copy has no default
// issuer and never borrows keys from a container: your agent passes its issuer/keys explicitly or
// uses config.mjs (`aauth init`). server.mjs, e2e.mjs and interop.test.mjs use these.
// ---------------------------------------------------------------------------

const HERE = path.dirname(new URL(import.meta.url).pathname);
export const REFERENCE = (() => {
  try {
    return Object.freeze(JSON.parse(fs.readFileSync(path.join(HERE, 'reference.json'), 'utf8')));
  } catch {
    return Object.freeze({});
  }
})();
export const DEFAULT_ISSUER = typeof REFERENCE.issuer === 'string' ? REFERENCE.issuer : undefined;
export const DEFAULT_CONTAINER = typeof REFERENCE.container === 'string' ? REFERENCE.container : undefined;

export function keysPath() {
  return process.env.AAUTH_KEYS || path.join(HERE, '.keys.json');
}

/** Server: load or create the keys file. */
export function loadOrCreateKeys(file = keysPath()) {
  try {
    return JSON.parse(fs.readFileSync(file, 'utf8'));
  } catch (e) {
    if (e.code !== 'ENOENT') throw e;
  }
  const keys = { ap: generateJwk(), agent: generateJwk(), test_ps: generateJwk(), created_at: new Date().toISOString() };
  fs.mkdirSync(path.dirname(file), { recursive: true });
  fs.writeFileSync(file, JSON.stringify(keys, null, 2), { mode: 0o600 });
  return keys;
}

/**
 * CLI/e2e: the keys the running server publishes. Order: $AAUTH_KEYS / agent/.keys.json,
 * else read /data/keys.json from the agent container (sudo -n docker exec), never printed.
 */
export function loadKeys({ quiet = false } = {}) {
  const file = keysPath();
  if (fs.existsSync(file)) return JSON.parse(fs.readFileSync(file, 'utf8'));
  if (process.env.AAUTH_KEYS) {
    // an explicit path that does not exist is a mistake, never a cue to borrow the live AP's keys
    throw new Error(`AAUTH_KEYS=${process.env.AAUTH_KEYS} does not exist.`);
  }
  if (!DEFAULT_CONTAINER) throw new Error(`No keys: ${file} does not exist. Start server.mjs first, or set AAUTH_KEYS.`);
  const container = process.env.AAUTH_CONTAINER || DEFAULT_CONTAINER;
  try {
    const out = execFileSync('sudo', ['-n', 'docker', 'exec', container, 'cat', '/data/keys.json'], { stdio: ['ignore', 'pipe', 'ignore'] });
    if (!quiet) process.stderr.write(`note: ${file} not found; using the agent provider keys from container ${container} (sudo docker exec)\n`);
    return JSON.parse(out.toString('utf8'));
  } catch {
    throw new Error(`No keys: ${file} does not exist and ${container}:/data/keys.json is unreadable. Start server.mjs first.`);
  }
}

// ---------------------------------------------------------------------------
// The agent: full three-party flow
// ---------------------------------------------------------------------------

const sleep = (ms, signal) =>
  new Promise((resolve) => {
    if (signal?.aborted) return resolve();
    const t = setTimeout(done, ms);
    function done() {
      clearTimeout(t);
      signal?.removeEventListener?.('abort', done);
      resolve();
    }
    signal?.addEventListener?.('abort', done, { once: true });
  });
const originOf = (url) => new URL(url).origin;

/** The space-separated scope of a token (or a scope string / list) as an array. */
export function scopesOf(tokenOrScope) {
  if (!tokenOrScope) return [];
  if (Array.isArray(tokenOrScope)) return tokenOrScope.flatMap((s) => String(s).split(/[\s,]+/)).filter(Boolean);
  const s = String(tokenOrScope);
  const isJwt = /^eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*$/.test(s);
  const scope = isJwt ? (claims(s).scope ?? '') : s;
  return String(scope).split(/[\s,]+/).filter(Boolean);
}

/** Agent ids are aauth:<local>@<agent provider host> (§5.2). */
export function defaultAgentId(issuer, local) {
  const host = new URL(issuer).host;
  return `aauth:${local || (DEFAULT_ISSUER && issuer === DEFAULT_ISSUER ? 'reports' : 'agent')}@${host}`;
}

export function assertAgentId(sub, issuer) {
  const m = /^aauth:([A-Za-z0-9._+-]{1,255})@([^@\s]+)$/.exec(String(sub));
  if (!m) throw new Error(`Agent id must look like aauth:<name>@<host> (letters, digits, . _ - +): ${sub}`);
  if (issuer && m[2] !== new URL(issuer).host) throw new Error(`Agent id ${sub} must use the agent provider's host ${new URL(issuer).host}`);
  return sub;
}

/**
 * new Agent({ issuer, apKey | agentToken, agentKey, sub, insecure, cache, callback })
 *   issuer      the Agent Provider: the https origin serving /.well-known/aauth-agent.json + its JWKS
 *   apKey       private JWK that signs agent tokens (its public half is in the AP's JWKS)
 *   agentToken  instead of apKey: async (ps) => aa-agent+jwt minted by your AP for agentKey
 *   agentKey    private JWK that signs every request (generated when omitted; cnf.jwk of every token)
 *   sub         agent id, aauth:<name>@<issuer host>
 *   cache       { get(key) -> {person, auth}, set(key, value), delete(key) } (default: in memory)
 *   callback    true (= {issuer}/callback) | URL string | false: appended to the approval URL
 * agent.request(method, url, { body, headers, scope, ps, why, onInteraction, onStep, fresh, pollTimeoutMs, signal })
 *   -> { status, headers, body, text, steps, interactions }   (+ failed/cancelled/error/detail on a failed flow)
 *   scope: ask for these scopes up front through the resource's authorization_endpoint (space/comma separated)
 *   signal: an AbortSignal; aborting while waiting for the person cancels the pending request (DELETE)
 * onInteraction({ purpose: 'person'|'auth', code, url, userUrl, location }) is awaited before polling.
 *   Return 'cancel' to DELETE the pending request and stop (result.cancelled = true).
 */
export class Agent {
  constructor({ issuer = process.env.AAUTH_AGENT_ISSUER || DEFAULT_ISSUER, apKey, agentToken, agentKey, sub, insecure = false, cache, discovery, callback = true, fetch: fetchImpl } = {}) {
    if (!apKey && typeof agentToken !== 'function') throw new Error('apKey (or an agentToken(ps) function) is required');
    if (!issuer) throw new Error('issuer is required: the Agent Provider origin (or set AAUTH_AGENT_ISSUER)');
    this.issuer = String(issuer).replace(/\/+$/, '');
    this.apKey = apKey;
    this.tokenSource = typeof agentToken === 'function' ? agentToken : null;
    this.agentKey = agentKey || generateJwk();
    this.sub = sub || defaultAgentId(this.issuer);
    this.jkt = jwkThumbprint(this.agentKey);
    this.insecure = insecure;
    this.fetchImpl = fetchImpl;
    this.discovery = discovery || new Discovery({ insecure, ...(fetchImpl ? { fetchImpl } : {}) });
    this.cache = cache || memoryCache();
    this.callback = callback;
  }

  /** The approval-page callback, or null. */
  get callbackUrl() {
    if (!this.callback) return null;
    return typeof this.callback === 'string' ? this.callback : `${this.issuer}/callback`;
  }

  /** A fresh agent token signed with apKey (synchronous; needs apKey). */
  agentToken(ps) {
    if (!this.apKey) throw new Error('agentToken() needs apKey; this agent gets its tokens from agentToken(ps)');
    const t = now();
    const payload = { iss: this.issuer, dwk: 'aauth-agent.json', sub: this.sub, cnf: { jwk: publicJwk(this.agentKey) }, jti: randomId(), iat: t, exp: t + 3600 };
    if (ps) payload.ps = ps;
    return signJwt({ typ: 'aa-agent+jwt', jwk: this.apKey, payload });
  }

  /** An agent token from apKey or from the agentToken(ps) source. */
  async getAgentToken(ps) {
    if (!this.tokenSource) return this.agentToken(ps);
    const token = await this.tokenSource(ps);
    const c = claims(token);
    if (jwkThumbprint(c.cnf?.jwk || {}) !== this.jkt) throw new AAuthError(0, 'invalid_agent_token', 'agentToken(ps) returned a token for a different agentKey');
    return token;
  }

  /** Sign and send one request of a flow; records it in ctx.steps and reports it to ctx.onStep. */
  async send(ctx, kind, title, url, opts) {
    const rec = await signedFetch(url, { jwk: this.agentKey, ...(this.fetchImpl ? { fetchImpl: this.fetchImpl } : {}), ...opts });
    const step = { kind, title, request: rec.request, status: rec.status, response: { status: rec.status, headers: rec.headers, body: rec.body } };
    ctx.steps.push(step);
    ctx.onStep?.(step);
    return rec;
  }

  async resolvePs(resource, explicit) {
    if (explicit) {
      const ps = explicit.replace(/\/+$/, '');
      assertServerId(ps, { insecure: this.insecure });
      return { ps, meta: await this.discovery.metadata(ps, 'aauth-person.json') };
    }
    try {
      return { ps: resource, meta: await this.discovery.metadata(resource, 'aauth-person.json') };
    } catch (e) {
      throw new AAuthError(0, 'no_person_server', `${resource} has no Person Server metadata; pass --ps <url> (${e.message})`);
    }
  }

  /** The cache key for (this agent, resource, PS). */
  cacheKey(resource, ps) {
    return `${this.issuer}|${this.sub}|${this.jkt}|${resource}|${ps}`;
  }

  async request(method, url, { body, headers, scope, ps: psOpt, why, onInteraction, onStep, fresh = false, pollTimeoutMs = 600_000, maxStepUps = 2, signal, _retried = false } = {}) {
    const steps = [];
    const interactions = [];
    // per-request state (an Agent may run several requests at once)
    const ctx = { steps, interactions, why, onInteraction, onStep, pollTimeoutMs, signal };
    const resource = originOf(url);
    assertServerId(resource, { insecure: this.insecure });
    const note = (step) => {
      steps.push(step);
      onStep?.(step);
    };
    const rmeta = await this.discovery.metadata(resource, 'aauth-resource.json');
    note({ kind: 'discover', title: 'Resource metadata', status: 200, response: { status: 200, body: rmeta } });

    const { ps, meta: psMeta } = await this.resolvePs(resource, psOpt);
    note({ kind: 'discover', title: 'Person Server metadata', status: 200, response: { status: 200, body: psMeta } });
    const cacheKey = this.cacheKey(resource, ps);
    if (fresh) this.cache.delete(cacheKey);
    const saved = this.cache.get(cacheKey) || {};
    const valid = (tok) => tok && claims(tok).exp > now() + 300;
    const agentToken = await this.getAgentToken(ps);
    const callOpts = { method, body, headers, additional: rmeta.additional_signature_components };
    Object.assign(ctx, { ps, psMeta, resource, agentToken, cacheKey });
    const again = () => this.request(method, url, { body, headers, scope, ps: psOpt, why, onInteraction, onStep, fresh: true, pollTimeoutMs, maxStepUps, signal, _retried: true });

    const finish = (rec, extra = {}) => ({ status: rec.status, headers: rec.headers, body: rec.body, text: rec.text, steps, interactions, ...extra });

    let person = valid(saved.person) ? saved.person : null;
    let auth = valid(saved.auth) ? saved.auth : null;
    let rec;
    let reuseLabel = ['reuse', 'Call with cached auth token'];

    // Up-front scope (§6.6): resource token from the authorization_endpoint, then the PS, then the call.
    const wanted = scopesOf(scope);
    if (wanted.length && !(auth && wanted.every((s) => scopesOf(auth).includes(s)))) {
      if (!rmeta.authorization_endpoint) {
        note({ kind: 'authorize', title: 'No authorization_endpoint: the scope comes from the resource challenge', status: 0 });
      } else {
        if (!person && !auth) {
          const got = await this.personToken(ctx);
          if (got.cancelled || got.failed) return { ...got, steps, interactions };
          person = got.token;
          this.cache.set(cacheKey, { person });
        }
        const presented = auth || person;
        const ask = [...new Set([...(auth ? scopesOf(auth) : []), ...wanted])].join(' ');
        const az = await this.send(ctx, 'authorize', `Ask the resource for ${ask}`, rmeta.authorization_endpoint, { method: 'POST', body: { scope: ask }, token: presented });
        if (az.status !== 200 || typeof az.body?.resource_token !== 'string') {
          if (az.status === 401 && !_retried && (saved.person === presented || saved.auth === presented)) {
            this.cache.delete(cacheKey);
            return again();
          }
          return finish(az, { failed: true, error: az.body?.error || `http_${az.status}`, detail: az.body?.detail });
        }
        const rt = az.body.resource_token;
        const rtClaims = await this.checkResourceToken(rt, resource, ps, presented);
        steps[steps.length - 1].tokens = [rt];
        const got = await this.authToken(ctx, rt, presented, rtClaims);
        if (got.cancelled || got.failed) return { ...got, steps, interactions };
        auth = got.token;
        this.cache.set(cacheKey, { person, auth });
        reuseLabel = ['call', 'Call with auth token'];
      }
    }

    if (auth) {
      rec = await this.send(ctx, reuseLabel[0], reuseLabel[1], url, { ...callOpts, token: auth });
      if (rec.requirement.requirement !== 'auth-token' && rec.status === 401) {
        // revoked / keys rotated / expired: start over
        auth = null;
        person = null;
        this.cache.delete(cacheKey);
      } else if (rec.requirement.requirement !== 'auth-token') {
        return finish(rec);
      }
    }
    if (!rec || (!auth && !person)) {
      if (!person) {
        rec = await this.send(ctx, 'call', 'Call with agent token', url, { ...callOpts, token: agentToken });
        if (rec.requirement.requirement !== 'person-token') return finish(rec);
        person = await this.personToken(ctx);
        if (person.cancelled || person.failed) return { ...person, steps, interactions };
        person = person.token;
        this.cache.set(cacheKey, { person });
      }
      rec = await this.send(ctx, 'call', 'Call with person token', url, { ...callOpts, token: person });
      if (rec.status === 401 && rec.requirement.requirement !== 'auth-token' && saved.person === person && !_retried) {
        this.cache.delete(cacheKey);
        return again();
      }
    }

    let presented = auth || person;
    for (let round = 0; round <= maxStepUps; round++) {
      if (!(rec.status === 401 || rec.status === 202 || rec.status === 402) || rec.requirement.requirement !== 'auth-token') return finish(rec);
      if (round === maxStepUps) return finish(rec, { error: 'step_up_loop', detail: 'The resource keeps asking for more scope' });
      const rt = rec.requirement['resource-token'];
      if (!rt) return finish(rec, { error: 'no_resource_token' });
      const rtClaims = await this.checkResourceToken(rt, resource, ps, presented);
      steps[steps.length - 1].tokens = [rt];
      const got = await this.authToken(ctx, rt, presented, rtClaims);
      if (got.cancelled || got.failed) return { ...got, steps, interactions };
      auth = got.token;
      this.cache.set(cacheKey, { person, auth });
      presented = auth;
      rec = await this.send(ctx, 'call', 'Call with auth token', url, { ...callOpts, token: auth });
      if (rec.status === 401 && rec.requirement.requirement !== 'auth-token') {
        this.cache.set(cacheKey, { person });
      }
    }
    return finish(rec);
  }

  async checkResourceToken(rt, resource, ps, presented) {
    const { payload: c } = await this.discovery.verifyJwt(rt, 'aa-resource+jwt');
    const p = claims(presented);
    const bad = (m) => {
      throw new AAuthError(0, 'invalid_resource_token', m);
    };
    if (c.iss !== resource) bad(`iss ${c.iss} is not ${resource}`);
    if (c.agent_jkt !== this.jkt) bad('agent_jkt is not this agent key');
    if (c.aud !== ps) bad(`aud ${c.aud} is not our PS ${ps}`);
    if (c.ps !== undefined && c.ps !== ps) bad(`ps ${c.ps} is not our PS`);
    if (c.sub !== p.sub) bad('sub does not match the presented token');
    if (c.presented_jti !== p.jti) bad('presented_jti does not match the presented token');
    return c;
  }

  async personToken(ctx) {
    const body = { resource: ctx.resource, capabilities: ['interaction'] };
    if (ctx.why) body.justification = ctx.why;
    const rec = await this.send(ctx, 'person_token', 'Ask the PS for a person token', ctx.psMeta.person_token_endpoint, { method: 'POST', body, token: ctx.agentToken });
    const result = await this.deferred(ctx, rec, 'person', ctx.psMeta.person_token_endpoint);
    if (result.token) {
      const { payload } = await this.discovery.verifyJwt(result.token, 'aa-person+jwt');
      if (payload.iss !== ctx.ps) throw new AAuthError(0, 'invalid_person_token', `iss ${payload.iss} != ${ctx.ps}`);
      if (payload.aud !== ctx.resource) throw new AAuthError(0, 'invalid_person_token', `aud ${payload.aud} != ${ctx.resource}`);
      if (jwkThumbprint(payload.cnf?.jwk || {}) !== this.jkt) throw new AAuthError(0, 'invalid_person_token', 'cnf is not this agent key');
    }
    return result;
  }

  async authToken(ctx, rt, presented, rtClaims) {
    const body = { resource_token: rt, presented_token: presented };
    if (ctx.why) body.justification = ctx.why;
    const rec = await this.send(ctx, 'auth_token', `Ask the PS for an auth token (${rtClaims.scope || ''})`, ctx.psMeta.auth_token_endpoint, { method: 'POST', body, token: ctx.agentToken });
    const result = await this.deferred(ctx, rec, 'auth', ctx.psMeta.auth_token_endpoint);
    if (result.token) {
      const { payload } = await this.discovery.verifyJwt(result.token, 'aa-auth+jwt');
      const bad = (m) => {
        throw new AAuthError(0, 'invalid_auth_token', m);
      };
      if (payload.iss !== rtClaims.aud) bad(`iss ${payload.iss} != resource token aud ${rtClaims.aud}`);
      if (payload.aud !== ctx.resource) bad(`aud ${payload.aud} != ${ctx.resource}`);
      if (jwkThumbprint(payload.cnf?.jwk || {}) !== this.jkt) bad('cnf is not this agent key');
      if (payload.sub !== claims(presented).sub) bad('sub does not match the presented token');
    }
    return result;
  }

  /** Handle a PS token endpoint response: 200, or 202 + interaction + polling. */
  async deferred(ctx, rec, purpose, endpoint) {
    const field = purpose === 'person' ? 'person_token' : 'auth_token';
    if (rec.status === 200 && rec.body?.[field]) return { token: rec.body[field], immediate: true };
    if (rec.status !== 202) {
      return { failed: true, status: rec.status, error: rec.body?.error || `http_${rec.status}`, detail: rec.body?.detail, headers: rec.headers, body: rec.body };
    }
    const r = rec.requirement;
    const location = rec.headers.location ? new URL(rec.headers.location, endpoint).href : null;
    if (!location) return { failed: true, status: 202, error: 'no_location' };
    const code = r.code || rec.body?.code;
    const base = r.url; // the PS interaction requirement carries the consent page URL
    let userUrl = null;
    if (r.requirement === 'interaction' && code && base) {
      userUrl = `${base}?code=${encodeURIComponent(code)}`;
      if (this.callbackUrl) userUrl += `&callback=${encodeURIComponent(this.callbackUrl)}`;
    }
    const info = { purpose, code, url: base, userUrl, location, requirement: r.requirement };
    ctx.interactions.push(info);
    if (ctx.onInteraction) {
      const decision = await ctx.onInteraction(info);
      if (decision === 'cancel') return this.cancel(ctx, location, info);
    }
    return this.poll(ctx, location, field, rec.headers['retry-after'], info);
  }

  async cancel(ctx, location, info) {
    const del = await this.send(ctx, 'poll', 'Cancel the pending request', location, { method: 'DELETE', token: ctx.agentToken });
    return { cancelled: true, status: del.status, info };
  }

  async poll(ctx, location, field, retryAfter, info) {
    const deadline = Date.now() + ctx.pollTimeoutMs;
    let wait = retryAfter !== undefined ? Number(retryAfter) : 0;
    let polls = 0;
    while (Date.now() < deadline) {
      if (wait > 0) await sleep(wait * 1000, ctx.signal);
      if (ctx.signal?.aborted) return this.cancel(ctx, location, info);
      const rec = await signedFetch(location, { method: 'GET', token: ctx.agentToken, jwk: this.agentKey, ...(this.fetchImpl ? { fetchImpl: this.fetchImpl } : {}) });
      polls++;
      if (rec.status === 202) {
        wait = rec.headers['retry-after'] !== undefined ? Number(rec.headers['retry-after']) : 5;
        if (!Number.isFinite(wait) || wait < 0) wait = 5;
        continue;
      }
      if (rec.status === 429) {
        wait += 5;
        continue;
      }
      const step = { kind: 'poll', title: `Poll (${polls}x)`, request: rec.request, status: rec.status, response: { status: rec.status, headers: rec.headers, body: rec.body } };
      ctx.steps.push(step);
      ctx.onStep?.(step);
      if (rec.status === 200 && rec.body?.[field]) return { token: rec.body[field], info };
      return { failed: true, status: rec.status, error: rec.body?.error || `http_${rec.status}`, detail: rec.body?.detail, headers: rec.headers, body: rec.body, info };
    }
    return { failed: true, status: 0, error: 'timeout', detail: 'Gave up waiting for the person', info };
  }
}

// Token caches. Keys are Agent#cacheKey(resource, ps) = `${issuer}|${sub}|${jkt}|${resource}|${ps}`;
// values { person, auth } (JWT strings). The tokens are bound to the agent key (cnf), so they are
// useless without it; the file is still written with mode 600.
export function memoryCache() {
  const m = new Map();
  return { get: (k) => m.get(k), set: (k, v) => m.set(k, v), delete: (k) => m.delete(k), clear: () => m.clear(), all: () => Object.fromEntries(m) };
}

export function fileCache(file) {
  const read = () => {
    try {
      return JSON.parse(fs.readFileSync(file, 'utf8'));
    } catch {
      return {};
    }
  };
  const write = (all) => {
    try {
      fs.mkdirSync(path.dirname(file), { recursive: true, mode: 0o700 });
      const tmp = `${file}.${process.pid}.tmp`;
      fs.writeFileSync(tmp, JSON.stringify(all, null, 2), { mode: 0o600 });
      fs.renameSync(tmp, file);
    } catch {}
  };
  return {
    file,
    get: (k) => read()[k],
    set: (k, v) => write({ ...read(), [k]: v }),
    delete: (k) => {
      const all = read();
      delete all[k];
      write(all);
    },
    clear: () => write({}),
    all: read,
  };
}

/** Split a cache key back into its parts. */
export function parseCacheKey(k) {
  const [issuer, sub, jkt, resource, ps] = String(k).split('|');
  return { issuer, sub, jkt, resource, ps };
}

export const escapeHtml = (s) =>
  String(s ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c]);
