# Cross-implementation fixtures

Produced by `agent/interop.test.mjs` with the AAuth reference demo's own library
(`shared/aauth.mjs` of https://github.com/wjgilmore/aauth-demo, MIT; point `AAUTH_DEMO_LIB` at
a local checkout of it). Regenerate with
`AAUTH_WRITE_FIXTURE=1 node --test agent/interop.test.mjs`; without that flag the test only
re-verifies the committed files (with both our Node verifier and the demo's verifier), so the
PHP tests see stable bytes. Self-contained: no network is needed to verify them.

## demo-signed-request.json

| key | meaning |
|---|---|
| `now` | Unix time to verify at (the signatures' `created` and the JWT `iat`) |
| `window` | signature window in seconds (60) |
| `agent_provider` | `{issuer, dwk: "aauth-agent.json", metadata, jwks}`. Build a static `KeyResolver` from it: `resolve(issuer, "aauth-agent.json", kid)` → `['jwk' => jwks.keys[kid], 'meta' => metadata]` |
| `agent_token` | the `aa-agent+jwt` carried in `Signature-Key` (signed by the demo `signJwt`, header `alg,typ,kid`) |
| `agent_token_header`, `agent_token_claims` | decoded, for convenience |
| `agent_public_jwk`, `agent_jkt` | the `cnf.jwk` that signed the HTTP requests and its RFC 7638 thumbprint |
| `request` | POST with a JSON body: `{method, url, authority, path, query (null = none), headers (lowercase name => value, exactly as sent), body (exact bytes)}`. Maps 1:1 onto `HttpRequestParts(method, authority, path, query, headers, body)` |
| `get_request` | GET without body or query, same shape |
| `expect` | `valid: true`, `typ`, `created`, the covered `components` of `request` and `get_components` of `get_request` (in Signature-Input order) |
| `negative` | mutations that must fail: `target` (`request`/`get_request`), `change` (fields of that request to replace) and/or `now` (verify at a different time), `error` = the expected `Signature-Error` code. `require_query: true` means verify with `requireQuery = true`. |

Expected errors: `body_tampered` → `invalid_signature` (Content-Digest), `authority_changed`,
`path_changed`, `method_changed` → `invalid_signature`, `query_added` (with requireQuery) →
`invalid_input`, `stale` (now + 120) → `invalid_signature`, `future` (now − 120) → `clock_skew`.

## demo-jwt.json

A person token (`aa-person+jwt`) signed by the demo's `signJwt` with an Ed25519 key:
`{now, issuer, dwk, metadata, jwks, jwt, typ, header, payload, cnf_jkt}`. Verify with
`Jwt::verify($jwt, 'aa-person+jwt', <static resolver from issuer/dwk/metadata/jwks>, $now)`; the
result's payload must equal `payload`, and the thumbprint of `payload.cnf.jwk` equals `cnf_jkt`.

## How the PHP suite consumes them

`tests/Protocol/DemoFixtureTest.php` (suite `Protocol`) reads both files when present and skips
otherwise (`AAUTH_FIXTURE_DIR` overrides the directory). It uses the real library path, not a
shortcut:

- keys: a real `Discovery` over a fake `HttpFetcher` that serves `{issuer}/.well-known/{dwk}` =
  `metadata` and `metadata.jwks_uri` = `jwks` (so the `issuer` byte-equality and kid selection
  are exercised);
- `request` / `get_request` → `HttpRequestParts(method, authority, path, query, headers, body)`
  → `SignatureKey::parse` → `Jwt::verify($jwt, expect.typ, $discovery, now)` →
  `HttpSignature::verify($parts, cnf_jwk, now, window, requireQuery)`; `get_request` is verified
  with `requireQuery = true`;
- asserts `agent_token`, `agent_jkt`, `agent_token_claims`, `expect.components`,
  `expect.get_components`, `expect.created`;
- every `negative` entry must throw `AAuthError` with status 401 and `error` equal to the entry's
  `error`;
- `demo-jwt.json`: `header`, `payload` and `cnf_jkt` must match after `Jwt::verify`.

Keys that are required: `now`, `agent_provider.{issuer,dwk,metadata,jwks}`, `agent_token`,
`agent_public_jwk`, `agent_jkt`, `agent_token_claims`, `request`, `expect.{typ,components,created}`.
Optional: `window` (default 60), `get_request` (+ `expect.get_components`), `negative`.
