# AAuth protocol library (`DreamFactory\Core\AAuth\Protocol`)

Pure PHP 8.3+, ext-sodium + ext-openssl, no Laravel, no composer deps. Implements the pieces of
draft-hardt-oauth-aauth-protocol-11 and draft-hardt-httpbis-signature-key-09 that DreamFactory
needs. Tests: `bin/test.sh --testsuite Protocol`.

## API notes

Details of the public API that callers need:

1. **`TOKEN_DWK` is a class constant**: `Jwt::TOKEN_DWK` (a namespaced `const` is not autoloadable).
   Use `Jwt::allowedDwk($typ)` for the accepted set: `aa-auth+jwt` → `['aauth-person.json']` (AS-issued auth tokens are not accepted: DreamFactory has no AS federation).
2. **Alg error codes follow spec §11.3.4**, not "always invalid_key": `Jwk::assertSupportedPublic()` throws
   `unsupported_algorithm` (+ `Accept-Signature-Alg: Ed25519, ES256`) when `alg` is absent, unknown or the
   polymorphic `EdDSA`; `invalid_key` when kty/crv disagree with `alg` or key material is malformed.
   Optional 2nd arg `$allowEdDSA` exists for tests; JWT verification and discovery never pass it (spec: MUST NOT accept EdDSA).
   `cnf.jwk` keys are always strict.
3. **`HttpSignature::verify()` ignores the RFC 9421 `alg` parameter by default**: -11 §11.3.3.2 says "verifiers MUST
   ignore it if present" (the spec's rule). An extra trailing argument
   `bool $rejectAlgParam = false` gives the demo's reject behaviour. The algorithm always comes from the key.
4. **`Discovery::__construct(HttpFetcher $http, ?\Closure $local = null, bool $allowInsecure = false)`** (3rd arg
   wired to `allow_insecure`).
   - `$local(iss, dwk, kid)`: return `['jwk' => ..., 'meta' => ...]` for our own issuer, `null` to fall through to HTTP,
     or an array without `jwk` to mean "ours but no such kid" (→ `unknown_key`). Private members are stripped.
   - Fetch results are memoized **per Discovery instance** (create one per request; the fetcher owns the real cache).
   - The single JWKS refresh on an unknown kid calls `getJsonFresh()` if the fetcher implements the new optional
     interface **`RefreshingHttpFetcher`** (`getJsonFresh(string $url): array`), else `getJson()` again. Implement it
     to skip your discovery cache (keep a per-issuer rate floor). `HttpFetcher` itself is unchanged.
   - Any non-AAuthError thrown by the fetcher becomes `401 Signature-Error: unknown_key` ("Could not fetch …").
   - `jwks_uri` must be https (http only with `$allowInsecure`); cross-origin jwks_uri is NOT restricted here: the
     fetcher must apply outbound admission (https, no private/loopback/link-local IPs, no cross-host redirects, size/time).
   - `Discovery::assertServerId()` throws `AAuthError(400, 'invalid_request', …)`, usable directly in the admin API
     (`POST person_servers`). Inside `resolve()` a bad `iss` becomes `401 invalid_jwt`.
5. **`Discovery` implements `RefreshableKeyResolver`** (new interface extending `KeyResolver` with `resolveFresh()`).
   `Jwt::verify()` calls it once when a JWT signature fails with a possibly stale key, before `invalid_jwt` (§11.4).
6. **`Jwt::verify()`** returns `decode()` + `meta` + `jwk` + **`cnf_jwk`** (the validated agent key for
   agent/person/auth tokens, `null` for resource tokens). Checks: typ first; header alg ∈ {Ed25519, ES256}
   (`none`/HS*/missing → `unsupported_algorithm`); dwk ∈ allowedDwk(typ); `iss` present; `cnf.jwk` present, public and
   supported for agent/person/auth (`invalid_jwt` / `invalid_key` / `unsupported_algorithm`); key via resolver; header alg
   must match key alg (`invalid_jwt`); signature; `exp` integer and > now, no leeway (`expired_jwt`); `iat` integer and
   ≤ now+60 (`clock_skew`); `exp − iat ≤ 3600` for person/auth tokens (`invalid_jwt`).
   It does **not** check `aud`, `ps`, `sub`, `jti`, `agent_jkt` — those are role-specific (the caller).
   All failures are 401 signature errors; at the PS, map body-parameter tokens yourself:
   `expired_jwt` → `expired_resource_token` / `expired_presented_token`, anything else → `invalid_*_token` (400).
7. **`AAuthError`**: `signature()` adds `Accept-Signature-Alg` / `Accept-Signature-Scheme: jwt` automatically for
   `unsupported_algorithm` / `unsupported_scheme`. New `AAuthError::invalidInput(array $required, $detail)` builds
   `Signature-Error: error=invalid_input, required_input=("@method" …)`. `toProblem()` adds
   `type: urn:ietf:params:sig-error:<code>` for signature errors (SK§5.2); plain errors stay `{error, detail}`.
   New `isSignatureError()`. 403 errors must be built with `new AAuthError(403, …)` (no Signature-Error, per spec).
8. **`StructuredFields`**: Tokens parse to `SfToken`, byte sequences to `SfBytes` (`->bin`); `StructuredFields::plain()`
   converts. Also `parseList`, `parseItem`, `serializeToken/Key/BareItem/Params/InnerList/Member/Dictionary`.
9. **`SignatureKey::parse($header, ?string $label = null)`** returns also `params` (plain). Selects label `sig`, else the
   only member. Codes: malformed / nothing selectable → `invalid_signature`; any scheme other than `jwt` (hwk, jwks_uri,
   x509, unknown) → `unsupported_scheme` + `Accept-Signature-Scheme: jwt`; missing/non-string `jwt` param → `invalid_key`.
10. **`HttpSignature::sign()`** returns `Content-Type`, `Content-Digest` (body only), `Signature-Key`, `Signature-Input`,
    `Signature` in that order. `@query` is covered only when listed in `$extra` (value `?` when the URL has none);
    pass `['@query']` when calling DF (the resource requires it when a query is present).
11. **`HttpSignature::verify()`** also returns `label`, `expires`, `params`, `signature` (raw bytes) and `base`.
    Key a replay cache on what was signed, `hash('sha256', $jkt . "\n" . $result['base'])`, not on the
    signature bytes (an ES256 signature has two valid encodings of the same request). Required: BASE; `content-type` +
    `content-digest` whenever the body is non-empty; `@query` when `$requireQuery` and the query is non-empty;
    `$requiredExtra`. A covered `content-digest` is verified even for an empty body. Component parameters
    (`;sf`, `;req`, …) are rejected (`invalid_signature`). Derived components supported: `@method @authority @path
    @query @request-target`. `@signature-params` is the canonical re-serialization of the parsed Signature-Input
    member (identical to the raw text for canonical senders such as the demo). It does NOT check that
    `@authority` is the issuer host and does not do replay detection (the caller).
12. **`HttpRequestParts`** lowercases header names and joins list values with `", "`; helpers `header($name)` and
    `HttpRequestParts::fromUrl($method, $url, $headers, $body)`. Pass the Host header as `authority` exactly as received.
13. **`Requirement::parse()`** returns `[]` for an empty/malformed header. `header()` uses `"; "` between parameters
    (as the spec examples), strings → SF Strings, ints, bools, `SfToken`.
14. **`InteractionCode::normalize()`** strips hyphens/whitespace, uppercases, folds I/L→1 and O→0, returns `''` if any other
    character is outside the Crockford alphabet. Added `isWellFormed()` (exactly 8 symbols) and `format()` (`XXXX-XXXX`).
15. Additions: `Jwk::generateEs256()`, `Jwk::sameKey($a, $b)`, `Jwk::member()`, `Jws::p256PublicPem/p256PrivatePem/
    derToRaw/rawToDer`, `HttpSignature::authorityOf(parse_url(...))`, constants `HttpSignature::LABEL/BODY`,
    `Jwt::CNF_TYPES`, `Jwt::IAT_LEEWAY`, `Jwt::MAX_PERSON_AUTH_LIFETIME`.

## Typical resource-side use

```php
$parts = new HttpRequestParts($_SERVER['REQUEST_METHOD'], $hostHeader,
    parse_url($_SERVER['REQUEST_URI'], PHP_URL_PATH) ?? '', ($q = $_SERVER['QUERY_STRING'] ?? '') === '' ? null : $q,
    $lowercaseHeaders, $request->getContent());
$sk  = SignatureKey::parse($parts->header('signature-key') ?? '');
$typ = Jwt::decode($sk['jwt'])['header']['typ'] ?? '';          // dispatch on typ FIRST
if (!in_array($typ, Jwt::CNF_TYPES, true)) throw AAuthError::signature('invalid_jwt', 'Unexpected token type');
$tok = Jwt::verify($sk['jwt'], $typ, new Discovery($fetcher, $localResolver, $allowInsecure), time());
$sig = HttpSignature::verify($parts, $tok['cnf_jwk'], time(), 60, requireQuery: true);
$jkt = Jwk::thumbprint($tok['cnf_jwk']);
// then: @authority == issuer host, aud == issuer for person/auth tokens, replay cache on sha256($jkt . "\n" . $sig['base']), ...
```
