<?php

namespace DreamFactory\Core\AAuth\Protocol;

/**
 * Compact JWS JWTs for AAuth tokens (§11.5). Header {alg, typ, kid}; alg "Ed25519" or "ES256" from the key.
 */
final class Jwt
{
    /** typ => the well-known document its issuer publishes (dwk). */
    public const TOKEN_DWK = [
        'aa-agent+jwt' => 'aauth-agent.json',
        'aa-person+jwt' => 'aauth-person.json',
        'aa-auth+jwt' => 'aauth-person.json',
        'aa-resource+jwt' => 'aauth-resource.json',
    ];

    /** Token types bound to an agent key via cnf.jwk. */
    public const CNF_TYPES = ['aa-agent+jwt', 'aa-person+jwt', 'aa-auth+jwt'];

    /** iat may be at most this far in the future (seconds). */
    public const IAT_LEEWAY = 60;

    /** Max exp - iat for person and auth tokens (§11.5.2). */
    public const MAX_PERSON_AUTH_LIFETIME = 3600;

    /**
     * dwk values accepted for a typ. The protocol also allows AS-issued auth tokens
     * (dwk aauth-access.json), but DreamFactory federates with no access server, so only person
     * server documents are accepted: an AS-style token would otherwise be verified against keys
     * published by whoever wrote its iss.
     */
    public static function allowedDwk(string $typ): array
    {
        return isset(self::TOKEN_DWK[$typ]) ? [self::TOKEN_DWK[$typ]] : [];
    }

    public static function sign(string $typ, array $payload, array $privateJwk): string
    {
        $header = ['alg' => Jwk::algOf($privateJwk), 'typ' => $typ];
        if (isset($privateJwk['kid'])) {
            $header['kid'] = $privateJwk['kid'];
        }
        $input = B64::url(self::json($header)) . '.' . B64::url(self::json($payload));
        return $input . '.' . B64::url(Jws::sign($input, $privateJwk));
    }

    /**
     * ['header' => [], 'payload' => [], 'input' => 'h.p', 'sig' => binary]. Malformed => invalid_jwt.
     * Does not verify anything.
     */
    public static function decode(string $jwt): array
    {
        $parts = explode('.', $jwt);
        if (count($parts) !== 3 || $parts[0] === '' || $parts[1] === '' || $parts[2] === '') {
            throw AAuthError::signature('invalid_jwt', 'Malformed JWT');
        }
        try {
            $hJson = B64::urlDecode($parts[0]);
            $pJson = B64::urlDecode($parts[1]);
            $sig = B64::urlDecode($parts[2]);
            $header = json_decode($hJson, true, 32, JSON_THROW_ON_ERROR);
            $payload = json_decode($pJson, true, 32, JSON_THROW_ON_ERROR);
        } catch (\InvalidArgumentException|\JsonException) {
            throw AAuthError::signature('invalid_jwt', 'Malformed JWT');
        }
        if (!is_array($header) || !is_array($payload) || !self::isObject($hJson) || !self::isObject($pJson)) {
            throw AAuthError::signature('invalid_jwt', 'Malformed JWT: header and payload must be JSON objects');
        }
        return ['header' => $header, 'payload' => $payload, 'input' => $parts[0] . '.' . $parts[1], 'sig' => $sig];
    }

    /**
     * Full verification (§11.5.2): typ (checked first), alg, dwk, iss, cnf.jwk presence for bound types,
     * issuer key via $keys, alg/key agreement, signature (one refresh via RefreshableKeyResolver),
     * exp (no leeway), iat (required; at most 60 s in the future => clock_skew), exp - iat <= 1h for
     * person/auth tokens.
     *
     * Returns decode() + 'meta' (issuer metadata) + 'jwk' (issuer signing key) + 'cnf_jwk' (bound agent key or null).
     * All failures are AAuthError::signature(...) (401 + Signature-Error); callers validating tokens carried in a
     * body parameter map them to their own codes (e.g. invalid_presented_token).
     */
    public static function verify(string $jwt, string $expectedTyp, KeyResolver $keys, int $now): array
    {
        $d = self::decode($jwt);
        $h = $d['header'];
        $p = $d['payload'];

        if (($h['typ'] ?? null) !== $expectedTyp) {
            $got = is_string($h['typ'] ?? null) ? $h['typ'] : '(none)';
            throw AAuthError::signature('invalid_jwt', "Expected typ {$expectedTyp}, got {$got}");
        }
        $alg = $h['alg'] ?? null;
        // fully specified algorithms only: the polymorphic "EdDSA" MUST NOT be accepted
        if (!in_array($alg, ['Ed25519', 'ES256'], true)) {
            $shown = is_string($alg) ? $alg : '(none)';
            throw AAuthError::signature('unsupported_algorithm', "JWT alg \"{$shown}\" is not accepted");
        }
        $dwk = $p['dwk'] ?? null;
        if (!is_string($dwk) || !in_array($dwk, self::allowedDwk($expectedTyp), true)) {
            throw AAuthError::signature('invalid_jwt', "Unexpected dwk for {$expectedTyp}");
        }
        $iss = $p['iss'] ?? null;
        if (!is_string($iss) || $iss === '') {
            throw AAuthError::signature('invalid_jwt', 'JWT has no iss');
        }
        $cnf = null;
        if (in_array($expectedTyp, self::CNF_TYPES, true)) {
            $cnf = self::cnfJwk($p);
        }
        $kid = $h['kid'] ?? null;
        if ($kid !== null && !is_string($kid)) {
            throw AAuthError::signature('invalid_jwt', 'JWT kid must be a string');
        }

        $resolved = $keys->resolve($iss, $dwk, $kid);
        self::checkSignature($d, $resolved['jwk'], $alg, $keys instanceof RefreshableKeyResolver
            ? fn () => $keys->resolveFresh($iss, $dwk, $kid)
            : null, $resolved);

        $exp = $p['exp'] ?? null;
        if (!is_int($exp)) {
            throw AAuthError::signature('invalid_jwt', 'JWT exp missing or not an integer');
        }
        if ($exp <= $now) {
            throw AAuthError::signature('expired_jwt', 'Token has expired');
        }
        $iat = $p['iat'] ?? null;
        if (!is_int($iat)) {
            throw AAuthError::signature('invalid_jwt', 'JWT iat missing or not an integer');
        }
        if ($iat > $now + self::IAT_LEEWAY) {
            throw AAuthError::signature('clock_skew', 'Token iat is in the future');
        }
        if (in_array($expectedTyp, ['aa-person+jwt', 'aa-auth+jwt'], true) && $exp - $iat > self::MAX_PERSON_AUTH_LIFETIME) {
            throw AAuthError::signature('invalid_jwt', 'Token lifetime exceeds 1 hour');
        }

        return $d + ['meta' => $resolved['meta'] ?? [], 'jwk' => $resolved['jwk'], 'cnf_jwk' => $cnf];
    }

    /**
     * Extract and validate payload cnf.jwk (structurally complete, alg present and supported; strict, no EdDSA).
     * Missing => invalid_jwt; bad key => invalid_key / unsupported_algorithm.
     */
    public static function cnfJwk(array $payload): array
    {
        $jwk = $payload['cnf']['jwk'] ?? null;
        if (!is_array($jwk) || $jwk === []) {
            throw AAuthError::signature('invalid_jwt', 'Token has no cnf.jwk');
        }
        if (array_key_exists('d', $jwk)) {
            throw AAuthError::signature('invalid_key', 'cnf.jwk must be a public key');
        }
        Jwk::assertSupportedPublic($jwk);
        return $jwk;
    }

    private static function checkSignature(array $d, array $jwk, string $headerAlg, ?\Closure $refresh, array &$resolved): void
    {
        $keyAlg = Jwk::algOf($jwk);
        if ($keyAlg !== $headerAlg) {
            throw AAuthError::signature('invalid_jwt', "JWT alg {$headerAlg} does not match the key alg {$keyAlg}");
        }
        if (Jws::verify($d['input'], $d['sig'], $jwk)) {
            return;
        }
        if ($refresh !== null) {
            $fresh = $refresh();
            if (!Jwk::sameKey($fresh['jwk'], $jwk)) {
                $resolved = $fresh;
                self::checkSignature($d, $fresh['jwk'], $headerAlg, null, $resolved);
                return;
            }
        }
        throw AAuthError::signature('invalid_jwt', 'JWT signature is invalid');
    }

    private static function isObject(string $json): bool
    {
        return str_starts_with(ltrim($json), '{');
    }

    private static function json(array $v): string
    {
        return json_encode($v, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_THROW_ON_ERROR);
    }
}
