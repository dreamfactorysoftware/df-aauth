<?php

namespace DreamFactory\Core\AAuth\Resource;

use DreamFactory\Core\AAuth\Protocol\AAuthError;
use DreamFactory\Core\AAuth\Protocol\HttpRequestParts;
use DreamFactory\Core\AAuth\Protocol\HttpSignature;
use DreamFactory\Core\AAuth\Protocol\Jwk;
use DreamFactory\Core\AAuth\Protocol\Jwt;
use DreamFactory\Core\AAuth\Protocol\SignatureKey;
use DreamFactory\Core\AAuth\Support\AAuth;
use DreamFactory\Core\AAuth\Support\Settings;
use DreamFactory\Core\AAuth\Support\Store;

/**
 * Verifies an AAuth-signed request (RFC 9421 + Signature-Key `jwt` scheme), in this order:
 * signature headers present, @authority is our issuer, Signature-Key parses (jwt scheme), token typ
 * is acceptable (checked FIRST), token verifies (discovery, kid, signature, exp/iat), cnf.jwk is a
 * supported key, the HTTP signature verifies with cnf.jwk, and a non-GET/HEAD request is not a
 * replay within the window (same key, same signature base). Throws AAuthError (401 +
 * Signature-Error) on failure; $preCheck may throw any AAuthError (e.g. 403) after the typ check and
 * before the token is verified.
 *
 * @return array{typ: string, claims: array, header: array, jwk: array, jkt: string, meta: array, jwt: string, components: array}
 */
final class RequestVerifier
{
    public const AGENT = 'aa-agent+jwt';
    public const PERSON = 'aa-person+jwt';
    public const AUTH = 'aa-auth+jwt';
    public const RESOURCE = 'aa-resource+jwt';

    public static function verify(HttpRequestParts $parts, array $typs, bool $requireQuery = false, ?\Closure $preCheck = null): array
    {
        $h = $parts->headers;
        foreach (['signature', 'signature-input', 'signature-key'] as $name) {
            if (!isset($h[$name]) || trim($h[$name]) === '') {
                throw AAuthError::signature('invalid_signature', "Missing $name header.");
            }
        }
        $issuer = Settings::issuer();
        if (strtolower($parts->authority) !== Settings::issuerAuthority()) {
            throw AAuthError::signature('invalid_signature', "Use $issuer");
        }

        $sk = SignatureKey::parse($h['signature-key']);
        if (($sk['scheme'] ?? '') !== 'jwt' || empty($sk['jwt'])) {
            throw AAuthError::signature('unsupported_scheme', 'Agents must use the jwt scheme.', ['Accept-Signature-Scheme' => 'jwt']);
        }
        $jwt = (string)$sk['jwt'];
        $decoded = Jwt::decode($jwt);
        $typ = (string)($decoded['header']['typ'] ?? '');
        if (!in_array($typ, $typs, true)) {
            throw AAuthError::signature('invalid_jwt', $typ === '' ? 'The token has no typ.' : "A $typ is not accepted here.");
        }
        if ($preCheck !== null) {
            // policy checks on the (not yet verified) claims that can only reject, e.g. an untrusted
            // person server: answered before any discovery fetch to that issuer
            $preCheck($typ, (array)($decoded['payload'] ?? []));
        }
        $now = AAuth::now();
        $verified = Jwt::verify($jwt, $typ, AAuth::discovery(), $now);
        $claims = $verified['payload'];
        $cnf = $verified['cnf_jwk'] ?? ($claims['cnf']['jwk'] ?? null);
        if (!is_array($cnf)) {
            throw AAuthError::signature('invalid_jwt', 'The token has no cnf.jwk.');
        }
        Jwk::assertSupportedPublic($cnf);

        $window = (int)config('df-aauth.signature_window', 60);
        $sig = HttpSignature::verify($parts, $cnf, $now, $window, $requireQuery);
        $jkt = Jwk::thumbprint($cnf);

        if (!in_array(strtoupper($parts->method), ['GET', 'HEAD'], true)) {
            // Keyed on what was signed (key + signature base), not the signature bytes: ECDSA
            // signatures are malleable ((r, s) and (r, n - s) both verify), so an ES256 request
            // keyed on its bytes could be replayed once with the twin signature. Ed25519 is
            // deterministic, so for it nothing changes.
            $key = 'aauth:sig:' . hash('sha256', $jkt . "\n" . $sig['base']);
            $fresh = true;
            try {
                $fresh = Store::cache()->add($key, 1, max(1, $window * 2));
            } catch (\Throwable $e) {
                // no cache: replay protection degrades to the created window
            }
            if (!$fresh) {
                throw AAuthError::signature('invalid_signature', 'This signature was already used.');
            }
        }

        return [
            'typ' => $typ,
            'claims' => $claims,
            'header' => $verified['header'] ?? $decoded['header'],
            'jwk' => $cnf,
            'jkt' => $jkt,
            'meta' => is_array($verified['meta'] ?? null) ? $verified['meta'] : [],
            'jwt' => $jwt,
            'components' => $sig['components'] ?? [],
        ];
    }

    /** Verifies a token passed as a value (body parameter), for the PS checks. */
    public static function token(string $jwt, array $typs): array
    {
        $decoded = Jwt::decode($jwt);
        $typ = (string)($decoded['header']['typ'] ?? '');
        if (!in_array($typ, $typs, true)) {
            throw AAuthError::signature('invalid_jwt', "Unexpected token type '$typ'.");
        }
        $verified = Jwt::verify($jwt, $typ, AAuth::discovery(), AAuth::now());
        $verified['typ'] = $typ;

        return $verified;
    }
}
