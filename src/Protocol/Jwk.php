<?php

namespace DreamFactory\Core\AAuth\Protocol;

/**
 * JWK helpers. Supported: OKP/Ed25519 (alg "Ed25519", MUST) and EC/P-256 (alg "ES256", SHOULD).
 * The algorithm always comes from the key's `alg` (§11.3.1); kty/crv must agree with it.
 */
final class Jwk
{
    private const PRIVATE_MEMBERS = ['d', 'p', 'q', 'dp', 'dq', 'qi', 'oth', 'k'];

    /** Private JWK: kty OKP, crv Ed25519, x, d (32-byte seed), alg Ed25519, kid = first 16 chars of the thumbprint. */
    public static function generateEd25519(): array
    {
        $kp = sodium_crypto_sign_keypair();
        $sk = sodium_crypto_sign_secretkey($kp);
        $jwk = [
            'kty' => 'OKP',
            'crv' => 'Ed25519',
            'x' => B64::url(sodium_crypto_sign_publickey($kp)),
            'd' => B64::url(substr($sk, 0, 32)),
            'alg' => 'Ed25519',
        ];
        sodium_memzero($sk);
        $jwk['kid'] = substr(self::thumbprint($jwk), 0, 16);
        return $jwk;
    }

    /** Private JWK for P-256: kty EC, crv P-256, x, y, d, alg ES256, kid = first 16 chars of the thumbprint. */
    public static function generateEs256(): array
    {
        $key = openssl_pkey_new(['private_key_type' => OPENSSL_KEYTYPE_EC, 'curve_name' => 'prime256v1']);
        if ($key === false) {
            throw new \RuntimeException('openssl could not generate a P-256 key');
        }
        $ec = openssl_pkey_get_details($key)['ec'];
        $pad = fn (string $b) => str_pad($b, 32, "\0", STR_PAD_LEFT);
        $jwk = [
            'kty' => 'EC',
            'crv' => 'P-256',
            'x' => B64::url($pad($ec['x'])),
            'y' => B64::url($pad($ec['y'])),
            'd' => B64::url($pad($ec['d'])),
            'alg' => 'ES256',
        ];
        $jwk['kid'] = substr(self::thumbprint($jwk), 0, 16);
        return $jwk;
    }

    /** Strips private members (d, and RSA/oct private parts). */
    public static function publicOf(array $jwk): array
    {
        foreach (self::PRIVATE_MEMBERS as $m) {
            unset($jwk[$m]);
        }
        return $jwk;
    }

    /** RFC 7638 thumbprint, base64url(sha256) without padding. OKP (crv,kty,x), EC (crv,kty,x,y), RSA (e,kty,n). */
    public static function thumbprint(array $jwk): string
    {
        $kty = $jwk['kty'] ?? null;
        $req = match ($kty) {
            'OKP' => ['crv', 'kty', 'x'],
            'EC' => ['crv', 'kty', 'x', 'y'],
            'RSA' => ['e', 'kty', 'n'],
            default => throw AAuthError::signature('invalid_key', 'Unsupported or missing JWK kty'),
        };
        $canon = [];
        foreach ($req as $m) {
            if (!isset($jwk[$m]) || !is_string($jwk[$m]) || $jwk[$m] === '') {
                throw AAuthError::signature('invalid_key', "JWK is missing \"{$m}\"");
            }
            $canon[$m] = $jwk[$m];
        }
        return B64::url(hash('sha256', json_encode($canon, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_THROW_ON_ERROR), true));
    }

    /** True when both JWKs have the same RFC 7638 thumbprint. */
    public static function sameKey(array $a, array $b): bool
    {
        try {
            return hash_equals(self::thumbprint($a), self::thumbprint($b));
        } catch (AAuthError) {
            return false;
        }
    }

    /**
     * Validate a public key we will verify with.
     *  - alg absent / unknown / polymorphic ("EdDSA")  => unsupported_algorithm (+ Accept-Signature-Alg)
     *  - kty/crv disagree with alg, or malformed key material => invalid_key
     * $allowEdDSA: accept alg "EdDSA" on an OKP/Ed25519 key (used only for issuer JWKS keys when verifying JWTs).
     */
    public static function assertSupportedPublic(array $jwk, bool $allowEdDSA = false): void
    {
        self::algOf($jwk, $allowEdDSA);
    }

    /** 'Ed25519' | 'ES256'. Validates the key like assertSupportedPublic(). */
    public static function algOf(array $jwk, bool $allowEdDSA = false): string
    {
        $alg = $jwk['alg'] ?? null;
        if (!is_string($alg) || $alg === '') {
            throw AAuthError::signature('unsupported_algorithm', 'JWK has no "alg"');
        }
        if ($alg === 'EdDSA' && $allowEdDSA) {
            $alg = 'Ed25519';
        }
        $kty = $jwk['kty'] ?? null;
        $crv = $jwk['crv'] ?? null;
        switch ($alg) {
            case 'Ed25519':
                if ($kty !== 'OKP' || $crv !== 'Ed25519') {
                    throw AAuthError::signature('invalid_key', 'JWK kty/crv do not match alg Ed25519');
                }
                self::assertMember($jwk, 'x', 32);
                if (isset($jwk['d'])) {
                    self::assertMember($jwk, 'd', 32);
                }
                return 'Ed25519';
            case 'ES256':
                if ($kty !== 'EC' || $crv !== 'P-256') {
                    throw AAuthError::signature('invalid_key', 'JWK kty/crv do not match alg ES256');
                }
                self::assertMember($jwk, 'x', 32);
                self::assertMember($jwk, 'y', 32);
                if (isset($jwk['d'])) {
                    self::assertMember($jwk, 'd', 32);
                }
                return 'ES256';
            default:
                throw AAuthError::signature('unsupported_algorithm', "JWK alg \"{$alg}\" is not supported");
        }
    }

    /** Decoded key member of an exact byte length, or invalid_key. */
    public static function member(array $jwk, string $name, int $len): string
    {
        self::assertMember($jwk, $name, $len);
        return B64::urlDecode($jwk[$name]);
    }

    private static function assertMember(array $jwk, string $name, int $len): void
    {
        $v = $jwk[$name] ?? null;
        try {
            $ok = is_string($v) && strlen(B64::urlDecode($v)) === $len;
        } catch (\InvalidArgumentException) {
            $ok = false;
        }
        if (!$ok) {
            throw AAuthError::signature('invalid_key', "JWK \"{$name}\" is not a {$len}-byte base64url value");
        }
    }
}
