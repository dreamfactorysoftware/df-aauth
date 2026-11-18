<?php

namespace DreamFactory\Core\AAuth\Protocol;

/**
 * Raw JOSE signatures (RFC 9421 §3.3.7 / RFC 7515): Ed25519 via sodium, ES256 via openssl with raw R||S (64 bytes).
 */
final class Jws
{
    // SubjectPublicKeyInfo prefix for an uncompressed P-256 point (id-ecPublicKey + prime256v1).
    private const P256_SPKI_PREFIX = '3059301306072a8648ce3d020106082a8648ce3d030107034200';

    /** Raw signature bytes. */
    public static function sign(string $input, array $privateJwk): string
    {
        $alg = Jwk::algOf($privateJwk);
        if (!isset($privateJwk['d'])) {
            throw AAuthError::signature('invalid_key', 'Signing requires a private JWK');
        }
        if ($alg === 'Ed25519') {
            $seed = Jwk::member($privateJwk, 'd', 32);
            $kp = sodium_crypto_sign_seed_keypair($seed);
            if (!hash_equals(sodium_crypto_sign_publickey($kp), Jwk::member($privateJwk, 'x', 32))) {
                throw AAuthError::signature('invalid_key', 'JWK x does not match d');
            }
            $sk = sodium_crypto_sign_secretkey($kp);
            $sig = sodium_crypto_sign_detached($input, $sk);
            sodium_memzero($sk);
            return $sig;
        }
        $pem = self::p256PrivatePem($privateJwk);
        $der = '';
        if (!openssl_sign($input, $der, $pem, OPENSSL_ALGO_SHA256)) {
            throw new \RuntimeException('openssl_sign failed');
        }
        return self::derToRaw($der, 32);
    }

    public static function verify(string $input, string $sig, array $publicJwk): bool
    {
        try {
            $alg = Jwk::algOf($publicJwk, true);
        } catch (AAuthError) {
            return false;
        }
        if ($alg === 'Ed25519') {
            if (strlen($sig) !== SODIUM_CRYPTO_SIGN_BYTES) {
                return false;
            }
            try {
                return sodium_crypto_sign_verify_detached($sig, $input, Jwk::member($publicJwk, 'x', 32));
            } catch (\SodiumException) {
                return false;
            }
        }
        if (strlen($sig) !== 64) {
            return false;
        }
        $pub = openssl_pkey_get_public(self::p256PublicPem($publicJwk));
        if ($pub === false) {
            return false;
        }
        return openssl_verify($input, self::rawToDer($sig), $pub, OPENSSL_ALGO_SHA256) === 1;
    }

    public static function p256PublicPem(array $jwk): string
    {
        $point = "\x04" . Jwk::member($jwk, 'x', 32) . Jwk::member($jwk, 'y', 32);
        $der = hex2bin(self::P256_SPKI_PREFIX) . $point;
        return "-----BEGIN PUBLIC KEY-----\n" . chunk_split(base64_encode($der), 64, "\n") . "-----END PUBLIC KEY-----\n";
    }

    /** SEC1 ECPrivateKey (RFC 5915) PEM for a P-256 JWK. */
    public static function p256PrivatePem(array $jwk): string
    {
        $d = Jwk::member($jwk, 'd', 32);
        $point = "\x04" . Jwk::member($jwk, 'x', 32) . Jwk::member($jwk, 'y', 32);
        $der = "\x30\x77" . "\x02\x01\x01" . "\x04\x20" . $d
            . "\xa0\x0a\x06\x08" . hex2bin('2a8648ce3d030107')
            . "\xa1\x44\x03\x42\x00" . $point;
        return "-----BEGIN EC PRIVATE KEY-----\n" . chunk_split(base64_encode($der), 64, "\n") . "-----END EC PRIVATE KEY-----\n";
    }

    /** DER ECDSA-Sig-Value => raw R||S. */
    public static function derToRaw(string $der, int $partLen): string
    {
        $pos = 0;
        $readLen = function () use ($der, &$pos): int {
            $l = ord($der[$pos++] ?? "\0");
            if ($l & 0x80) {
                $n = $l & 0x7f;
                $l = 0;
                for ($i = 0; $i < $n; $i++) {
                    $l = ($l << 8) | ord($der[$pos++] ?? "\0");
                }
            }
            return $l;
        };
        if (($der[$pos++] ?? '') !== "\x30") {
            throw new \InvalidArgumentException('Bad DER signature');
        }
        $readLen();
        $out = '';
        for ($k = 0; $k < 2; $k++) {
            if (($der[$pos++] ?? '') !== "\x02") {
                throw new \InvalidArgumentException('Bad DER signature');
            }
            $l = $readLen();
            $int = ltrim(substr($der, $pos, $l), "\0");
            $pos += $l;
            if (strlen($int) > $partLen) {
                throw new \InvalidArgumentException('Bad DER signature');
            }
            $out .= str_pad($int, $partLen, "\0", STR_PAD_LEFT);
        }
        return $out;
    }

    /** Raw R||S => DER ECDSA-Sig-Value. */
    public static function rawToDer(string $raw): string
    {
        $half = intdiv(strlen($raw), 2);
        $enc = function (string $int): string {
            $int = ltrim($int, "\0");
            if ($int === '' || (ord($int[0]) & 0x80)) {
                $int = "\0" . $int;
            }
            return "\x02" . chr(strlen($int)) . $int;
        };
        $body = $enc(substr($raw, 0, $half)) . $enc(substr($raw, $half));
        return "\x30" . chr(strlen($body)) . $body;
    }
}
