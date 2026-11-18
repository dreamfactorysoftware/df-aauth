<?php

namespace DreamFactory\Core\AAuth\Protocol;

/**
 * Base64 helpers. JWT parts, JWK members, thumbprints: base64url without padding.
 * Structured Field byte sequences (Signature, Content-Digest): standard base64 with padding.
 */
final class B64
{
    public static function url(string $bin): string
    {
        return rtrim(strtr(base64_encode($bin), '+/', '-_'), '=');
    }

    /** Strict base64url decode (padding optional). Throws \InvalidArgumentException on bad input. */
    public static function urlDecode(string $s): string
    {
        if ($s !== '' && !preg_match('/^[A-Za-z0-9_-]+={0,2}$/', $s)) {
            throw new \InvalidArgumentException('Invalid base64url');
        }
        $s = rtrim($s, '=');
        if (strlen($s) % 4 === 1) {
            throw new \InvalidArgumentException('Invalid base64url length');
        }
        $out = base64_decode(strtr($s, '-_', '+/'), true);
        if ($out === false) {
            throw new \InvalidArgumentException('Invalid base64url');
        }
        return $out;
    }

    public static function std(string $bin): string
    {
        return base64_encode($bin);
    }

    /** Strict standard base64 decode (padding optional). Throws \InvalidArgumentException on bad input. */
    public static function stdDecode(string $s): string
    {
        if ($s !== '' && !preg_match('/^[A-Za-z0-9+\/]+={0,2}$/', $s)) {
            throw new \InvalidArgumentException('Invalid base64');
        }
        if (strlen(rtrim($s, '=')) % 4 === 1) {
            throw new \InvalidArgumentException('Invalid base64 length');
        }
        $out = base64_decode($s, true);
        if ($out === false) {
            throw new \InvalidArgumentException('Invalid base64');
        }
        return $out;
    }
}
