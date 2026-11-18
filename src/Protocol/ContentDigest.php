<?php

namespace DreamFactory\Core\AAuth\Protocol;

/** RFC 9530 Content-Digest. */
final class ContentDigest
{
    /** "sha-256=:<std base64>:" */
    public static function sha256(string $body): string
    {
        return 'sha-256=:' . base64_encode(hash('sha256', $body, true)) . ':';
    }

    /**
     * True when the header carries a sha-256 (or sha-512) digest matching $body. Every supported digest present
     * must match; unsupported algorithms are ignored; at least one supported digest is required.
     * Malformed headers => false.
     */
    public static function verify(string $header, string $body): bool
    {
        try {
            $dict = StructuredFields::parseDictionary($header);
        } catch (\InvalidArgumentException) {
            return false;
        }
        $algos = ['sha-256' => 'sha256', 'sha-512' => 'sha512'];
        $checked = 0;
        foreach ($algos as $label => $algo) {
            if (!isset($dict[$label])) {
                continue;
            }
            $v = $dict[$label]['value'] ?? null;
            if (!$v instanceof SfBytes || !hash_equals(hash($algo, $body, true), $v->bin)) {
                return false;
            }
            $checked++;
        }
        return $checked > 0;
    }
}
