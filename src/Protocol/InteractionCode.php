<?php

namespace DreamFactory\Core\AAuth\Protocol;

/** Interaction codes (§11.6.3.1): Crockford base32, 8 symbols (40 bits), displayed XXXX-XXXX. */
final class InteractionCode
{
    public const ALPHABET = '0123456789ABCDEFGHJKMNPQRSTVWXYZ';

    public static function generate(): string
    {
        $s = '';
        for ($i = 0; $i < 8; $i++) {
            $s .= self::ALPHABET[random_int(0, 31)];
        }
        return substr($s, 0, 4) . '-' . substr($s, 4);
    }

    /**
     * Canonical comparison form: hyphens and whitespace removed, uppercased, I/L folded to 1 and O to 0.
     * Returns '' when the result contains a character outside the alphabet.
     */
    public static function normalize(string $c): string
    {
        $c = strtoupper(preg_replace('/[\s-]+/', '', $c) ?? '');
        $c = strtr($c, ['I' => '1', 'L' => '1', 'O' => '0']);
        return preg_match('/^[0-9A-HJKMNP-TV-Z]+$/', $c) ? $c : '';
    }

    /** True when $c normalizes to exactly 8 symbols. */
    public static function isWellFormed(string $c): bool
    {
        return strlen(self::normalize($c)) === 8;
    }

    /** Normalized 8-symbol code => display form XXXX-XXXX. */
    public static function format(string $normalized): string
    {
        $n = self::normalize($normalized);
        return strlen($n) === 8 ? substr($n, 0, 4) . '-' . substr($n, 4) : $n;
    }
}
