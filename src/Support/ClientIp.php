<?php

namespace DreamFactory\Core\AAuth\Support;

use Illuminate\Http\Request;

/**
 * The client address for AAuth rate limits. DreamFactory's own TrustProxies setup is left alone;
 * X-Forwarded-For is honoured only when the direct peer (REMOTE_ADDR) is listed in
 * df-aauth.trusted_proxies (DF_AAUTH_TRUSTED_PROXIES: comma separated IPs or CIDRs, e.g. the
 * docker gateway in front of which a TLS proxy runs). The right-most untrusted hop wins, so a
 * client cannot forge its address by sending its own X-Forwarded-For.
 */
final class ClientIp
{
    public static function of(?Request $request = null): string
    {
        $request ??= self::current();
        $peer = (string)($request?->server('REMOTE_ADDR') ?? ($_SERVER['REMOTE_ADDR'] ?? ''));
        $trusted = self::trusted();
        if ($peer === '' || !$trusted || !self::inList($peer, $trusted)) {
            return $peer;
        }
        $xff = (string)($request?->headers->get('X-Forwarded-For') ?? '');
        if ($xff === '') {
            return $peer;
        }
        $hops = array_values(array_filter(array_map('trim', explode(',', $xff)), fn ($h) => $h !== ''));
        for ($i = count($hops) - 1; $i >= 0; $i--) {
            $hop = trim($hops[$i], '[]');
            if (!filter_var($hop, FILTER_VALIDATE_IP)) {
                return $peer;
            }
            if (!self::inList($hop, $trusted)) {
                return $hop;
            }
        }

        return $peer;
    }

    /** @return string[] */
    public static function trusted(): array
    {
        $raw = config('df-aauth.trusted_proxies', '');
        $list = is_array($raw) ? $raw : explode(',', (string)$raw);

        return array_values(array_filter(array_map('trim', $list), fn ($x) => $x !== ''));
    }

    public static function inList(string $ip, array $list): bool
    {
        foreach ($list as $entry) {
            if (self::matches($ip, $entry)) {
                return true;
            }
        }

        return false;
    }

    public static function matches(string $ip, string $cidr): bool
    {
        if (!str_contains($cidr, '/')) {
            return @inet_pton($ip) !== false && @inet_pton($ip) === @inet_pton($cidr);
        }
        [$net, $bits] = explode('/', $cidr, 2);
        $a = @inet_pton($ip);
        $b = @inet_pton($net);
        if ($a === false || $b === false || strlen($a) !== strlen($b) || !ctype_digit($bits)) {
            return false;
        }
        $bits = (int)$bits;
        if ($bits > strlen($a) * 8) {
            return false;
        }
        $bytes = intdiv($bits, 8);
        if (strncmp($a, $b, $bytes) !== 0) {
            return false;
        }
        $rest = $bits % 8;
        if ($rest === 0) {
            return true;
        }
        $mask = (0xff << (8 - $rest)) & 0xff;

        return (ord($a[$bytes]) & $mask) === (ord($b[$bytes]) & $mask);
    }

    private static function current(): ?Request
    {
        try {
            return function_exists('request') && function_exists('app') && app()->bound('request') ? request() : null;
        } catch (\Throwable $e) {
            return null;
        }
    }
}
