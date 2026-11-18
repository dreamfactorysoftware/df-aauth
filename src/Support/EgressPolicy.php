<?php

namespace DreamFactory\Core\AAuth\Support;

/**
 * Which non-public addresses discovery fetches may reach (signature-key SK§7.3: private, loopback
 * and link-local destinations are refused "unless explicitly allowed by deployment configuration").
 *
 * Public (globally routable) addresses are always admitted. On top of that an admin may allow:
 *  - DF_AAUTH_PRIVATE_HOSTS: comma separated hostnames, exact (agents.corp.internal) or with a
 *    leading "*." (*.corp.internal: any subdomain, not corp.internal itself). These hosts may
 *    resolve to private-use addresses: 10/8, 172.16/12, 192.168/16, 100.64/10 (CGNAT) and IPv6
 *    unique local fc00::/7. Not loopback.
 *  - DF_AAUTH_PRIVATE_NETWORKS: comma separated CIDRs or single addresses (10.20.0.0/16,
 *    fd12:3456::/48, 127.0.0.1). Any host resolving inside them is admitted, loopback included.
 * Either list admits an address. Whatever is listed, these are never reachable: link-local
 * 169.254.0.0/16 (cloud metadata 169.254.169.254) and fe80::/10, AWS IMDS fd00:ec2::/32, Alibaba
 * metadata 100.100.100.200, 0.0.0.0/8 and ::, multicast, broadcast and 240.0.0.0/4, including
 * the same addresses written as IPv4-mapped, IPv4-compatible, NAT64 or 6to4 IPv6.
 * Defaults (both empty) keep public-only egress.
 */
final class EgressPolicy
{
    /** IPv4 ranges no setting can open. */
    private const DENY_V4 = [['0.0.0.0', 8], ['169.254.0.0', 16], ['100.100.100.200', 32], ['224.0.0.0', 4], ['240.0.0.0', 4]];
    /** IPv6 ranges no setting can open. */
    private const DENY_V6 = ['::/128', 'fe80::/10', 'fd00:ec2::/32', 'ff00::/8'];
    /** Private-use ranges a listed hostname may resolve to. */
    private const PRIVATE_V4 = [['10.0.0.0', 8], ['172.16.0.0', 12], ['192.168.0.0', 16], ['100.64.0.0', 10]];
    private const PRIVATE_V6 = ['fc00::/7'];

    /**
     * @param string[] $hosts    normalized patterns: "host" or "*.suffix"
     * @param string[] $networks CIDRs or single addresses
     */
    public function __construct(private array $hosts = [], private array $networks = [])
    {
    }

    public static function fromConfig(): self
    {
        return new self(
            self::parseHosts(config('df-aauth.private_hosts', '')),
            self::parseNetworks(config('df-aauth.private_networks', '')),
        );
    }

    /** @return string[] valid host patterns (invalid entries are dropped) */
    public static function parseHosts(mixed $raw): array
    {
        $out = [];
        foreach (self::items($raw) as $h) {
            $h = rtrim(strtolower($h), '.');
            $bare = str_starts_with($h, '*.') ? substr($h, 2) : $h;
            if ($bare === '' || str_contains($bare, '*') || !preg_match('/^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)*$/', $bare)) {
                continue;
            }
            $out[] = $h;
        }

        return array_values(array_unique($out));
    }

    /** @return string[] valid CIDRs / addresses (invalid entries are dropped) */
    public static function parseNetworks(mixed $raw): array
    {
        $out = [];
        foreach (self::items($raw) as $n) {
            [$ip, $bits] = array_pad(explode('/', $n, 2), 2, null);
            $bin = @inet_pton((string)$ip);
            if ($bin === false) {
                continue;
            }
            if ($bits !== null && (!ctype_digit($bits) || (int)$bits > strlen($bin) * 8)) {
                continue;
            }
            $out[] = $n;
        }

        return array_values(array_unique($out));
    }

    public function isEmpty(): bool
    {
        return $this->hosts === [] && $this->networks === [];
    }

    /** @return array{hosts: string[], networks: string[]} */
    public function toArray(): array
    {
        return ['hosts' => $this->hosts, 'networks' => $this->networks];
    }

    /** True when $host matches DF_AAUTH_PRIVATE_HOSTS. */
    public function hostListed(string $host): bool
    {
        $host = rtrim(strtolower(trim($host, '[]')), '.');
        foreach ($this->hosts as $pattern) {
            if (str_starts_with($pattern, '*.')) {
                $suffix = substr($pattern, 1); // ".corp.internal"
                if (str_ends_with($host, $suffix) && strlen($host) > strlen($suffix)) {
                    return true;
                }
            } elseif ($host === $pattern) {
                return true;
            }
        }

        return false;
    }

    /** May a fetch for $host connect to the non-public address $ip? (Public addresses never ask.) */
    public function admits(string $host, string $ip): bool
    {
        if (self::isForbidden($ip)) {
            return false;
        }
        $forms = array_values(array_filter([$ip, self::embeddedV4($ip)]));
        foreach ($this->networks as $net) {
            foreach ($forms as $form) {
                if (ClientIp::matches($form, $net)) {
                    return true;
                }
            }
        }
        if ($this->hostListed($host)) {
            foreach ($forms as $form) {
                if (self::isPrivateUse($form)) {
                    return true;
                }
            }
        }

        return false;
    }

    /** Link-local, metadata, unspecified, multicast and reserved addresses: refused whatever the config says. */
    public static function isForbidden(string $ip): bool
    {
        if (!filter_var($ip, FILTER_VALIDATE_IP)) {
            return true;
        }
        $v4 = filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) ? $ip : self::embeddedV4($ip);
        if ($v4 !== null) {
            foreach (self::DENY_V4 as [$net, $bits]) {
                if (ClientIp::matches($v4, "$net/$bits")) {
                    return true;
                }
            }
            if ($v4 === $ip) {
                return false;
            }
        }
        foreach (self::DENY_V6 as $cidr) {
            if (ClientIp::matches($ip, $cidr)) {
                return true;
            }
        }

        return false;
    }

    public static function isPrivateUse(string $ip): bool
    {
        if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
            foreach (self::PRIVATE_V4 as [$net, $bits]) {
                if (ClientIp::matches($ip, "$net/$bits")) {
                    return true;
                }
            }

            return false;
        }
        foreach (self::PRIVATE_V6 as $cidr) {
            if (ClientIp::matches($ip, $cidr)) {
                return true;
            }
        }

        return false;
    }

    /**
     * The IPv4 address an IPv6 address stands for: IPv4-mapped ::ffff:a.b.c.d, IPv4-compatible
     * ::a.b.c.d, NAT64 64:ff9b::/96 and 6to4 2002::/16. Null for anything else.
     */
    public static function embeddedV4(string $ip): ?string
    {
        if (!filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6)) {
            return null;
        }
        $bin = inet_pton($ip);
        if ($bin === false || strlen($bin) !== 16) {
            return null;
        }
        $zero10 = str_repeat("\x00", 10);
        if (str_starts_with($bin, $zero10 . "\xff\xff")) {
            return inet_ntop(substr($bin, 12, 4)) ?: null;
        }
        if (str_starts_with($bin, $zero10 . "\x00\x00") && substr($bin, 12, 4) !== "\x00\x00\x00\x00" && substr($bin, 12, 4) !== "\x00\x00\x00\x01") {
            return inet_ntop(substr($bin, 12, 4)) ?: null; // ::a.b.c.d (but not :: or ::1)
        }
        if (str_starts_with($bin, "\x00\x64\xff\x9b" . str_repeat("\x00", 8))) {
            return inet_ntop(substr($bin, 12, 4)) ?: null;
        }
        if (str_starts_with($bin, "\x20\x02")) {
            return inet_ntop(substr($bin, 2, 4)) ?: null;
        }

        return null;
    }

    /** @return string[] */
    private static function items(mixed $raw): array
    {
        $list = is_array($raw) ? $raw : explode(',', (string)$raw);

        return array_values(array_filter(array_map(fn ($x) => trim((string)$x), $list), fn ($x) => $x !== ''));
    }
}
