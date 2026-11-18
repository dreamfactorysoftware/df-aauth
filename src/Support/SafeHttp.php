<?php

namespace DreamFactory\Core\AAuth\Support;

use DreamFactory\Core\AAuth\Protocol\AAuthError;
use DreamFactory\Core\AAuth\Protocol\RefreshingHttpFetcher;

/**
 * Outbound JSON fetches for discovery (metadata documents, JWKS) with egress admission
 * (signature-key SK§7.3):
 *  - https only (http only when allow_insecure),
 *  - the host must resolve to public addresses only: loopback, private, CGNAT and reserved
 *    addresses are refused unless the deployment admits them (EgressPolicy:
 *    DF_AAUTH_PRIVATE_HOSTS / DF_AAUTH_PRIVATE_NETWORKS) or allow_insecure (development);
 *    link-local and cloud metadata addresses are refused always,
 *  - the connection is pinned to the vetted address (CURLOPT_RESOLVE, no DNS rebinding) and never
 *    goes through an environment proxy (which would resolve the host itself),
 *  - TLS is verified against the system trust store, or DF_AAUTH_CA_BUNDLE (a PEM file, or a
 *    c_rehash'd directory) for an internal CA; an unreadable bundle fails closed,
 *  - no redirects, a timeout (fetch_timeout, default 3 s) and a size cap (256 KB).
 * Results are cached in the AAuth cache store (Store; discovery_cache_seconds, default 5 min).
 * getJsonFresh() (Discovery's single refresh on an unknown kid / failed signature) skips the
 * cache, but at most once per minute per URL.
 * Failures are cached too (FAILURE_TTL per URL; a host that times out or refuses is skipped for
 * that long), and uncached fetches are budgeted per client address (FETCH_BUDGET per minute), so
 * unauthenticated requests naming slow issuers cannot tie up PHP workers.
 */
class SafeHttp implements RefreshingHttpFetcher
{
    public const FAILURE_TTL = 60;
    public const FETCH_BUDGET = 20;

    public function getJson(string $url): array
    {
        $cached = $this->cacheGet(self::key($url));

        return is_array($cached) ? $cached : $this->fetchAndStore($url);
    }

    public function getJsonFresh(string $url): array
    {
        $at = $this->cacheGet(self::key($url) . ':at');
        $cached = $this->cacheGet(self::key($url));
        if (is_array($cached) && is_int($at) && time() - $at < 60) {
            return $cached; // refresh floor: at most one fetch per minute per URL
        }

        return $this->fetchAndStore($url);
    }

    private function fetchAndStore(string $url): array
    {
        $ttl = max(1, (int)config('df-aauth.discovery_cache_seconds', 300));
        $failKey = self::key($url) . ':fail';
        $hostKey = 'aauth:fetch-host:' . sha1(strtolower((string)parse_url($url, PHP_URL_HOST)));
        foreach ([$failKey, $hostKey] as $k) {
            $failed = $this->cacheGet($k);
            if (is_string($failed)) {
                throw self::fail($failed . ' (cached)');
            }
        }
        $client = ClientIp::of();
        if ($client !== '' && Throttle::exceeded('discovery', $client, self::FETCH_BUDGET, 60)) {
            throw self::fail("$url: too many discovery fetches from this client; try again in a minute");
        }
        try {
            $data = $this->fetch($url);
        } catch (AAuthError $e) {
            $detail = (string)preg_replace('/^Discovery failed: /', '', $e->detail);
            $this->cachePut($failKey, $detail, self::FAILURE_TTL);
            if (str_contains($detail, '[unreachable]')) {
                $this->cachePut($hostKey, $detail, self::FAILURE_TTL);
            }
            throw $e;
        }
        $this->cachePut(self::key($url), $data, $ttl);
        $this->cachePut(self::key($url) . ':at', time(), $ttl);

        return $data;
    }

    private static function key(string $url): string
    {
        return 'aauth:fetch:' . sha1($url);
    }

    /** Uncached fetch with egress admission. */
    public function fetch(string $url): array
    {
        $insecure = Settings::allowInsecure();
        [$host, $port, $ip] = self::admit($url, $insecure, EgressPolicy::fromConfig());
        $tls = self::tlsOptions();

        $body = '';
        $max = max(1024, (int)config('df-aauth.fetch_max_bytes', 262144));
        $tooBig = false;
        $ch = curl_init($url);
        $timeout = max(1, (int)config('df-aauth.fetch_timeout', 3));
        curl_setopt_array($ch, [
            CURLOPT_FOLLOWLOCATION => false,
            CURLOPT_TIMEOUT => $timeout,
            CURLOPT_CONNECTTIMEOUT => min(2, $timeout),
            CURLOPT_PROTOCOLS => $insecure ? (CURLPROTO_HTTPS | CURLPROTO_HTTP) : CURLPROTO_HTTPS,
            CURLOPT_HTTPHEADER => ['Accept: application/json'],
            CURLOPT_USERAGENT => 'DreamFactory-AAuth/1.0',
            CURLOPT_RESOLVE => ["$host:$port:" . (str_contains($ip, ':') ? "[$ip]" : $ip)],
            CURLOPT_PROXY => '', // never an environment proxy: it would resolve the host itself
            CURLOPT_SSL_VERIFYPEER => true,
            CURLOPT_SSL_VERIFYHOST => 2,
            CURLOPT_WRITEFUNCTION => function ($ch, $chunk) use (&$body, $max, &$tooBig) {
                $body .= $chunk;
                if (strlen($body) > $max) {
                    $tooBig = true;

                    return 0; // abort
                }

                return strlen($chunk);
            },
        ] + $tls);
        $ok = curl_exec($ch);
        $status = (int)curl_getinfo($ch, CURLINFO_RESPONSE_CODE);
        $err = curl_error($ch);
        unset($ch); // curl_close() is a no-op since PHP 8.0 and deprecated in 8.5
        if ($tooBig) {
            throw self::fail("$url: response larger than $max bytes");
        }
        if ($ok === false) {
            throw self::fail("$url: [unreachable] $err");
        }
        if ($status !== 200) {
            throw self::fail("$url: HTTP $status");
        }
        $json = json_decode($body, true);
        if (!is_array($json)) {
            throw self::fail("$url: not a JSON object");
        }

        return $json;
    }

    /**
     * Validates the URL and resolves the host to an admissible address: public, or non-public but
     * admitted by $policy (DF_AAUTH_PRIVATE_HOSTS / _NETWORKS), or anything but link-local/metadata
     * when $insecure. Every resolved address must pass, not just the one that is pinned.
     *
     * $resolve (tests): fn(string $host): string[] instead of the system resolver.
     *
     * @return array{0: string, 1: int, 2: string} host, port, pinned IP
     */
    public static function admit(string $url, bool $insecure = false, ?EgressPolicy $policy = null, ?\Closure $resolve = null): array
    {
        $policy ??= new EgressPolicy();
        $p = parse_url($url);
        $scheme = strtolower((string)($p['scheme'] ?? ''));
        $host = strtolower((string)($p['host'] ?? ''));
        if ($host === '' || !in_array($scheme, $insecure ? ['https', 'http'] : ['https'], true)) {
            throw self::fail("$url: only https URLs can be fetched");
        }
        if (isset($p['user']) || isset($p['pass'])) {
            throw self::fail("$url: credentials in URL");
        }
        $port = (int)($p['port'] ?? ($scheme === 'https' ? 443 : 80));
        $bare = trim($host, '[]');
        if (filter_var($bare, FILTER_VALIDATE_IP)) {
            $ips = [$bare];
        } else {
            $ips = $resolve !== null ? array_values((array)$resolve($bare)) : self::resolve($bare);
            if (!$ips) {
                throw self::fail("$url: host does not resolve");
            }
        }
        foreach ($ips as $ip) {
            if (EgressPolicy::isForbidden($ip)) {
                throw self::fail("$url: $host resolves to a link-local, metadata or reserved address");
            }
            if (!$insecure && !self::isPublicIp($ip) && !$policy->admits($bare, $ip)) {
                throw self::fail("$url: $host resolves to a non-public address (not admitted by DF_AAUTH_PRIVATE_HOSTS or DF_AAUTH_PRIVATE_NETWORKS)");
            }
        }

        return [$bare, $port, $ips[0]];
    }

    /** True for globally routable unicast addresses (no private, loopback, link-local, metadata...). */
    public static function isPublicIp(string $ip): bool
    {
        if (!filter_var($ip, FILTER_VALIDATE_IP)) {
            return false;
        }
        // IPv4-mapped IPv6 (::ffff:a.b.c.d): judge the embedded IPv4 address.
        if (preg_match('/^::ffff:(\d+\.\d+\.\d+\.\d+)$/i', $ip, $m)) {
            $ip = $m[1];
        }
        if (!filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE)) {
            return false;
        }
        if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
            $n = ip2long($ip);
            foreach ([
                ['0.0.0.0', 8], ['100.64.0.0', 10], ['127.0.0.0', 8], ['169.254.0.0', 16], ['192.0.0.0', 24],
                ['192.0.2.0', 24], ['198.18.0.0', 15], ['198.51.100.0', 24], ['203.0.113.0', 24], ['224.0.0.0', 3],
            ] as [$net, $bits]) {
                $mask = -1 << (32 - $bits);
                if (($n & $mask) === (ip2long($net) & $mask)) {
                    return false;
                }
            }

            return true;
        }
        $bin = inet_pton($ip);
        if ($bin === false || strlen($bin) !== 16) {
            return false;
        }
        // Forms that embed an IPv4 address: judge the embedded address (NAT64, 6to4).
        if (str_starts_with($bin, "\x00\x64\xff\x9b" . str_repeat("\x00", 8))) { // 64:ff9b::/96
            return self::isPublicIp(inet_ntop(substr($bin, 12, 4)));
        }
        if (str_starts_with($bin, "\x20\x02")) { // 2002::/16 6to4
            return self::isPublicIp(inet_ntop(substr($bin, 2, 4)));
        }
        // Otherwise only global unicast (2000::/3), minus the special-purpose blocks inside it.
        if ((ord($bin[0]) & 0xe0) !== 0x20) {
            return false; // ::/8 (incl. ::1, ::, ::ffff:0:0/96 translated), 64:ff9b:1::/48, 100::/64, fc00::/7, fe80::/10, fec0::/10, ff00::/8 ...
        }
        foreach ([['2001::', 23], ['2001:db8::', 32], ['2001:10::', 28], ['3fff::', 20], ['2620:4f:8000::', 48], ['fd00:ec2::', 32]] as [$net, $bits]) {
            if (ClientIp::matches($ip, "$net/$bits")) {
                return false;
            }
        }

        return true;
    }

    /**
     * cURL TLS options: DF_AAUTH_CA_BUNDLE (file => CAINFO, directory => CAPATH) or the system store.
     * A configured bundle that cannot be read fails the fetch rather than silently trusting less or more.
     */
    public static function tlsOptions(): array
    {
        $bundle = trim((string)config('df-aauth.ca_bundle', ''));
        if ($bundle === '') {
            return [];
        }
        if (is_dir($bundle) && is_readable($bundle)) {
            return [CURLOPT_CAPATH => $bundle];
        }
        if (is_file($bundle) && is_readable($bundle)) {
            return [CURLOPT_CAINFO => $bundle];
        }
        try {
            \Illuminate\Support\Facades\Log::error("df-aauth: DF_AAUTH_CA_BUNDLE '$bundle' is not a readable file or directory; discovery fetches fail until it is fixed.");
        } catch (\Throwable $e) {
        }

        throw self::fail('the CA bundle configured on this server is not readable');
    }

    /** @return string[] */
    private static function resolve(string $host): array
    {
        $ips = [];
        $v4 = @gethostbynamel($host);
        if (is_array($v4)) {
            $ips = $v4;
        }
        $aaaa = @dns_get_record($host, DNS_AAAA);
        if (is_array($aaaa)) {
            foreach ($aaaa as $r) {
                if (!empty($r['ipv6'])) {
                    $ips[] = $r['ipv6'];
                }
            }
        }

        return array_values(array_unique($ips));
    }

    private static function fail(string $detail): AAuthError
    {
        return AAuthError::signature('unknown_key', 'Discovery failed: ' . $detail);
    }

    private function cacheGet(string $key): mixed
    {
        try {
            return Store::cache()->get($key);
        } catch (\Throwable $e) {
            return null;
        }
    }

    private function cachePut(string $key, mixed $value, int $ttl): void
    {
        try {
            Store::cache()->put($key, $value, $ttl);
        } catch (\Throwable $e) {
        }
    }
}
