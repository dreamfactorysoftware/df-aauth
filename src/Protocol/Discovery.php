<?php

namespace DreamFactory\Core\AAuth\Protocol;

/**
 * Key discovery (§11.2, §11.4): {iss}/.well-known/{dwk} -> check metadata.issuer === iss (byte equality)
 * -> jwks_uri -> key by kid, refreshing the JWKS once on an unknown kid.
 *
 * $local (self-resolution): fn(string $iss, string $dwk, ?string $kid): ?array returning
 * ['jwk' => ..., 'meta' => ...] for issuers we host ourselves (no HTTP to ourselves), or null to fall through.
 * An array without 'jwk' means "ours, but no such kid" => unknown_key. metadata() never consults $local.
 */
final class Discovery implements RefreshableKeyResolver
{
    /** @var array<string, array> per-instance memo of fetched documents */
    private array $memo = [];

    public function __construct(
        private HttpFetcher $http,
        private ?\Closure $local = null,
        private bool $allowInsecure = false,
    ) {
    }

    public function resolve(string $iss, string $dwk, ?string $kid): array
    {
        return $this->doResolve($iss, $dwk, $kid, false);
    }

    public function resolveFresh(string $iss, string $dwk, ?string $kid): array
    {
        return $this->doResolve($iss, $dwk, $kid, true);
    }

    /** Fetch and validate {iss}/.well-known/{dwk}. */
    public function metadata(string $iss, string $dwk): array
    {
        $this->assertIss($iss);
        self::assertDwk($dwk);
        $url = $iss . '/.well-known/' . $dwk;
        $meta = $this->fetch($url, false);
        if (!array_key_exists('issuer', $meta) || !is_string($meta['issuer']) || $meta['issuer'] === '') {
            throw AAuthError::signature('issuer_missing', "Metadata at {$url} has no issuer");
        }
        if ($meta['issuer'] !== $iss) {
            throw AAuthError::signature('issuer_mismatch', "Metadata issuer \"{$meta['issuer']}\" does not equal \"{$iss}\"");
        }
        return $meta;
    }

    /**
     * Server identifier (§11.1.1): https, lowercase host, no port/path/query/fragment/userinfo, no trailing slash.
     * $allowInsecure (dev only): also allows http and an explicit port.
     * Throws AAuthError(400, 'invalid_request').
     */
    public static function assertServerId(string $id, bool $allowInsecure = false): void
    {
        $bad = fn (string $why) => new AAuthError(400, 'invalid_request', "Invalid server identifier \"{$id}\": {$why}");
        if ($id === '' || preg_match('/[\s\x00-\x1f\x7f-\xff]/', $id)) {
            throw $bad('empty or contains whitespace/non-ASCII');
        }
        $u = parse_url($id);
        if ($u === false || !isset($u['scheme'], $u['host'])) {
            throw $bad('not an absolute URL');
        }
        $scheme = $u['scheme'];
        if ($scheme !== 'https' && !($allowInsecure && $scheme === 'http')) {
            throw $bad('must use https');
        }
        if (isset($u['user']) || isset($u['pass'])) {
            throw $bad('must not contain userinfo');
        }
        if (isset($u['port']) && !$allowInsecure) {
            throw $bad('must not contain a port');
        }
        if (isset($u['path']) || isset($u['query']) || isset($u['fragment'])) {
            throw $bad('must not contain a path, query, fragment or trailing slash');
        }
        $host = $u['host'];
        if ($host !== strtolower($host) || !preg_match('/^[a-z0-9.-]+$|^\[[0-9a-f:.]+\]$/', $host)) {
            throw $bad('host must be lowercase ASCII (A-labels)');
        }
        $rebuilt = $scheme . '://' . $host . (isset($u['port']) ? ':' . $u['port'] : '');
        if ($rebuilt !== $id) {
            throw $bad('must be exactly scheme://host');
        }
    }

    private function doResolve(string $iss, string $dwk, ?string $kid, bool $fresh): array
    {
        if ($this->local !== null) {
            $hit = ($this->local)($iss, $dwk, $kid);
            if (is_array($hit)) {
                if (!isset($hit['jwk']) || !is_array($hit['jwk'])) {
                    throw AAuthError::signature('unknown_key', 'No local key ' . ($kid ?? '(none)') . " for {$iss}");
                }
                return ['jwk' => Jwk::publicOf($hit['jwk']), 'meta' => $hit['meta'] ?? []];
            }
        }
        $meta = $this->metadata($iss, $dwk);
        $jwksUri = $meta['jwks_uri'] ?? null;
        if (!is_string($jwksUri) || !$this->isFetchableUrl($jwksUri)) {
            throw AAuthError::signature('unknown_key', "Metadata for {$iss} has no usable jwks_uri");
        }
        $key = $fresh ? null : $this->findKey($this->fetch($jwksUri, false), $kid);
        if ($key === null) {
            $key = $this->findKey($this->fetch($jwksUri, true), $kid); // refresh once
        }
        if ($key === null) {
            throw AAuthError::signature('unknown_key', 'No key ' . ($kid ?? '(no kid)') . " in {$jwksUri}");
        }
        Jwk::assertSupportedPublic($key);
        return ['jwk' => Jwk::publicOf($key), 'meta' => $meta];
    }

    private function findKey(array $jwks, ?string $kid): ?array
    {
        $keys = $jwks['keys'] ?? null;
        if (!is_array($keys)) {
            return null;
        }
        $keys = array_values(array_filter($keys, 'is_array'));
        if ($kid === null) {
            return count($keys) === 1 ? $keys[0] : null;
        }
        foreach ($keys as $k) {
            if (($k['kid'] ?? null) === $kid) {
                return $k;
            }
        }
        return null;
    }

    private function fetch(string $url, bool $fresh): array
    {
        if (!$fresh && isset($this->memo[$url])) {
            return $this->memo[$url];
        }
        try {
            if ($fresh && $this->http instanceof RefreshingHttpFetcher) {
                $doc = $this->http->getJsonFresh($url);
            } else {
                $doc = $this->http->getJson($url);
            }
        } catch (AAuthError $e) {
            throw $e;
        } catch (\Throwable $e) {
            throw AAuthError::signature('unknown_key', "Could not fetch {$url}: " . $e->getMessage());
        }
        return $this->memo[$url] = $doc;
    }

    private function assertIss(string $iss): void
    {
        try {
            self::assertServerId($iss, $this->allowInsecure);
        } catch (AAuthError $e) {
            throw AAuthError::signature('invalid_jwt', $e->detail);
        }
    }

    private static function assertDwk(string $dwk): void
    {
        if (!preg_match('/^aauth-[a-z]+\.json$/', $dwk)) {
            throw AAuthError::signature('invalid_jwt', "Unexpected dwk \"{$dwk}\"");
        }
    }

    private function isFetchableUrl(string $url): bool
    {
        $u = parse_url($url);
        if ($u === false || !isset($u['scheme'], $u['host']) || isset($u['user']) || isset($u['pass'])) {
            return false;
        }
        return $u['scheme'] === 'https' || ($this->allowInsecure && $u['scheme'] === 'http');
    }
}
