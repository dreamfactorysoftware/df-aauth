<?php

namespace DreamFactory\Core\AAuth\Protocol;

/**
 * Raw request facts for signature verification. Build it from the raw server variables
 * (REQUEST_METHOD, the still-encoded path of REQUEST_URI, the raw QUERY_STRING, Host), never from a framework's
 * normalized getters.
 *
 *  - $authority: the Host the client used (case is folded when building the base)
 *  - $path:      raw, still-encoded path without the query ('' is treated as '/')
 *  - $query:     raw query string without '?', or null when the request target had none
 *  - $headers:   lowercase name => value (a list of values is joined with ", ")
 */
final class HttpRequestParts
{
    public function __construct(
        public string $method,
        public string $authority,
        public string $path,
        public ?string $query,
        public array $headers,
        public string $body,
    ) {
        $norm = [];
        foreach ($headers as $k => $v) {
            $norm[strtolower((string) $k)] = is_array($v) ? implode(', ', array_map('trim', $v)) : (string) $v;
        }
        $this->headers = $norm;
    }

    /** From an absolute URL (tests, outgoing requests). */
    public static function fromUrl(string $method, string $url, array $headers = [], string $body = ''): self
    {
        $u = parse_url($url);
        if ($u === false || !isset($u['host'])) {
            throw new \InvalidArgumentException('Absolute URL required');
        }
        return new self($method, HttpSignature::authorityOf($u), $u['path'] ?? '', $u['query'] ?? null, $headers, $body);
    }

    public function header(string $name): ?string
    {
        return $this->headers[strtolower($name)] ?? null;
    }
}
