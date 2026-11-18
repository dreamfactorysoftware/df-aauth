<?php

namespace DreamFactory\Core\AAuth\Support;

use DreamFactory\Core\AAuth\Protocol\HttpRequestParts;
use Illuminate\Http\Request;

/**
 * Builds the exact request facts a signature covers from the raw server variables, never from
 * Laravel's normalized getters: df.verb_override rewrites the request method in place and Symfony
 * sorts/re-encodes the query string.
 */
final class RawRequest
{
    public static function parts(Request $request): HttpRequestParts
    {
        $server = $_SERVER;
        $method = strtoupper((string)($server['REQUEST_METHOD'] ?? $request->server->get('REQUEST_METHOD', $request->getMethod())));
        $uri = (string)($server['REQUEST_URI'] ?? $request->server->get('REQUEST_URI', $request->getRequestUri()));
        $path = parse_url($uri, PHP_URL_PATH);
        if (!is_string($path) || $path === '') {
            $path = '/';
        }
        $query = $server['QUERY_STRING'] ?? $request->server->get('QUERY_STRING');
        if ($query === null || $query === '') {
            $q = parse_url($uri, PHP_URL_QUERY);
            $query = is_string($q) && $q !== '' ? $q : null;
        }
        $host = strtolower((string)($server['HTTP_HOST'] ?? $request->headers->get('host', '')));

        $headers = [];
        foreach ($request->headers->all() as $name => $values) {
            $headers[strtolower($name)] = implode(', ', array_map('strval', (array)$values));
        }

        return new HttpRequestParts($method, $host, $path, $query, $headers, (string)$request->getContent());
    }

    /** The real (pre-override) method of the request. */
    public static function method(Request $request): string
    {
        return strtoupper((string)($_SERVER['REQUEST_METHOD'] ?? $request->server->get('REQUEST_METHOD', $request->getMethod())));
    }

    public static function clientIp(Request $request): string
    {
        return (string)($request->ip() ?? 'unknown');
    }
}
