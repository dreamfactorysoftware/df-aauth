<?php

namespace DreamFactory\Core\AAuth\Support;

use Symfony\Component\HttpFoundation\Response;

/** CORS for the public AAuth endpoints (outside api/*, so Laravel's CORS never applies). */
final class Cors
{
    public const ALLOW_HEADERS = 'Content-Type, Content-Digest, Signature, Signature-Input, Signature-Key, Prefer, AAuth-Capabilities';
    public const EXPOSE_HEADERS = 'AAuth-Requirement, Signature-Error, Accept-Signature-Scheme, Accept-Signature-Alg, Location, Retry-After';

    public static function apply(Response $response, string $methods = 'GET, OPTIONS'): Response
    {
        $response->headers->set('Access-Control-Allow-Origin', '*');
        $response->headers->set('Access-Control-Allow-Methods', $methods);
        $response->headers->set('Access-Control-Allow-Headers', self::ALLOW_HEADERS);
        $response->headers->set('Access-Control-Expose-Headers', self::EXPOSE_HEADERS);
        $response->headers->set('Access-Control-Max-Age', '600');

        return $response;
    }

    public static function preflight(string $methods = 'GET, OPTIONS'): Response
    {
        return self::apply(new Response('', 204), $methods);
    }
}
