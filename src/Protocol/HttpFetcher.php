<?php

namespace DreamFactory\Core\AAuth\Protocol;

/**
 * GETs a JSON document (metadata or JWKS) and returns it decoded as an array.
 * Implementations own egress admission (https, no private IPs, size/time limits, no cross-host redirects)
 * and caching. Throw any \Throwable on failure; Discovery maps it to a Signature-Error.
 */
interface HttpFetcher
{
    public function getJson(string $url): array;
}
