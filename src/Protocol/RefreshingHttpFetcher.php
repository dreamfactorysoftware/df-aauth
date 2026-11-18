<?php

namespace DreamFactory\Core\AAuth\Protocol;

/**
 * Optional extension of HttpFetcher: fetch without the cache (still rate limited by the implementation,
 * e.g. at most one refresh per minute per issuer). Discovery uses it for the single JWKS refresh on an
 * unknown kid; plain HttpFetchers get a second getJson() call instead.
 */
interface RefreshingHttpFetcher extends HttpFetcher
{
    public function getJsonFresh(string $url): array;
}
