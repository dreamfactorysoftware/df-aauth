<?php

namespace DreamFactory\Core\AAuth\Tests\Protocol\Support;

use DreamFactory\Core\AAuth\Protocol\RefreshingHttpFetcher;

/** Cached docs from getJson(), fresh docs from getJsonFresh(). */
final class FakeRefreshingFetcher extends FakeFetcher implements RefreshingHttpFetcher
{
    public array $freshLog = [];

    public function __construct(array $docs, public array $freshDocs)
    {
        parent::__construct($docs);
    }

    public function getJsonFresh(string $url): array
    {
        $this->freshLog[] = $url;
        if (!array_key_exists($url, $this->freshDocs)) {
            throw new \RuntimeException("404 {$url}");
        }
        return $this->freshDocs[$url];
    }
}
