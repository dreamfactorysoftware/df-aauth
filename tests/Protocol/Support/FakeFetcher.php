<?php

namespace DreamFactory\Core\AAuth\Tests\Protocol\Support;

use DreamFactory\Core\AAuth\Protocol\HttpFetcher;

/**
 * url => document, or url => list of documents served in sequence (last one repeats).
 * Records every fetched URL in $log.
 */
class FakeFetcher implements HttpFetcher
{
    public array $log = [];

    public function __construct(public array $docs)
    {
    }

    public function getJson(string $url): array
    {
        $this->log[] = $url;
        if (!array_key_exists($url, $this->docs)) {
            throw new \RuntimeException("404 {$url}");
        }
        $d = $this->docs[$url];
        if (array_is_list($d) && $d !== [] && is_array($d[0])) {
            $n = count(array_keys($this->log, $url, true)) - 1;
            return $d[min($n, count($d) - 1)];
        }
        return $d;
    }

    public function count(string $url): int
    {
        return count(array_keys($this->log, $url, true));
    }
}
