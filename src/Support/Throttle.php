<?php

namespace DreamFactory\Core\AAuth\Support;

/**
 * Fixed-window counters in the AAuth cache store (Store; never throw; with no cache nothing is
 * limited). Keys are hashed, so emails and addresses never appear in cache keys. Counters are
 * shared by every node when the store is (redis, memcached, database).
 */
final class Throttle
{
    public static function count(string $bucket, string $subject): int
    {
        try {
            return (int)Store::cache()->get(self::key($bucket, $subject), 0);
        } catch (\Throwable $e) {
            return 0;
        }
    }

    /** Adds one hit and returns the new count. */
    public static function hit(string $bucket, string $subject, int $window): int
    {
        $key = self::key($bucket, $subject);
        $ttl = max(1, $window);
        try {
            $cache = Store::cache();
            $added = $cache->add($key, 0, $ttl);
            $n = (int)$cache->increment($key);
            if (!$added && $n === 1) {
                // The window expired between add() and increment(): stores such as redis then
                // create the counter WITHOUT a TTL (INCRBY on a missing key), which would never
                // reset. Write it again with the window (Laravel's RateLimiter does the same).
                $cache->put($key, 1, $ttl);
            }

            return $n;
        } catch (\Throwable $e) {
            return 0;
        }
    }

    public static function clear(string $bucket, string $subject): void
    {
        try {
            Store::cache()->forget(self::key($bucket, $subject));
        } catch (\Throwable $e) {
        }
    }

    /** Counts a hit and tells whether the limit is now exceeded. */
    public static function exceeded(string $bucket, string $subject, int $limit, int $window): bool
    {
        return self::hit($bucket, $subject, $window) > $limit;
    }

    private static function key(string $bucket, string $subject): string
    {
        return 'aauth:th:' . $bucket . ':' . hash('sha256', $subject);
    }
}
