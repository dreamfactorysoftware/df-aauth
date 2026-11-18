<?php

namespace DreamFactory\Core\AAuth\Support;

use Illuminate\Contracts\Cache\Repository;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Log;

/**
 * The cache every piece of short-lived AAuth state goes through: signature replay records,
 * failure and rate counters, single-use code claims, discovery results and Playground runs.
 * Durable state (keys, pending requests, grants, policy) lives in the system database.
 *
 * DF_AAUTH_CACHE_STORE names a store from config/cache.php (for example `redis`); empty means
 * DreamFactory's default store. With more than one DreamFactory node it must be a store every node
 * shares (redis, memcached, database): a node-local store (file, array) lets a signature be
 * replayed on another node and multiplies every limit by the node count. An undefined store name
 * falls back to the default store and logs an error, so a typo never switches the limits off.
 */
final class Store
{
    /** Stores whose data is local to one node (or one process). */
    public const NODE_LOCAL = ['file', 'array', 'apc', 'null'];

    private static ?string $warned = null;

    public static function cache(): Repository
    {
        $name = self::name();
        if ($name !== null) {
            try {
                return Cache::store($name);
            } catch (\InvalidArgumentException $e) {
                if (self::$warned !== $name) {
                    self::$warned = $name;
                    try {
                        Log::error("df-aauth: DF_AAUTH_CACHE_STORE '$name' is not a configured cache store; using the default store.");
                    } catch (\Throwable $ignored) {
                    }
                }
            }
        }

        return Cache::store();
    }

    /** The configured store name, or null for DreamFactory's default store. */
    public static function name(): ?string
    {
        $name = trim((string)config('df-aauth.cache_store', ''));

        return $name === '' ? null : $name;
    }

    /** Driver of the store AAuth actually uses (e.g. redis, file). */
    public static function driver(): string
    {
        $name = self::name() ?? (string)config('cache.default', '');
        $driver = (string)config("cache.stores.$name.driver", '');

        return $driver !== '' ? $driver : $name;
    }

    public static function isShared(): bool
    {
        return !in_array(self::driver(), self::NODE_LOCAL, true);
    }
}
