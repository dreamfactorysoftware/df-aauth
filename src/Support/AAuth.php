<?php

namespace DreamFactory\Core\AAuth\Support;

use DreamFactory\Core\AAuth\Protocol\AAuthError;
use DreamFactory\Core\AAuth\Protocol\Discovery;

/** Shared wiring: the discovery/key resolver with self-resolution for our own issuer. */
final class AAuth
{
    private static ?Discovery $discovery = null;

    /** DB timestamp (stored in the app timezone, UTC on DreamFactory) as ISO 8601 UTC for the admin API. */
    public static function iso(mixed $ts): ?string
    {
        if ($ts === null || $ts === '') {
            return null;
        }
        try {
            return \Illuminate\Support\Carbon::parse((string)$ts, config('app.timezone') ?: 'UTC')->utc()->format('Y-m-d\\TH:i:s\\Z');
        } catch (\Throwable) {
            return (string)$ts;
        }
    }

    public static function flush(): void
    {
        self::$discovery = null;
    }

    public static function discovery(): Discovery
    {
        if (self::$discovery === null) {
            self::$discovery = new Discovery(new SafeHttp(), \Closure::fromCallable([self::class, 'resolveLocal']), Settings::allowInsecure());
        }

        return self::$discovery;
    }

    /**
     * Self-resolution: tokens issued by this DreamFactory are verified with keys from the DB, never by
     * an HTTP call to ourselves. Returns null for other issuers (Discovery then fetches).
     */
    public static function resolveLocal(string $iss, string $dwk, ?string $kid): ?array
    {
        if ($iss !== Settings::issuer()) {
            return null;
        }
        $purpose = Keys::DWK_PURPOSE[$dwk] ?? null;
        $meta = Metadata::forDwk($dwk);
        if ($purpose === null || $meta === null) {
            throw AAuthError::signature('unknown_key', "This server publishes no $dwk.");
        }
        $jwk = Keys::find($purpose, $kid);
        if ($jwk === null) {
            throw AAuthError::signature('unknown_key', "Unknown key id '$kid'.");
        }

        return ['jwk' => $jwk, 'meta' => $meta];
    }

    /** Metadata for any issuer: local document for ourselves, discovery for everyone else. */
    public static function metadata(string $iss, string $dwk): array
    {
        if ($iss === Settings::issuer()) {
            $doc = Metadata::forDwk($dwk);
            if ($doc === null) {
                throw new AAuthError(404, 'invalid_request', "This server publishes no $dwk.");
            }

            return $doc;
        }

        return self::discovery()->metadata($iss, $dwk);
    }

    public static function now(): int
    {
        return time();
    }
}
