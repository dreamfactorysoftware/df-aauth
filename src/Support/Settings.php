<?php

namespace DreamFactory\Core\AAuth\Support;

use DreamFactory\Core\AAuth\Protocol\Discovery;
use Illuminate\Support\Facades\DB;

/**
 * Key/value settings in aauth_settings (JSON values) plus the derived issuer facts.
 * Values are memoized per request; flush() drops the memo (tests, after writes).
 */
final class Settings
{
    public const TABLE = 'aauth_settings';
    private const DEFAULTS = ['enabled' => false, 'ps_local_enabled' => true];

    private static ?array $memo = null;

    public static function flush(): void
    {
        self::$memo = null;
    }

    public static function get(string $name, mixed $default = null): mixed
    {
        if (self::$memo === null) {
            self::$memo = [];
            try {
                foreach (DB::table(self::TABLE)->get(['name', 'value']) as $row) {
                    self::$memo[$row->name] = $row->value === null ? null : json_decode($row->value, true);
                }
            } catch (\Throwable $e) {
                // tables missing (package not migrated yet): behave as "not configured"
            }
        }

        return array_key_exists($name, self::$memo) ? self::$memo[$name] : ($default ?? self::DEFAULTS[$name] ?? null);
    }

    public static function set(string $name, mixed $value): void
    {
        $now = now();
        $json = json_encode($value);
        $updated = DB::table(self::TABLE)->where('name', $name)->update(['value' => $json, 'updated_at' => $now]);
        if (!$updated && !DB::table(self::TABLE)->where('name', $name)->exists()) {
            DB::table(self::TABLE)->insert(['name' => $name, 'value' => $json, 'updated_at' => $now]);
        }
        self::flush();
    }

    /**
     * AAuth is active: switched on by an admin, the issuer is a valid server identifier, and the
     * instance's license level is Gold (License).
     */
    public static function enabled(): bool
    {
        return (bool)self::get('enabled', false) && self::issuerOk() && License::isGold();
    }

    public static function localPersonServerEnabled(): bool
    {
        return (bool)self::get('ps_local_enabled', true);
    }

    public static function allowInsecure(): bool
    {
        return (bool)config('df-aauth.allow_insecure', false);
    }

    /** DF_AAUTH_ISSUER, else the APP_URL origin when it is https. Never the request Host. */
    public static function issuer(): ?string
    {
        $issuer = trim((string)config('df-aauth.issuer', ''));
        if ($issuer === '') {
            $app = trim((string)config('app.url', ''));
            $parts = parse_url($app);
            if (!is_array($parts) || ($parts['scheme'] ?? '') !== 'https' || empty($parts['host'])) {
                return null;
            }
            $issuer = 'https://' . strtolower($parts['host']) . (isset($parts['port']) ? ':' . $parts['port'] : '');
        }

        return rtrim($issuer, '/');
    }

    public static function issuerOk(): bool
    {
        $issuer = self::issuer();
        if ($issuer === null || $issuer === '') {
            return false;
        }
        try {
            Discovery::assertServerId($issuer, self::allowInsecure());

            return true;
        } catch (\Throwable $e) {
            return false;
        }
    }

    /** Host (plus a port, dev only) that signed requests must use as @authority. */
    public static function issuerAuthority(): ?string
    {
        $issuer = self::issuer();
        if (!$issuer) {
            return null;
        }
        $p = parse_url($issuer);

        return strtolower(($p['host'] ?? '') . (isset($p['port']) ? ':' . $p['port'] : ''));
    }

    public static function issuerHost(): string
    {
        return (string)parse_url((string)self::issuer(), PHP_URL_HOST);
    }

    public static function url(string $path): string
    {
        return self::issuer() . '/' . ltrim($path, '/');
    }

    /** Instance display name used in metadata. */
    public static function instanceName(): string
    {
        $name = trim((string)self::get('name', ''));

        return $name !== '' ? $name : 'DreamFactory';
    }
}
