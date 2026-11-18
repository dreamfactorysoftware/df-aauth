<?php

namespace DreamFactory\Core\AAuth\Support;

use DreamFactory\Core\Enums\LicenseLevel;
use DreamFactory\Core\Exceptions\ForbiddenException;
use DreamFactory\Core\Utility\Environment;

/**
 * AAuth is a DreamFactory Gold feature, like df-compliance's service reports and restricted
 * admins. It is available when the instance's license level
 * (DreamFactory\Core\Utility\Environment::getLicenseLevel()) is Gold:
 *
 *  - system/aauth answers 403 with MESSAGE on other license levels (Resources\AAuth);
 *  - Settings::enabled() is false, so signed requests get no AAuth identity and the public AAuth
 *    endpoints (metadata, authorize, person server, consent) answer as when AAuth is off.
 */
final class License
{
    public const MESSAGE = 'AAuth is not available for your license. Please upgrade to Gold.';

    /** @var \Closure():string|null returns a LicenseLevel value; null = Environment::getLicenseLevel() */
    private static ?\Closure $resolver = null;

    private function __construct()
    {
    }

    /** True when the instance's license level is Gold. Any failure to tell counts as not Gold. */
    public static function isGold(): bool
    {
        try {
            $level = self::$resolver !== null ? (self::$resolver)() : Environment::getLicenseLevel();
        } catch (\Throwable $e) {
            return false;
        }

        return $level === LicenseLevel::GOLD;
    }

    /** @throws ForbiddenException */
    public static function requireGold(): void
    {
        if (!self::isGold()) {
            throw new ForbiddenException(self::MESSAGE);
        }
    }

    /** Tests: a closure returning a LicenseLevel value, or null for the instance's real level. */
    public static function resolveUsing(?\Closure $resolver): void
    {
        self::$resolver = $resolver;
    }
}
