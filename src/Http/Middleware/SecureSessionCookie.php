<?php

namespace DreamFactory\Core\AAuth\Http\Middleware;

use DreamFactory\Core\AAuth\Support\Settings;
use Illuminate\Http\Request;

/**
 * Runs before the `web` group (StartSession) on the consent and grants pages:
 *  - when the AAuth issuer is https, the session cookie (which carries the signed-in person) is
 *    always marked Secure, even when the app sits behind a TLS proxy and sees plain http itself;
 *  - DF_AAUTH_SESSION_DRIVER (redis, database, ...) replaces SESSION_DRIVER for these pages only,
 *    so a multi-node DreamFactory without sticky sessions keeps the person signed in and the CSRF
 *    token valid whichever node answers. `database` uses the aauth_sessions table.
 * Nothing changes for any other route.
 */
class SecureSessionCookie
{
    public const TABLE = 'aauth_sessions';

    public function handle(Request $request, \Closure $next)
    {
        try {
            if (str_starts_with((string)Settings::issuer(), 'https://')) {
                config(['session.secure' => true]);
            }
            self::applyDriver();
        } catch (\Throwable $e) {
        }

        return $next($request);
    }

    /** Points the session config at DF_AAUTH_SESSION_DRIVER, when set. */
    public static function applyDriver(): void
    {
        $driver = strtolower(trim((string)config('df-aauth.session_driver', '')));
        if ($driver === '') {
            return;
        }
        $set = ['session.driver' => $driver];
        if ($driver === 'database') {
            $set['session.table'] = self::TABLE;
        }
        config($set);
    }
}
