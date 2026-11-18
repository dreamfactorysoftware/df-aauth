<?php

namespace DreamFactory\Core\AAuth\PersonServer;

use DreamFactory\Core\AAuth\Support\ClientIp;
use DreamFactory\Core\AAuth\Support\Throttle;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;

/**
 * The one credential check behind the consent and grants pages, with failure limits per client
 * address and per target account. A locked bucket answers "throttled" without checking the
 * password, so the pages cannot be used to try passwords.
 *
 *  - no service: DreamFactory email (or username, per df.login_attribute) + password
 *    (Auth::validate: no DF session side effects);
 *  - service = an LDAP / Active Directory service: the directory checks the username + password and
 *    the person is its DreamFactory shadow user, exactly as DreamFactory's own login with that
 *    service would map them (Accounts::directoryLogin), again without a DF session.
 * Redirect-based single sign-on (OAuth, OIDC, SAML) is SsoLogin.
 */
final class SignIn
{
    public const IP_LIMIT = 10;
    public const IP_WINDOW = 600;
    public const ACCOUNT_LIMIT = 20;
    public const ACCOUNT_WINDOW = 900;

    /** @return array{status: 'ok'|'wrong'|'throttled', user_id: ?int} */
    public static function attempt(Request $request, string $email, string $password, string $service = ''): array
    {
        $ip = ClientIp::of($request);
        $service = trim($service);
        $login = trim($email);
        // directory accounts are their own namespace: jdoe at ldap-corp is not jdoe@local
        $account = ($service !== '' ? 'svc:' . mb_strtolower($service) . '|' : '') . mb_strtolower($login);
        if (self::locked($ip, $login === '' ? '' : $account)) {
            return ['status' => 'throttled', 'user_id' => null];
        }
        $userId = null;
        if ($password !== '' && $login !== '') {
            try {
                $userId = $service === '' ? self::local($login, $password) : app(Accounts::class)->directoryLogin($service, $login, $password);
            } catch (\Throwable $e) {
                $userId = null;
            }
        }
        if (!$userId) {
            Throttle::hit('login-ip', $ip, self::IP_WINDOW);
            if ($login !== '') {
                Throttle::hit('login-acct', $account, self::ACCOUNT_WINDOW);
            }

            return ['status' => 'wrong', 'user_id' => null];
        }
        Throttle::clear('login-acct', $account);

        return ['status' => 'ok', 'user_id' => (int)$userId];
    }

    public static function locked(string $ip, string $account): bool
    {
        return Throttle::count('login-ip', $ip) >= self::IP_LIMIT
            || ($account !== '' && Throttle::count('login-acct', $account) >= self::ACCOUNT_LIMIT);
    }

    /** DreamFactory's own users table: the active user with that login and password, or null. */
    private static function local(string $login, string $password): ?int
    {
        $attr = (string)config('df.login_attribute', 'email') ?: 'email';
        if (!Auth::validate([$attr => $login, 'password' => $password, 'is_active' => 1])) {
            return null;
        }
        $id = \DB::table('user')->where($attr, $login)->where('is_active', true)->value('id');

        return $id ? (int)$id : null;
    }
}
