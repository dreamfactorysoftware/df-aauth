<?php

namespace DreamFactory\Core\AAuth\PersonServer;

use DreamFactory\Core\AAuth\Protocol\Ids;
use DreamFactory\Core\AAuth\Support\Settings;
use Illuminate\Http\Request;

/**
 * Consent sign-in through DreamFactory's own login page, for people who sign in with OAuth,
 * OpenID Connect, SAML (or LDAP there): see docs/sso-approval.md.
 *
 *  1. "Sign in with single sign-on" (a CSRF-protected POST on the consent or grants page) stores a
 *     one-time state in this browser's consent session and redirects to
 *     {issuer}/dreamfactory/dist/#/auth/login?redirect={issuer}/aauth/interact/sso#state=S
 *  2. The admin app signs the person in with any DreamFactory login method (or sees they already
 *     are), and only for a same-origin redirect appends ?session_token=JWT. Because our redirect
 *     URL ends in a fragment, the token lands in the fragment: never sent to a server, never in
 *     access logs or Referer. (DreamFactory's OAuth callback appends it the same way.)
 *  3. GET /aauth/interact/sso serves a page whose script moves state + token from the fragment
 *     into a POST (CSRF token included) and scrubs the URL. A token arriving in the query instead
 *     is accepted too (and the response redirects to a clean URL at once).
 *  4. POST /aauth/interact/sso: the state must be one this session issued (single use, at most
 *     MAX_AGE old, so only the browser that started the sign-in can finish it); the token must be a
 *     valid DreamFactory session (signature, expiry, blacklist, active user). The person is then
 *     signed in to the consent session only (no DF session is created or changed) and sees the
 *     usual "Continue as ..." card: signing in is still not consent.
 */
final class SsoLogin
{
    public const STATE = 'aauth_ps.sso';
    public const MAX_AGE = 900;
    public const MAX_STATES = 5;
    public const PATH = '/aauth/interact/sso';

    /** Is single sign-on offered on the sign-in cards? DF_AAUTH_SSO: auto (an SSO login service is active) | on | off. */
    public static function offered(): bool
    {
        $mode = strtolower(trim((string)config('df-aauth.sso', 'auto')));
        if (in_array($mode, ['off', 'false', '0', 'no'], true)) {
            return false;
        }
        if (in_array($mode, ['on', 'true', '1', 'yes'], true)) {
            return true;
        }
        try {
            return app(Accounts::class)->hasSso();
        } catch (\Throwable $e) {
            return false;
        }
    }

    /**
     * Remembers a fresh one-time state for this browser and returns the DreamFactory login URL.
     *
     * @param string|null $pid    the pending request the person is answering (null: the grants page)
     */
    public static function start(Request $request, ?string $pid): string
    {
        $state = Ids::random(24);
        // a few outstanding states per browser (two consent tabs must not cancel each other)
        $states = array_filter((array)$request->session()->get(self::STATE, []), fn ($v) => is_array($v) && time() - (int)($v['at'] ?? 0) <= self::MAX_AGE);
        $states[$state] = ['pid' => $pid, 'at' => time()];
        $request->session()->put(self::STATE, array_slice($states, -self::MAX_STATES, null, true));
        $issuer = (string)Settings::issuer();
        $path = '/' . ltrim((string)config('df-aauth.sso_login_path', '/dreamfactory/dist/#/auth/login'), '/');
        $back = $issuer . self::PATH . '#state=' . $state;

        return $issuer . $path . (str_contains($path, '?') ? '&' : '?') . 'redirect=' . rawurlencode($back);
    }

    /**
     * Consumes the state (whatever the outcome) and validates the token. user_id is null on any
     * failure; pid is the request the state was started for (only when the state matched).
     *
     * @return array{user_id: ?int, pid: ?string, matched: bool}
     */
    public static function complete(Request $request, string $state, string $jwt): array
    {
        $fail = ['user_id' => null, 'pid' => null, 'matched' => false];
        $states = (array)$request->session()->get(self::STATE, []);
        $saved = null;
        foreach ($states as $key => $v) {
            if ($state !== '' && is_string($key) && hash_equals($key, $state)) {
                $saved = $v;
                unset($states[$key]); // single use, whatever the outcome
            }
        }
        if (!is_array($saved)) {
            return $fail;
        }
        $request->session()->put(self::STATE, $states);
        $pid = is_string($saved['pid'] ?? null) ? $saved['pid'] : null;
        if (time() - (int)($saved['at'] ?? 0) > self::MAX_AGE) {
            return ['pid' => $pid, 'matched' => true] + $fail;
        }
        $uid = app(Accounts::class)->sessionUser($jwt);

        return ['user_id' => $uid ?: null, 'pid' => $pid, 'matched' => true];
    }
}
