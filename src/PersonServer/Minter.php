<?php

namespace DreamFactory\Core\AAuth\PersonServer;

use DreamFactory\Core\AAuth\Protocol\Ids;
use DreamFactory\Core\AAuth\Protocol\Jwt;
use DreamFactory\Core\AAuth\Support\AAuth;
use DreamFactory\Core\AAuth\Support\Keys;
use DreamFactory\Core\AAuth\Support\Settings;
use DreamFactory\Core\AAuth\Support\Users;

/**
 * Mints person tokens (§7.1.2) and auth tokens (§9.4.1) for the local Person Server. Each token is
 * recorded with the agent it is issued for (IssuedTokens) before it is signed; a token that cannot be
 * recorded is not issued.
 */
final class Minter
{
    /**
     * Configured lifetime in seconds, kept within what every verifier accepts: person and auth tokens
     * with exp - iat above one hour are rejected (Jwt::MAX_PERSON_AUTH_LIFETIME), so a larger setting
     * is capped instead of producing tokens nobody can use.
     */
    public static function lifetime(string $key): int
    {
        return max(60, min(Jwt::MAX_PERSON_AUTH_LIFETIME, (int)config('df-aauth.' . $key, Jwt::MAX_PERSON_AUTH_LIFETIME)));
    }

    /** @return array{token: string, exp: int, sub: string} */
    public static function personToken(array $pending, array $user): array
    {
        $now = AAuth::now();
        $agent = $pending['agent'];
        $sub = Subjects::record((int)$user['id'], $pending['resource']);
        $exp = min($now + self::lifetime('person_token_ttl'), (int)($agent['exp'] ?? PHP_INT_MAX));
        $claims = [
            'iss' => Settings::issuer(),
            'dwk' => 'aauth-person.json',
            'aud' => $pending['resource'],
            'sub' => $sub,
            'cnf' => ['jwk' => $agent['jwk']],
            'jti' => Ids::random(),
            'iat' => $now,
            'exp' => $exp,
        ];
        foreach (['mission_s256', 'tenant'] as $copy) {
            if (isset($agent['extra'][$copy])) {
                $claims[$copy] = $agent['extra'][$copy];
            }
        }
        IssuedTokens::record($claims['jti'], 'person', $agent, $exp);

        return ['token' => Jwt::sign('aa-person+jwt', $claims, Keys::privateJwk('person')), 'exp' => $exp, 'sub' => $sub];
    }

    /** @return array{token: string, exp: int} */
    public static function authToken(array $pending, array $user, array $scopes): array
    {
        $now = AAuth::now();
        $agent = $pending['agent'];
        $issuer = Settings::issuer();
        $exp = min(
            $now + self::lifetime('auth_token_ttl'),
            (int)($agent['exp'] ?? PHP_INT_MAX),
            (int)($pending['presented_exp'] ?? PHP_INT_MAX)
        );
        $claims = [
            'iss' => $issuer,
            'dwk' => 'aauth-person.json',
            'aud' => $pending['resource'],
            'ps' => $issuer,
            'sub' => (string)$pending['sub'],
            'cnf' => ['jwk' => $agent['jwk']],
            'scope' => implode(' ', $scopes),
            'jti' => Ids::random(),
            'iat' => $now,
            'exp' => $exp,
        ];
        if (in_array('profile', $scopes, true)) {
            $claims['name'] = Users::displayName($user);
        }
        if (in_array('email', $scopes, true) && !empty($user['email'])) {
            $claims['email'] = (string)$user['email'];
        }
        foreach (['mission_s256', 'tenant', 'account'] as $copy) {
            if (isset($agent['extra'][$copy])) {
                $claims[$copy] = $agent['extra'][$copy];
            }
        }
        IssuedTokens::record($claims['jti'], 'auth', $agent, $exp);

        return ['token' => Jwt::sign('aa-auth+jwt', $claims, Keys::privateJwk('person')), 'exp' => $exp];
    }
}
