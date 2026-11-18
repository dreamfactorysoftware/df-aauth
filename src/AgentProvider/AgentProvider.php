<?php

namespace DreamFactory\Core\AAuth\AgentProvider;

use DreamFactory\Core\AAuth\Protocol\Ids;
use DreamFactory\Core\AAuth\Protocol\Jwk;
use DreamFactory\Core\AAuth\Protocol\Jwt;
use DreamFactory\Core\AAuth\Support\AAuth;
use DreamFactory\Core\AAuth\Support\Keys;
use DreamFactory\Core\AAuth\Support\Settings;

/**
 * DreamFactory as an Agent Provider (/.well-known/aauth-agent.json): issues aa-agent+jwt tokens for
 * agents it hosts, today only the built-in Playground.
 */
final class AgentProvider
{
    public static function playgroundSubject(): string
    {
        return 'aauth:playground@' . Settings::issuerHost();
    }

    /**
     * Is this verified agent identity DreamFactory's own Playground? Only then do the consent pages
     * show the DreamFactory gear for it; any other agent gets a plain monogram, whatever it calls itself.
     */
    public static function isPlayground(?string $iss, ?string $sub): bool
    {
        $issuer = Settings::issuer();

        return $issuer !== null && $issuer !== '' && $iss === $issuer && $sub === self::playgroundSubject();
    }

    /** Agent token binding $agentPublicJwk (cnf) to $sub, with the agent's PS. */
    public static function agentToken(array $agentPublicJwk, string $sub, ?string $ps = null): string
    {
        $now = AAuth::now();
        $claims = [
            'iss' => Settings::issuer(),
            'dwk' => 'aauth-agent.json',
            'sub' => $sub,
            'cnf' => ['jwk' => Jwk::publicOf($agentPublicJwk)],
            'jti' => Ids::random(),
            'iat' => $now,
            'exp' => $now + max(60, min(86400, (int)config('df-aauth.agent_token_ttl', 3600))),
        ];
        if ($ps) {
            $claims['ps'] = $ps;
        }

        return Jwt::sign('aa-agent+jwt', $claims, Keys::privateJwk('agent'));
    }
}
