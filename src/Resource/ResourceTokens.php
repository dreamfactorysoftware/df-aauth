<?php

namespace DreamFactory\Core\AAuth\Resource;

use DreamFactory\Core\AAuth\Protocol\Ids;
use DreamFactory\Core\AAuth\Protocol\Jwt;
use DreamFactory\Core\AAuth\Support\AAuth;
use DreamFactory\Core\AAuth\Support\Keys;
use DreamFactory\Core\AAuth\Support\Settings;

/** Mints aa-resource+jwt tokens (protocol §6.7.1). */
final class ResourceTokens
{
    /**
     * @param array  $presented claims of the presented person or auth token
     * @param string $ps        the person server: person token iss, or auth token ps
     */
    public static function mint(array $presented, string $ps, string $agentJkt, string $scope): string
    {
        $now = AAuth::now();
        $claims = [
            'iss' => Settings::issuer(),
            'dwk' => 'aauth-resource.json',
            'aud' => $ps,
            'ps' => $ps,
            'sub' => (string)($presented['sub'] ?? ''),
            'presented_jti' => (string)($presented['jti'] ?? ''),
            'agent_jkt' => $agentJkt,
            'scope' => $scope,
            'jti' => Ids::random(),
            'iat' => $now,
            'exp' => $now + (int)config('df-aauth.resource_token_ttl', 300),
        ];
        foreach (['mission_s256', 'tenant'] as $copy) {
            if (isset($presented[$copy])) {
                $claims[$copy] = $presented[$copy];
            }
        }

        return Jwt::sign('aa-resource+jwt', $claims, Keys::privateJwk('resource'));
    }
}
