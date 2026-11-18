<?php

namespace DreamFactory\Core\AAuth\Support;

use DreamFactory\Core\AAuth\Resource\Scopes;

/** The three well-known documents DreamFactory publishes (resource, person server, agent provider). */
final class Metadata
{
    public static function resource(): array
    {
        $iss = Settings::issuer();

        return [
            'issuer' => $iss,
            'jwks_uri' => $iss . '/aauth/jwks/resource.json',
            'name' => Settings::instanceName(),
            'access_mode' => 'auth-token',
            'authorization_endpoint' => $iss . '/aauth/authorize',
            'scope_descriptions' => (object)Scopes::descriptions(),
            'signature_window' => (int)config('df-aauth.signature_window', 60),
            // @query when the URL has a query; content-type and content-digest whenever there is a body
            'additional_signature_components' => ['@query', 'content-type', 'content-digest'],
        ];
    }

    public static function person(): array
    {
        $iss = Settings::issuer();

        return [
            'issuer' => $iss,
            'jwks_uri' => $iss . '/aauth/jwks/person.json',
            'person_token_endpoint' => $iss . '/aauth/person',
            'auth_token_endpoint' => $iss . '/aauth/token',
            'scopes_supported' => ['profile', 'email'],
            'claims_supported' => ['sub', 'name', 'email'],
            'name' => Settings::instanceName(),
            'accept_signature_algs' => ['Ed25519', 'ES256'],
        ];
    }

    public static function agent(): array
    {
        $iss = Settings::issuer();

        return [
            'issuer' => $iss,
            'jwks_uri' => $iss . '/aauth/jwks/agent.json',
            'name' => (string)config('df-aauth.playground_agent_name', 'DreamFactory Playground'),
        ];
    }

    /** Document for a dwk name, or null. */
    public static function forDwk(string $dwk): ?array
    {
        return match ($dwk) {
            'aauth-resource.json' => self::resource(),
            'aauth-person.json' => Settings::localPersonServerEnabled() ? self::person() : null,
            'aauth-agent.json' => self::agent(),
            default => null,
        };
    }
}
