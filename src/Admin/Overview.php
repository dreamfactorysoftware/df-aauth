<?php

namespace DreamFactory\Core\AAuth\Admin;

use DreamFactory\Core\AAuth\Resource\PersonServers;
use DreamFactory\Core\AAuth\Support\BackingApp;
use DreamFactory\Core\AAuth\Support\Keys;
use DreamFactory\Core\AAuth\Support\Settings;
use DreamFactory\Core\Exceptions\BadRequestException;
use Illuminate\Support\Facades\DB;

final class Overview
{
    public static function get(): array
    {
        $issuer = Settings::issuer();
        $ok = Settings::issuerOk();

        return [
            'enabled' => (bool)Settings::get('enabled', false) && $ok,
            'issuer' => $issuer,
            'issuer_ok' => $ok,
            'urls' => [
                'resource_metadata' => $issuer ? $issuer . '/.well-known/aauth-resource.json' : null,
                'person_metadata' => $issuer ? $issuer . '/.well-known/aauth-person.json' : null,
                'agent_metadata' => $issuer ? $issuer . '/.well-known/aauth-agent.json' : null,
                'interact' => $issuer ? $issuer . '/aauth/interact' : null,
            ],
            'counts' => [
                'scopes_enabled' => (int)DB::table('aauth_scopes')->where('enabled', true)->count(),
                'person_servers' => (int)DB::table('aauth_person_servers')->where('enabled', true)->count(),
                'agents' => (int)DB::table('aauth_agents')->count(),
                'grants' => (int)DB::table('aauth_ps_grants')->count(),
                'activity_24h' => (int)DB::table('aauth_activity')->where('created_at', '>=', now()->subDay())->count(),
            ],
        ];
    }

    public static function patch(array $data): array
    {
        if (array_key_exists('enabled', $data)) {
            $on = filter_var($data['enabled'], FILTER_VALIDATE_BOOLEAN);
            if ($on && !Settings::issuerOk()) {
                throw new BadRequestException('Set DF_AAUTH_ISSUER to an https URL.');
            }
            if ($on) {
                foreach (Keys::PURPOSES as $purpose) {
                    Keys::publicJwk($purpose);
                }
                PersonServers::ensureLocal();
                BackingApp::id();
            }
            Settings::set('enabled', $on);
        }

        return self::get();
    }
}
