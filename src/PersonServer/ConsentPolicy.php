<?php

namespace DreamFactory\Core\AAuth\PersonServer;

use DreamFactory\Core\AAuth\Resource\Scopes;
use DreamFactory\Core\AAuth\Support\Settings;
use DreamFactory\Core\AAuth\Support\Users;

/**
 * "People can grant only what they have": for this DreamFactory as the resource, a scope can be
 * granted by a sys admin, or by a user who holds the scope's role (in any app). Identity scopes
 * (profile, email) are always grantable. For external resources every requested scope is the
 * person's to give.
 */
final class ConsentPolicy
{
    /** @return array<string, bool> scope => grantable */
    public static function grantable(array $user, array $scopes, string $resource): array
    {
        $out = [];
        if ($resource !== Settings::issuer()) {
            foreach ($scopes as $s) {
                $out[$s] = true;
            }

            return $out;
        }
        $admin = (bool)($user['is_sys_admin'] ?? false);
        $roles = $admin ? [] : Users::roleIds((int)$user['id']);
        $enabled = Scopes::enabledByName();
        foreach ($scopes as $s) {
            if (in_array($s, Scopes::IDENTITY, true)) {
                $out[$s] = true;
            } elseif (!isset($enabled[$s])) {
                $out[$s] = false;
            } else {
                $out[$s] = $admin || in_array((int)$enabled[$s]['role_id'], $roles, true);
            }
        }

        return $out;
    }
}
