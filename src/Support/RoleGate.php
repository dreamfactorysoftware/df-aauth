<?php

namespace DreamFactory\Core\AAuth\Support;

use DreamFactory\Core\Enums\ServiceRequestorTypes;
use DreamFactory\Core\Enums\Verbs;
use DreamFactory\Core\Models\Role;
use DreamFactory\Core\Utility\Session;

/**
 * The decision AccessCheck would make for a given role, without touching the caller's session:
 * snapshot the session, seed only that role (never a sys admin), evaluate, restore.
 */
final class RoleGate
{
    public static function role(int $roleId): ?array
    {
        try {
            $role = Role::getCachedInfo($roleId);
        } catch (\Throwable $e) {
            return null;
        }

        return is_array($role) ? $role : null;
    }

    public static function allows(int $roleId, string $service, ?string $resource, string $verb): bool
    {
        $role = self::role($roleId);
        if (!$role || empty($role['is_active'])) {
            return false;
        }
        $service = strtolower($service);
        $component = strtolower((string)$resource);
        $snapshot = \Session::all();
        try {
            \Session::forget('user');
            \Session::forget('role');
            \Session::put('app.id', null);
            \Session::put('has_role', true);
            Session::setRoleInfo($role);
            if (Session::checkServicePermission($verb, $service, $component, ServiceRequestorTypes::API, false)) {
                return true;
            }

            return strtoupper($verb) === Verbs::GET && $component === '_schema'
                && !empty(Session::getAllowedComponentsForGet($service, ServiceRequestorTypes::API));
        } catch (\Throwable $e) {
            return false;
        } finally {
            \Session::flush();
            \Session::put($snapshot);
        }
    }

    /** [row count, total verb bits] of a role's service access (privilege ordering). */
    public static function stats(int $roleId): array
    {
        $role = self::role($roleId);
        $rows = is_array($role['role_service_access_by_role_id'] ?? null) ? $role['role_service_access_by_role_id'] : [];
        $bits = 0;
        foreach ($rows as $r) {
            $mask = (int)(is_array($r) ? ($r['verb_mask'] ?? 0) : ($r->verb_mask ?? 0));
            $bits += substr_count(decbin($mask & 0x1f), '1');
        }

        return [count($rows), $bits];
    }
}
