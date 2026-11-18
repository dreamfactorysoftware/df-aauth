<?php

namespace DreamFactory\Core\AAuth\Support;

use Illuminate\Support\Facades\DB;

/** Read-only lookups of DreamFactory users and their role assignments (no Session side effects). */
final class Users
{
    public static function find(int $id): ?array
    {
        $row = DB::table('user')->where('id', $id)->first(['id', 'name', 'first_name', 'last_name', 'email', 'is_sys_admin', 'is_active']);

        return $row ? (array)$row : null;
    }

    public static function displayName(array $user): string
    {
        $name = trim((string)($user['name'] ?? ''));
        $full = trim(($user['first_name'] ?? '') . ' ' . ($user['last_name'] ?? ''));
        // LDAP / AD shadow users can carry a one-letter name (df-adldap stores the first character of cn)
        if ($name === '' || (mb_strlen($name) < 2 && $full !== '')) {
            $name = $full;
        }

        return $name !== '' ? $name : (string)($user['email'] ?? '');
    }

    /**
     * What "Continue as ..." calls the person: the first name, else the first word of the name; ''
     * when there is only an email, or the name is too long for a button.
     */
    public static function firstName(array $user): string
    {
        $first = trim((string)($user['first_name'] ?? ''));
        if ($first === '') {
            $name = trim((string)($user['name'] ?? ''));
            $first = $name === '' || str_contains($name, '@') ? '' : (string)preg_split('/\s+/u', $name)[0];
        }

        return mb_strlen($first) <= 16 ? $first : '';
    }

    /** @return int[] role ids assigned to the user in any app */
    public static function roleIds(int $userId): array
    {
        return array_values(array_unique(array_map('intval',
            DB::table('user_to_app_to_role')->where('user_id', $userId)->pluck('role_id')->all())));
    }
}
