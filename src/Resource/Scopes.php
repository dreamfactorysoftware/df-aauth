<?php

namespace DreamFactory\Core\AAuth\Resource;

use DreamFactory\Core\Exceptions\BadRequestException;
use DreamFactory\Core\Exceptions\NotFoundException;
use DreamFactory\Core\AAuth\PersonServer\Grants;
use DreamFactory\Core\AAuth\Protocol\Jwt;
use DreamFactory\Core\AAuth\Support\Settings;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Facades\Schema;

/** aauth_scopes: one row per DreamFactory role that agents may ask for (a scope IS a role). */
final class Scopes
{
    public const TABLE = 'aauth_scopes';
    public const PATTERN = '/^[a-z0-9][a-z0-9._:-]{0,63}$/';
    public const IDENTITY = ['profile', 'email'];
    private const RETIRED = 'retired_scopes';
    /** The holder of a deleted role's reservations: no role id, so no later role can claim them. */
    public const NO_ROLE = 0;

    /** @var array<int, ?string> scope names of roles being deleted (roleDeleting -> roleDeleted, or finishDeletes) */
    private static array $deleting = [];

    /** @return array<int, array> enabled scope rows (role_id, scope, description, role_name, scope_since) */
    public static function enabled(): array
    {
        try {
            return DB::table(self::TABLE . ' as s')
                ->leftJoin('role as r', 'r.id', '=', 's.role_id')
                ->where('s.enabled', true)
                ->orderBy('s.role_id')
                ->get(['s.role_id', 's.scope', 's.description', 'r.name as role_name', 's.scope_since'])
                ->map(fn ($r) => (array)$r)->all();
        } catch (\Throwable $e) {
            return [];
        }
    }

    public static function enabledByName(): array
    {
        $out = [];
        foreach (self::enabled() as $row) {
            $out[$row['scope']] = $row;
        }

        return $out;
    }

    /** scope => description (or role name) for the resource metadata. */
    public static function descriptions(): array
    {
        $out = [];
        foreach (self::enabled() as $row) {
            $d = trim((string)($row['description'] ?? ''));
            $out[$row['scope']] = $d !== '' ? $d : (string)($row['role_name'] ?? $row['scope']);
        }

        return $out;
    }

    /** All roles with their scope configuration (unconfigured roles get a suggested slug, disabled). */
    public static function all(): array
    {
        $rows = DB::table('role as r')
            ->leftJoin(self::TABLE . ' as s', 's.role_id', '=', 'r.id')
            ->orderBy('r.name')
            ->get(['r.id as role_id', 'r.name as role_name', 'r.description as role_description', 's.scope', 's.description', 's.enabled']);
        $out = [];
        foreach ($rows as $r) {
            $out[] = self::wire((array)$r);
        }

        return $out;
    }

    public static function get(int $roleId): array
    {
        $r = DB::table('role as r')
            ->leftJoin(self::TABLE . ' as s', 's.role_id', '=', 'r.id')
            ->where('r.id', $roleId)
            ->first(['r.id as role_id', 'r.name as role_name', 'r.description as role_description', 's.scope', 's.description', 's.enabled']);
        if (!$r) {
            throw new NotFoundException("Role $roleId not found.");
        }

        return self::wire((array)$r);
    }

    public static function patch(int $roleId, array $data): array
    {
        $current = self::get($roleId);
        $existing = DB::table(self::TABLE)->where('role_id', $roleId)->first();
        $update = [];
        if (array_key_exists('scope', $data)) {
            $scope = strtolower(trim((string)$data['scope']));
            if (!preg_match(self::PATTERN, $scope)) {
                throw new BadRequestException('Scope must be 1-64 characters: lowercase letters, digits, and . _ : - (starting with a letter or digit).');
            }
            if (in_array($scope, self::IDENTITY, true)) {
                throw new BadRequestException("'$scope' is reserved for identity claims.");
            }
            if (DB::table(self::TABLE)->where('scope', $scope)->where('role_id', '<>', $roleId)->exists()) {
                throw new BadRequestException("Scope '$scope' is already used by another role.");
            }
            // a role re-sending the name it holds takes nothing, whatever reservation names it
            $retiredBy = $existing && $scope === $existing->scope ? null : self::retiredBy($scope);
            if ($retiredBy !== null && $retiredBy !== $roleId) {
                throw new BadRequestException("Scope '$scope' belonged to another role until recently, and auth tokens issued for it may still be in use. Choose another name, or try again in an hour.");
            }
            $update['scope'] = $scope;
        }
        if (array_key_exists('description', $data)) {
            $d = $data['description'];
            $update['description'] = $d === null ? null : mb_substr(trim((string)$d), 0, 1000);
        }
        if (array_key_exists('enabled', $data)) {
            $update['enabled'] = filter_var($data['enabled'], FILTER_VALIDATE_BOOLEAN);
        }
        $now = now();
        if ($existing) {
            $renamed = isset($update['scope']) && $update['scope'] !== $existing->scope;
            if ($renamed) {
                $update['scope_since'] = $now->getTimestamp();
            }
            // One transaction: a rename whose cleanup fails is not made, so retrying it redoes both.
            // A name the role takes starts with no grants or allow-list entries (left behind, for
            // instance, by a deleted role whose cleanup failed); then the old name's move to it.
            DB::transaction(function () use ($update, $roleId, $now, $renamed, $existing) {
                if ($update) {
                    DB::table(self::TABLE)->where('role_id', $roleId)->update($update + ['updated_at' => $now]);
                }
                if ($renamed) {
                    self::forget($update['scope'], null);
                    self::retire((string)$existing->scope, $roleId, $update['scope']);
                }
            });
        } else {
            $scope = $update['scope'] ?? self::uniqueSlug($current['scope'], $roleId);
            DB::transaction(function () use ($roleId, $scope, $update, $now) {
                DB::table(self::TABLE)->insert([
                    'role_id' => $roleId,
                    'scope' => $scope,
                    'description' => $update['description'] ?? null,
                    'enabled' => $update['enabled'] ?? false,
                    'scope_since' => $now->getTimestamp(),
                    'created_at' => $now,
                    'updated_at' => $now,
                ]);
                self::forget($scope, null);
            });
        }

        return self::get($roleId);
    }

    /**
     * A role is about to be deleted (eloquent.deleting). Nothing the role can notice changes yet,
     * because the delete can still fail (a foreign key without ON DELETE CASCADE, such as a login
     * service's default role): the role's scope name is noted for roleDeleted() (its aauth_scopes row
     * goes with the role through the cascade) and reserved for no role (NO_ROLE). While the role
     * exists that changes nothing: a role may always re-send its own name (patch()), and renaming
     * away from it reserves it for the role again (retire()). Should the cleanup after the delete
     * never run or fail, the name is already out of reach of a role that gets the deleted role's id.
     * The names the role renamed away earlier stay its own until the row is gone, so a role whose
     * delete is refused can still take them back. Throws when the reservation cannot be stored; the
     * listener then refuses the delete.
     */
    public static function roleDeleting(int $roleId): void
    {
        if (!Schema::hasTable(self::TABLE)) {
            return; // AAuth's tables are not set up: no scope to give up
        }
        $scope = DB::table(self::TABLE)->where('role_id', $roleId)->value('scope');
        $scope = is_string($scope) && $scope !== '' ? $scope : null;
        self::$deleting[$roleId] = $scope;
        if ($scope !== null) {
            self::changeReservations(function (array $list) use ($scope) {
                $list[$scope] = ['role_id' => self::NO_ROLE, 'until' => max((int)($list[$scope]['until'] ?? 0), time() + self::reserved())];

                return $list;
            });
        }
    }

    /**
     * The role row is gone (eloquent.deleted; inside the caller's transaction when the delete runs in
     * one): its scope name is given up, in one transaction. The scope row is dropped (when no foreign
     * key cascade did it); the name it held at the delete (the noted one, followed through a rename
     * that raced the delete) leaves grants and allow-lists (a grant left with no scope is deleted);
     * that name and the names the role gave up earlier are reserved for no role (NO_ROLE): MySQL 5.7
     * hands the highest deleted id to the next new role after a restart, which must not inherit them.
     * Throws when this cannot be done, and the role stays noted, so finishDeletes() tries again when
     * the request ends; a name that stays in a grant is still never inherited, because a role that
     * takes a name starts without its grants (patch()).
     */
    public static function roleDeleted(int $roleId): void
    {
        if (!Schema::hasTable(self::TABLE)) {
            unset(self::$deleting[$roleId]);

            return;
        }
        $noted = self::$deleting[$roleId] ?? null;
        DB::transaction(function () use ($roleId, $noted) {
            $row = DB::table(self::TABLE)->where('role_id', $roleId)->value('scope');
            DB::table(self::TABLE)->where('role_id', $roleId)->delete();
            $names = [];
            self::changeReservations(function (array $list) use ($roleId, $noted, $row, &$names) {
                $names = self::namesAtDelete($list, $roleId, [$noted, is_string($row) ? $row : null]);
                foreach ($list as $name => $v) {
                    if ((int)$v['role_id'] === $roleId) {
                        $list[$name]['role_id'] = self::NO_ROLE;
                    }
                }
                foreach ($names as $name) {
                    $list[$name] = ['role_id' => self::NO_ROLE, 'until' => max((int)($list[$name]['until'] ?? 0), time() + self::reserved())];
                }

                return $list;
            });
            foreach ($names as $name) {
                self::forget($name, null);
            }
        });
        unset(self::$deleting[$roleId]);
    }

    /**
     * When the request ends (ServiceProvider::flushState): a role noted by roleDeleting() whose row is
     * gone but whose cleanup did not run (a deleted listener registered before df-aauth's threw) or
     * failed gets it now, once; the other notes (deletes that were refused or rolled back) are
     * dropped. Never throws.
     */
    public static function finishDeletes(): void
    {
        if (self::$deleting === []) {
            return;
        }
        foreach (array_keys(self::$deleting) as $roleId) {
            try {
                if (!DB::table('role')->where('id', $roleId)->exists()) {
                    self::roleDeleted((int)$roleId);
                    Log::notice('df-aauth: role ' . $roleId . ' deleted; its AAuth scope name was removed from grants and person server lists when the request ended.');
                }
            } catch (\Throwable $e) {
                Log::error('df-aauth: role ' . $roleId . ' deleted, but its AAuth scope name could not be removed from grants and person server lists: ' . $e->getMessage());
            }
        }
        self::$deleting = [];
    }

    /**
     * The scope names a role held when its row went: the name noted before the delete (or still in its
     * scope row), followed through the renames recorded since (retire() keeps each successor), so the
     * name of a rename that raced the delete is given up too. Names another role holds are left out.
     *
     * @param list<?string> $starts
     * @return list<string>
     */
    private static function namesAtDelete(array $list, int $roleId, array $starts): array
    {
        $names = [];
        foreach ($starts as $name) {
            while (is_string($name) && $name !== '' && !isset($names[$name])) {
                $names[$name] = true;
                $entry = $list[$name] ?? null;
                $name = is_array($entry) && (int)($entry['role_id'] ?? -1) === $roleId ? ($entry['to'] ?? null) : null;
            }
        }
        $names = array_map('strval', array_keys($names));
        $held = $names === [] ? [] : array_map('strval', DB::table(self::TABLE)->whereIn('scope', $names)->pluck('scope')->all());

        return array_values(array_diff($names, $held));
    }

    /**
     * A role gives up a scope name (renamed to $successor). The name stays reserved for that role for
     * reserved() seconds, and every reference to it at this DreamFactory goes with the role (forget).
     * The reservation is stored in the system database (aauth_settings retired_scopes), so every
     * DreamFactory node sees it and no cache eviction can release it early. It also keeps the
     * successor, so a role delete that this rename raced gives up the new name too (namesAtDelete()).
     */
    public static function retire(string $scope, int $roleId, ?string $successor = null): void
    {
        $entry = ['role_id' => $roleId, 'until' => time() + self::reserved()] + ($successor !== null ? ['to' => $successor] : []);
        DB::transaction(function () use ($scope, $entry, $successor) {
            self::changeReservations(fn (array $list) => [$scope => $entry] + $list);
            self::forget($scope, $successor);
        });
    }

    /**
     * Person server allow-lists and standing grants for this resource move from $scope to $successor,
     * or lose it ($successor null; a grant left with no scope is deleted), so a later role that takes
     * the name inherits no trust and no "Always allow". Person servers set to every scope stay so.
     */
    private static function forget(string $scope, ?string $successor): void
    {
        $replace = fn (array $names) => array_values(array_unique(array_filter(
            array_map(fn ($s) => $s === $scope ? $successor : $s, $names), fn ($s) => $s !== null)));
        foreach (DB::table(PersonServers::TABLE)->whereNotNull('scopes')->get(['id', 'scopes']) as $row) {
            $names = json_decode((string)$row->scopes, true);
            if (is_array($names) && in_array($scope, $names, true)) {
                // an emptied list stays a list ('[]' = no scopes), never null (= every scope)
                DB::table(PersonServers::TABLE)->where('id', $row->id)->update(['scopes' => json_encode($replace($names))]);
            }
        }
        $issuer = Settings::issuer();
        if ($issuer) {
            foreach (DB::table(Grants::TABLE)->where('resource', $issuer)->get(['id', 'scope']) as $row) {
                $names = array_values(array_filter(explode(' ', (string)$row->scope)));
                if (!in_array($scope, $names, true)) {
                    continue;
                }
                $names = $replace($names);
                if ($names === []) {
                    DB::table(Grants::TABLE)->where('id', $row->id)->delete();
                } else {
                    DB::table(Grants::TABLE)->where('id', $row->id)->update(['scope' => implode(' ', $names)]);
                }
            }
        }
    }

    /**
     * Seconds a given-up scope name stays reserved: the longest auth token lifetime DreamFactory
     * accepts from any person server (Jwt::MAX_PERSON_AUTH_LIFETIME; DreamFactory's own tokens are
     * capped there too), plus the minute a token's iat may lie in the future. A token minted for the
     * old holder after the name was given up (an external person server's late approval) can outlive
     * this; heldAt() refuses it.
     */
    public static function reserved(): int
    {
        return Jwt::MAX_PERSON_AUTH_LIFETIME + Jwt::IAT_LEEWAY;
    }

    /**
     * Did the scope's role hold this name when a token issued at $iat granted it? A token issued
     * before the role took the name (scope_since: row created or renamed) was issued for an earlier
     * holder, a deleted or renamed role, and must not reach this one. Rows from before scope_since
     * existed (null) are not constrained.
     */
    public static function heldAt(array $row, int $iat): bool
    {
        $since = $row['scope_since'] ?? null;

        return $since === null || $iat >= (int)$since;
    }

    /** Drops expired reservations; returns how many there were (none are removed when $dryRun). */
    public static function pruneRetired(bool $dryRun = false): int
    {
        $all = Settings::get(self::RETIRED, []);
        $all = is_array($all) ? $all : [];
        $expired = count($all) - count(self::live($all));
        if ($expired > 0 && !$dryRun) {
            self::changeReservations(fn (array $list) => $list);
        }

        return $expired;
    }

    /** @return array<string, array{role_id: int, until: int}> live reservations */
    private static function retiredList(): array
    {
        $list = Settings::get(self::RETIRED, []);

        return is_array($list) ? self::live($list) : [];
    }

    private static function live(array $list): array
    {
        $now = time();

        return array_filter($list, fn ($v) => is_array($v) && isset($v['role_id']) && (int)($v['until'] ?? 0) > $now);
    }

    /**
     * Rewrites the reservation list under a row lock, from the stored value (never a per-request
     * memo), dropping expired entries: writers on other nodes and the daily prune cannot drop each
     * other's reservations.
     */
    private static function changeReservations(\Closure $change): void
    {
        if (!DB::table(Settings::TABLE)->where('name', self::RETIRED)->exists()) {
            try {
                // its own savepoint: a concurrent insert fails here without aborting an outer transaction
                DB::transaction(fn () => DB::table(Settings::TABLE)->insert(['name' => self::RETIRED, 'value' => '{}', 'updated_at' => now()]));
            } catch (\Throwable $e) {
                if (!DB::table(Settings::TABLE)->where('name', self::RETIRED)->exists()) {
                    throw $e;
                }
            }
        }
        DB::transaction(function () use ($change) {
            $stored = json_decode((string)DB::table(Settings::TABLE)->where('name', self::RETIRED)->lockForUpdate()->value('value'), true);
            Settings::set(self::RETIRED, $change(self::live(is_array($stored) ? $stored : [])));
        });
    }

    /** The role that recently gave up this scope name, if any. */
    private static function retiredBy(string $scope): ?int
    {
        $v = self::retiredList()[$scope] ?? null;

        return $v === null ? null : (int)$v['role_id'];
    }

    public static function slug(string $name): string
    {
        $s = strtolower(trim($name));
        $s = preg_replace('/[^a-z0-9._:-]+/', '-', $s) ?? '';
        $s = trim($s, '-._:');
        if ($s === '' || in_array($s, self::IDENTITY, true)) {
            $s = 'role-' . ($s === '' ? 'x' : $s);
        }

        return substr($s, 0, 64);
    }

    private static function uniqueSlug(string $slug, int $roleId): string
    {
        $retiredBy = self::retiredBy($slug);
        if (!DB::table(self::TABLE)->where('scope', $slug)->exists() && ($retiredBy === null || $retiredBy === $roleId)) {
            return $slug;
        }

        return substr($slug, 0, 54) . '-' . $roleId;
    }

    private static function wire(array $r): array
    {
        $configured = $r['scope'] !== null;

        return [
            'role_id' => (int)$r['role_id'],
            'role_name' => (string)$r['role_name'],
            'role_description' => $r['role_description'],
            'scope' => $configured ? (string)$r['scope'] : self::slug((string)$r['role_name']),
            'description' => $configured ? $r['description'] : null,
            'enabled' => $configured && (bool)$r['enabled'],
        ];
    }
}
