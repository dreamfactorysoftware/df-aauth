<?php

namespace DreamFactory\Core\AAuth\PersonServer;

use DreamFactory\Core\Exceptions\NotFoundException;
use Illuminate\Support\Facades\DB;

/** Standing "Always allow" grants: (person, resource, agent) -> scopes the PS approves without asking. */
final class Grants
{
    public const TABLE = 'aauth_ps_grants';

    public static function find(int $userId, string $resource, string $agentIss, string $agentSub): ?array
    {
        $row = DB::table(self::TABLE)->where('user_id', $userId)->where('resource', $resource)
            ->where('agent_iss', $agentIss)->where('agent_sub', $agentSub)->first();

        return $row ? self::decode($row) : null;
    }

    /** True when the grant covers every requested scope. */
    public static function covers(?array $grant, array $scopes): bool
    {
        return $grant !== null && $scopes !== [] && !array_diff($scopes, $grant['scopes']);
    }

    public static function save(int $userId, string $resource, ?string $resourceName, string $agentIss, string $agentSub, ?string $agentName, array $scopes): void
    {
        $existing = self::find($userId, $resource, $agentIss, $agentSub);
        $now = now();
        if ($existing) {
            $merged = array_values(array_unique(array_merge($existing['scopes'], $scopes)));
            DB::table(self::TABLE)->where('id', $existing['id'])->update([
                'scope' => implode(' ', $merged), 'agent_name' => $agentName, 'resource_name' => $resourceName,
            ]);

            return;
        }
        DB::table(self::TABLE)->insert([
            'user_id' => $userId, 'resource' => $resource, 'resource_name' => $resourceName,
            'agent_iss' => $agentIss, 'agent_sub' => $agentSub, 'agent_name' => $agentName,
            'scope' => implode(' ', array_values(array_unique($scopes))), 'created_at' => $now,
        ]);
    }

    public static function touch(int $id): void
    {
        DB::table(self::TABLE)->where('id', $id)->update(['last_used_at' => now()]);
    }

    public static function forUser(int $userId): array
    {
        return DB::table(self::TABLE)->where('user_id', $userId)->orderByDesc('created_at')->get()
            ->map(fn ($r) => self::decode($r))->all();
    }

    public static function get(int $id): array
    {
        $one = self::list($id);
        if (!$one) {
            throw new NotFoundException("Grant $id not found.");
        }

        return $one[0];
    }

    public static function list(?int $id = null): array
    {
        $q = DB::table(self::TABLE . ' as g')->leftJoin('user as u', 'u.id', '=', 'g.user_id')
            ->orderByDesc('g.created_at')->orderByDesc('g.id');
        if ($id !== null) {
            $q->where('g.id', $id);
        }
        $rows = $q->get(['g.*', 'u.email as user_email', 'u.name as user_name']);
        $out = [];
        foreach ($rows as $r) {
            $g = self::decode($r);
            $out[] = [
                'id' => $g['id'], 'user_id' => $g['user_id'], 'user_email' => $r->user_email, 'user_name' => $r->user_name,
                'resource' => $g['resource'], 'resource_name' => $g['resource_name'], 'agent_sub' => $g['agent_sub'],
                'agent_iss' => $g['agent_iss'], 'agent_name' => $g['agent_name'], 'scope' => implode(' ', $g['scopes']),
                'created_at' => \DreamFactory\Core\AAuth\Support\AAuth::iso($g['created_at']), 'last_used_at' => \DreamFactory\Core\AAuth\Support\AAuth::iso($g['last_used_at']),
            ];
        }

        return $out;
    }

    public static function delete(int $id, ?int $userId = null): array
    {
        $q = DB::table(self::TABLE)->where('id', $id);
        if ($userId !== null) {
            $q->where('user_id', $userId);
        }
        if (!$q->delete()) {
            throw new NotFoundException("Grant $id not found.");
        }

        return ['id' => $id];
    }

    private static function decode(object $row): array
    {
        $r = (array)$row;
        $r['id'] = (int)$r['id'];
        $r['user_id'] = (int)$r['user_id'];
        $r['scopes'] = array_values(array_filter(explode(' ', (string)$r['scope'])));

        return $r;
    }
}
