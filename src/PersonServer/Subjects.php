<?php

namespace DreamFactory\Core\AAuth\PersonServer;

use DreamFactory\Core\AAuth\Protocol\B64;
use Illuminate\Support\Facades\DB;

/**
 * Pairwise subject identifiers (protocol §14.1): one stable `sub` per (person, resource), the same
 * for every agent. sub = base64url(HMAC-SHA256(APP_KEY-derived secret, "user_id|resource"))[0..22).
 * Rows are written when a token is minted so the local resource can map sub -> DF user.
 */
final class Subjects
{
    public const TABLE = 'aauth_ps_subjects';

    public static function pairwise(int $userId, string $resource): string
    {
        $secret = hash_hmac('sha256', 'df-aauth/pairwise-sub/v1', (string)config('app.key', ''), true);

        return substr(B64::url(hash_hmac('sha256', $userId . '|' . $resource, $secret, true)), 0, 22);
    }

    /** Computes the sub and records the mapping. */
    public static function record(int $userId, string $resource): string
    {
        $sub = self::pairwise($userId, $resource);
        if (!DB::table(self::TABLE)->where('sub', $sub)->exists()) {
            try {
                DB::table(self::TABLE)->insert(['sub' => $sub, 'user_id' => $userId, 'resource' => mb_substr($resource, 0, 255), 'created_at' => now()]);
            } catch (\Throwable $e) {
                // concurrent insert of the same deterministic row
            }
        }

        return $sub;
    }

    public static function userFor(string $sub): ?int
    {
        $id = DB::table(self::TABLE)->where('sub', $sub)->value('user_id');

        return $id ? (int)$id : null;
    }

    /** @return array{user_id: int, resource: string}|null */
    public static function find(string $sub): ?array
    {
        $row = DB::table(self::TABLE)->where('sub', $sub)->first(['user_id', 'resource']);

        return $row ? ['user_id' => (int)$row->user_id, 'resource' => (string)$row->resource] : null;
    }
}
