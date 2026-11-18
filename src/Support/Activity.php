<?php

namespace DreamFactory\Core\AAuth\Support;

use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Log;

/** One aauth_activity row per AAuth-signed API request (every outcome). Never throws. */
final class Activity
{
    public const TABLE = 'aauth_activity';
    public const OUTCOMES = ['allowed', 'person_required', 'auth_required', 'denied', 'blocked', 'error'];

    public static function log(array $row): void
    {
        try {
            $data = [
                'created_at' => now(),
                'agent_row_id' => $row['agent_row_id'] ?? null,
                'agent_id' => self::cut($row['agent_id'] ?? null, 255),
                'ps_issuer' => self::cut($row['ps_issuer'] ?? null, 255),
                'person_sub' => self::cut($row['person_sub'] ?? null, 255),
                'user_id' => $row['user_id'] ?? null,
                'scope' => self::cut($row['scope'] ?? null, 255),
                'method' => self::cut((string)($row['method'] ?? 'GET'), 12),
                'path' => self::cut((string)($row['path'] ?? ''), 512),
                'status' => (int)($row['status'] ?? 0),
                'outcome' => in_array($row['outcome'] ?? '', self::OUTCOMES, true) ? $row['outcome'] : 'error',
                'detail' => self::cut($row['detail'] ?? null, 255),
            ];
            DB::table(self::TABLE)->insert($data);
            if (random_int(1, 100) === 1) {
                self::prune();
            }
        } catch (\Throwable $e) {
            Log::warning('df-aauth: activity not recorded: ' . $e->getMessage());
        }
    }

    /** Full housekeeping (Maintenance::prune); returns the activity rows removed. */
    public static function prune(): int
    {
        return Maintenance::prune()['activity'];
    }

    private static function cut(?string $v, int $len): ?string
    {
        return $v === null ? null : mb_substr($v, 0, $len);
    }
}
