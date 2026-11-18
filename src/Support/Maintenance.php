<?php

namespace DreamFactory\Core\AAuth\Support;

use DreamFactory\Core\AAuth\PersonServer\IssuedTokens;
use DreamFactory\Core\AAuth\PersonServer\Pending;
use DreamFactory\Core\AAuth\Resource\Agents;
use DreamFactory\Core\AAuth\Resource\Scopes;
use Illuminate\Support\Facades\DB;

/**
 * Housekeeping (php artisan df:aauth prune, scheduled daily; also run on ~1% of activity inserts):
 *  - pending requests that expired more than an hour ago (the tokens inside are long expired),
 *  - activity older than DF_AAUTH_ACTIVITY_RETENTION_DAYS (0 = keep forever),
 *  - remembered agent keys not seen for the retention period (kept while retention is 0),
 *  - signing keys retired longer than the overlap window (private keys included),
 *  - expired scope-name reservations,
 *  - records of person and auth tokens that expired more than an hour ago.
 * Standing grants, pairwise subjects and policy are never pruned. Idempotent and safe on every node.
 */
final class Maintenance
{
    /** @var string[] errors of the last prune() (each step runs even when another fails) */
    public static array $errors = [];

    /** @return array{pending: int, activity: int, agent_keys: int, signing_keys: int, retired_scopes: int, issued_tokens: int} */
    public static function prune(bool $dryRun = false): array
    {
        self::$errors = [];

        return [
            'pending' => self::guard(fn () => self::pending($dryRun)),
            'activity' => self::guard(fn () => self::activity($dryRun)),
            'agent_keys' => self::guard(fn () => self::agentKeys($dryRun)),
            'signing_keys' => self::guard(fn () => Keys::prune($dryRun)),
            'retired_scopes' => self::guard(fn () => Scopes::pruneRetired($dryRun)),
            'issued_tokens' => self::guard(fn () => IssuedTokens::prune($dryRun)),
        ];
    }

    public static function pending(bool $dryRun = false): int
    {
        if (!$dryRun) {
            return Pending::prune();
        }

        return (int)DB::table(Pending::TABLE)->where('expires_at', '<', now()->subHour())->count();
    }

    public static function activity(bool $dryRun = false): int
    {
        $days = (int)config('df-aauth.activity_retention_days', 30);
        if ($days <= 0) {
            return 0;
        }
        $q = DB::table(Activity::TABLE)->where('created_at', '<', now()->subDays($days));

        return $dryRun ? (int)$q->count() : (int)$q->delete();
    }

    /** Remembered agent keys follow the activity retention (0 = keep forever, like the activity they attribute); blocked agents keep theirs. */
    public static function agentKeys(bool $dryRun = false): int
    {
        $days = (int)config('df-aauth.activity_retention_days', 30);
        if ($days <= 0) {
            return 0;
        }
        if (!$dryRun) {
            return Agents::pruneKeys();
        }

        return (int)Agents::staleKeys()->count();
    }

    private static function guard(\Closure $fn): int
    {
        try {
            return (int)$fn();
        } catch (\Throwable $e) {
            self::$errors[] = $e->getMessage();

            return 0;
        }
    }
}
