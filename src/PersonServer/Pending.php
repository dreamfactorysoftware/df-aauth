<?php

namespace DreamFactory\Core\AAuth\PersonServer;

use DreamFactory\Core\AAuth\Protocol\Ids;
use DreamFactory\Core\AAuth\Protocol\InteractionCode;
use DreamFactory\Core\AAuth\Support\Store;
use Illuminate\Support\Facades\Crypt;
use Illuminate\Support\Facades\DB;

/**
 * Deferred person/auth token requests (aauth_ps_pending).
 *
 * status: pending -> interacting (a browser claimed it: its first sign-in or decision) -> approved | denied
 *         approved -> delivered (token handed to the polling agent; later polls 410)
 *         denied / expired -> closed (after the agent was told once; later polls 410)
 *         cancelled (agent DELETE; later polls 410)
 *         failed (too many wrong sign-ins on its consent page; polls 410 invalid_code)
 */
final class Pending
{
    public const TABLE = 'aauth_ps_pending';
    public const LIVE = ['pending', 'interacting'];

    public static function create(string $kind, array $agent, string $resource, ?string $resourceName, array $extra = []): array
    {
        $now = now();
        $ttl = (int)config('df-aauth.pending_ttl', 600);
        for ($i = 0; $i < 5; $i++) {
            $code = InteractionCode::normalize(InteractionCode::generate());
            $clash = DB::table(self::TABLE)->where('code', $code)->whereIn('status', self::LIVE)->where('expires_at', '>', $now)->exists();
            if (!$clash) {
                break;
            }
        }
        $row = [
            'id' => substr(Ids::random(18), 0, 32),
            'kind' => $kind,
            'code' => $code,
            'status' => $extra['status'] ?? 'pending',
            'agent' => json_encode($agent, JSON_UNESCAPED_SLASHES),
            'resource' => mb_substr($resource, 0, 255),
            'resource_name' => $resourceName !== null ? mb_substr($resourceName, 0, 255) : null,
            'scope' => $extra['scope'] ?? null,
            'scope_descriptions' => isset($extra['scope_descriptions']) ? json_encode($extra['scope_descriptions'], JSON_UNESCAPED_SLASHES) : null,
            'justification' => isset($extra['justification']) ? mb_substr((string)$extra['justification'], 0, 1000) : null,
            'sub' => $extra['sub'] ?? null,
            'presented_exp' => $extra['presented_exp'] ?? null,
            'user_id' => $extra['user_id'] ?? null,
            'result' => null,
            'result_exp' => null,
            'created_at' => $now,
            'expires_at' => $now->copy()->addSeconds($ttl),
        ];
        DB::table(self::TABLE)->insert($row);
        if (random_int(1, 50) === 1) {
            self::prune();
        }

        return self::find($row['id']);
    }

    public static function find(string $id): ?array
    {
        $row = DB::table(self::TABLE)->where('id', $id)->first();

        return $row ? self::decode($row) : null;
    }

    /** Live (not terminal, not expired) request for a code typed or linked by the person. */
    public static function findLiveByCode(string $code): ?array
    {
        try {
            $norm = InteractionCode::normalize($code);
        } catch (\Throwable $e) {
            return null;
        }
        if ($norm === '') {
            return null;
        }
        $row = DB::table(self::TABLE)->where('code', $norm)->whereIn('status', self::LIVE)
            ->where('expires_at', '>', now())->orderByDesc('created_at')->first();

        return $row ? self::decode($row) : null;
    }

    /** The newest request for a code in any state (created in the last day), for outcome pages. */
    public static function findByCode(string $code): ?array
    {
        try {
            $norm = InteractionCode::normalize($code);
        } catch (\Throwable $e) {
            return null;
        }
        if ($norm === '') {
            return null;
        }
        $row = DB::table(self::TABLE)->where('code', $norm)->where('created_at', '>', now()->subDay())
            ->orderByDesc('created_at')->first();

        return $row ? self::decode($row) : null;
    }

    /**
     * Interaction codes are single-use (§11.6.3.1): the first browser that acts on a request (signs
     * in, starts single sign-on, decides, or types the code) owns it; any other browser presenting
     * the code later is refused. Opening the link does not claim it, so link previews and mail
     * scanners that fetch the link first cannot take it. Returns true when $browser owns $id.
     */
    public static function claim(array $p, string $browser): bool
    {
        $key = 'aauth:pid-owner:' . $p['id'];
        $ttl = max(60, (int)config('df-aauth.pending_ttl', 600) + 60);
        try {
            if (Store::cache()->add($key, $browser, $ttl)) {
                return true;
            }

            return Store::cache()->get($key) === $browser;
        } catch (\Throwable $e) {
            return true; // no cache: degrade to "code + CSRF session"
        }
    }

    /** Has another browser already claimed this request? Read-only (opening a link never claims). */
    public static function claimedElsewhere(array $p, string $browser): bool
    {
        try {
            $owner = Store::cache()->get('aauth:pid-owner:' . $p['id']);
        } catch (\Throwable $e) {
            return false; // no cache: degrade to "code + CSRF session", as claim() does
        }

        return is_string($owner) && $owner !== $browser;
    }

    /** Live requests of one agent (iss, sub), for the per-agent cap. */
    public static function liveCountForAgent(string $iss, string $sub): int
    {
        $n = 0;
        $rows = DB::table(self::TABLE)->whereIn('status', self::LIVE)->where('expires_at', '>', now())
            ->where('created_at', '>', now()->subSeconds((int)config('df-aauth.pending_ttl', 600) + 5))
            ->limit(500)->get(['agent']);
        foreach ($rows as $r) {
            $a = json_decode((string)$r->agent, true) ?: [];
            if (($a['iss'] ?? null) === $iss && ($a['sub'] ?? null) === $sub) {
                $n++;
            }
        }

        return $n;
    }

    /** Deletes requests that expired more than an hour ago (tokens inside are long expired too). */
    public static function prune(): int
    {
        try {
            return DB::table(self::TABLE)->where('expires_at', '<', now()->subHour())->delete();
        } catch (\Throwable $e) {
            return 0;
        }
    }

    public static function isLive(array $p): bool
    {
        return in_array($p['status'], self::LIVE, true) && !self::isExpired($p);
    }

    public static function isExpired(array $p): bool
    {
        return $p['expires_at'] !== null && \Illuminate\Support\Carbon::parse($p['expires_at'])->lte(now());
    }

    public static function markInteracting(string $id): void
    {
        DB::table(self::TABLE)->where('id', $id)->where('status', 'pending')->update(['status' => 'interacting']);
    }

    public static function approve(string $id, string $token, int $exp, ?int $userId = null, ?string $sub = null): bool
    {
        $update = ['status' => 'approved', 'result' => Crypt::encryptString($token), 'result_exp' => $exp];
        if ($userId !== null) {
            $update['user_id'] = $userId;
        }
        if ($sub !== null) {
            $update['sub'] = $sub;
        }

        return DB::table(self::TABLE)->where('id', $id)->whereIn('status', self::LIVE)->update($update) > 0;
    }

    public static function deny(string $id, ?int $userId = null): bool
    {
        $update = ['status' => 'denied'];
        if ($userId !== null) {
            $update['user_id'] = $userId;
        }

        return DB::table(self::TABLE)->where('id', $id)->whereIn('status', self::LIVE)->update($update) > 0;
    }

    /** Too many wrong sign-ins on the consent page: the request ends (polls get 410 invalid_code). */
    public static function fail(string $id): bool
    {
        return DB::table(self::TABLE)->where('id', $id)->whereIn('status', self::LIVE)->update(['status' => 'failed']) > 0;
    }

    public static function setStatus(string $id, string $status): void
    {
        DB::table(self::TABLE)->where('id', $id)->update(['status' => $status]);
    }

    public static function result(array $p): ?string
    {
        return $p['result'] ? Crypt::decryptString($p['result']) : null;
    }

    /**
     * What the polling agent gets now, and the state transition.
     *
     * @return array{0: int, 1: array} [status, body]  (body has 'token' for 200)
     */
    public static function poll(array $p): array
    {
        switch ($p['status']) {
            case 'approved':
                self::setStatus($p['id'], 'delivered');

                return [200, ['token' => self::result($p), 'expires_in' => max(0, (int)$p['result_exp'] - time())]];
            case 'denied':
                self::setStatus($p['id'], 'closed');

                return [403, ['error' => 'denied', 'detail' => 'The person denied the request.']];
            case 'pending':
            case 'interacting':
                if (self::isExpired($p)) {
                    self::setStatus($p['id'], 'closed');

                    return [408, ['error' => 'expired', 'detail' => 'The request expired before the person answered.']];
                }

                return [202, ['status' => $p['status']]];
            default: // delivered, closed, cancelled, expired
                return [410, ['error' => 'invalid_code', 'detail' => 'This pending request is finished.']];
        }
    }

    public static function displayCode(string $code): string
    {
        return strlen($code) === 8 ? substr($code, 0, 4) . '-' . substr($code, 4) : $code;
    }

    private static function decode(object $row): array
    {
        $r = (array)$row;
        $r['agent'] = json_decode((string)$r['agent'], true) ?: [];
        $r['scope_descriptions'] = $r['scope_descriptions'] ? (json_decode($r['scope_descriptions'], true) ?: []) : [];
        $r['user_id'] = $r['user_id'] !== null ? (int)$r['user_id'] : null;
        $r['presented_exp'] = $r['presented_exp'] !== null ? (int)$r['presented_exp'] : null;
        $r['expires_at'] = $r['expires_at'] !== null ? (string)$r['expires_at'] : null;

        return $r;
    }
}
