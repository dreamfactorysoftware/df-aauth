<?php

namespace DreamFactory\Core\AAuth\Resource;

use DreamFactory\Core\AAuth\PersonServer\IssuedTokens;
use DreamFactory\Core\AAuth\Protocol\AAuthError;
use DreamFactory\Core\AAuth\Support\Settings;
use DreamFactory\Core\Exceptions\BadRequestException;
use DreamFactory\Core\Exceptions\NotFoundException;
use Illuminate\Support\Facades\DB;

/**
 * Agents seen by this DreamFactory. Agent tokens name the agent (sub + agent provider issuer). Person
 * and auth tokens deliberately do not (three-party privacy):
 *  - a token this DreamFactory's person server issued belongs to the agent it was issued for
 *    (IssuedTokens, by jti), the agent that got the person's approval or standing grant;
 *  - a token from an external person server is attributed through the signing key: aauth_agent_keys
 *    holds one row for every agent a key has presented an agent token for, here at the resource or
 *    at the local person server (a binding history, not one overwritten row), and the newest binding
 *    names the agent. A key that never presented one stands in as "jkt:<first 12 chars>".
 * Agents that use this DreamFactory's person server are therefore always identified, whatever agent
 * id the key presents later; for an external person server a block covers only the keys DreamFactory
 * has seen, plus the stand-in.
 *
 * Blocks follow the key too: a key is refused while ANY agent it is bound to (or its stand-in) is
 * blocked, so an agent provider that puts a new sub in an agent token cannot move a key, or the
 * person and auth tokens bound to it, away from a block, before or after the block. Every decision
 * reads the system database (no cache can disagree with it), and a read that fails throws, so callers
 * fail closed (admit()). The admin API lists, for every agent, the other agents that share a key with
 * it (shares_key_with, one hop), so an admin can block all of them. A key may present agent tokens
 * for at most MAX_AGENTS_PER_KEY agent ids.
 */
final class Agents
{
    public const TABLE = 'aauth_agents';
    public const KEYS = 'aauth_agent_keys';
    /** A person server call updates the agent's last_seen_at at most this often (it is not counted as a request). */
    private const LISTED_TOUCH = 60;
    /**
     * Agent ids one signing key may present agent tokens for (a real agent presents one); an agent
     * token naming one more is refused (403 too_many_agents), so no key can spawn agent ids without end.
     */
    public const MAX_AGENTS_PER_KEY = 20;
    /** shares_key_with entries per agent in the list (GET /agents/{id} returns all of them). */
    public const LIST_SHARES = 20;

    /**
     * Who signed this verified request, recorded as an agent of this DreamFactory: an agent token
     * binds its key to the agent it names (rememberKey), person and auth tokens belong to the agent
     * they were issued for or, from an external person server, to their key (identityForToken).
     * $count counts the request (resource APIs); person server and authorization endpoint calls only
     * keep the agent listed, so it can be blocked. The caller refuses the request when the returned
     * row's status is 'blocked'. Throws AAuthError for a token of this person server it has no record
     * of (401) and for an agent token naming one agent id more than a key may use (403), and any other
     * exception when the system database cannot say: an unknown block state is never "allowed".
     *
     * @param array $v RequestVerifier::verify() result
     * @return array{0: array{agent_id: string, issuer: string, name: ?string}, 1: array} identity, aauth_agents row
     */
    public static function admit(array $v, bool $count): array
    {
        if (($v['typ'] ?? null) === RequestVerifier::AGENT) {
            $claims = $v['claims'];
            $name = isset($v['meta']['name']) && is_string($v['meta']['name']) ? $v['meta']['name'] : null;
            $identity = self::rememberKey($v['jkt'], (string)($claims['sub'] ?? ''), (string)($claims['iss'] ?? ''), $name);
        } else {
            $identity = self::identityForToken($v);
        }
        $agent = $count ? self::seen($identity['agent_id'], $identity['issuer'], $identity['name'] ?? null)
            : self::listed($identity['agent_id'], $identity['issuer'], $identity['name'] ?? null);
        if (!isset($agent['status'])) {
            throw new \RuntimeException('agent row not readable');
        }

        return [$identity, $agent];
    }

    /**
     * Records that a signing key presented an agent token naming this agent, and returns the agent the
     * request belongs to. A key bound to a blocked agent (or whose stand-in is blocked) gets no new
     * binding: the request stays that blocked agent's, whatever sub the token claims, and so do the
     * person and auth tokens issued to the key. Throws AAuthError (403 too_many_agents) when the key
     * is already bound to MAX_AGENTS_PER_KEY other agents, and any other exception when the system
     * database cannot be read.
     *
     * @return array{agent_id: string, issuer: string, name: ?string}
     */
    public static function rememberKey(string $jkt, string $agentId, string $issuer, ?string $name): array
    {
        $identity = ['agent_id' => mb_substr($agentId, 0, 255), 'issuer' => mb_substr($issuer, 0, 255), 'name' => $name !== null ? mb_substr($name, 0, 255) : null];
        $blocked = self::blockedBinding($jkt);
        if ($blocked !== null && !self::same($blocked, $identity)) {
            return $blocked;
        }
        self::bind($jkt, $identity);

        return $identity;
    }

    /**
     * The agent a person or auth token request belongs to. A token this DreamFactory's person server
     * issued belongs to the agent it was issued for, whatever agent id the key presented an agent token
     * for since: Activity, the request count and blocks follow the agent that got the approval or the
     * standing grant. A token from an external person server (which does not say) belongs to its key
     * (identityForKey). Either way a key bound to a blocked agent stays refused: when the agent the
     * token was issued for is allowed but another agent id the key used is blocked, the request is that
     * blocked agent's. Throws AAuthError (401 invalid_jwt) for a token of ours with no record, and any
     * other exception when the system database cannot be read.
     *
     * @return array{agent_id: string, issuer: string, name: ?string}
     */
    private static function identityForToken(array $v): array
    {
        if (($v['claims']['iss'] ?? null) !== Settings::issuer()) {
            return self::identityForKey($v['jkt']);
        }
        $issued = IssuedTokens::agentFor((string)($v['claims']['jti'] ?? ''));
        if ($issued === null) {
            throw AAuthError::signature('invalid_jwt', 'This DreamFactory has no record of issuing this token. Get a new one.');
        }
        if (self::isBlocked($issued['agent_id'], $issued['issuer'])) {
            return $issued;
        }

        return self::blockedBinding($v['jkt']) ?? $issued;
    }

    /**
     * The agent a key's requests belong to when the token does not say (tokens from external person
     * servers): a blocked agent the key is bound to, else the agent it most recently presented an agent
     * token for, else "jkt:<first 12 chars>". Throws when the system database cannot be read (the
     * block state would be unknown).
     *
     * @return array{agent_id: string, issuer: string, name: ?string}
     */
    public static function identityForKey(string $jkt): array
    {
        $blocked = self::blockedBinding($jkt);
        if ($blocked !== null) {
            return $blocked;
        }
        $row = DB::table(self::KEYS)->where('jkt', $jkt)->orderByDesc('last_seen_at')->orderByDesc('id')
            ->first(['agent_id', 'issuer', 'name']);

        return $row ? self::binding($row) : self::standIn($jkt);
    }

    /** Is this agent blocked? Throws when the system database cannot be read: unknown is never "allowed". */
    public static function isBlocked(string $agentId, string $issuer): bool
    {
        return DB::table(self::TABLE)->where('agent_id', mb_substr($agentId, 0, 255))->where('issuer', mb_substr($issuer, 0, 255))
            ->where('status', 'blocked')->exists();
    }

    /** Removes an agent row and its key bindings; its activity rows stay (detached) unless $purgeActivity. */
    public static function delete(int $id, bool $purgeActivity = false): array
    {
        $row = DB::table(self::TABLE)->where('id', $id)->first();
        if (!$row) {
            throw new NotFoundException("Agent $id not found.");
        }
        if ($row->status === 'blocked') {
            throw new BadRequestException('Unblock the agent before removing it; a removed agent is allowed again.');
        }
        if ($purgeActivity) {
            DB::table('aauth_activity')->where('agent_row_id', $id)->delete();
        } else {
            DB::table('aauth_activity')->where('agent_row_id', $id)->update(['agent_row_id' => null]);
        }
        try {
            DB::table(self::KEYS)->where('agent_id', $row->agent_id)->where('issuer', $row->issuer)->delete();
        } catch (\Throwable $e) {
        }
        DB::table(self::TABLE)->where('id', $id)->delete();

        return ['id' => $id];
    }

    /** Forgets key bindings not seen for the activity retention period. */
    public static function pruneKeys(): int
    {
        try {
            return self::staleKeys()->delete();
        } catch (\Throwable $e) {
            return 0;
        }
    }

    /**
     * Key bindings not seen for the activity retention period. Bindings to blocked agents are never
     * stale: they are what keeps the key blocked, and a blocked key stops presenting agent tokens here.
     */
    public static function staleKeys(): \Illuminate\Database\Query\Builder
    {
        $days = max(1, (int)config('df-aauth.activity_retention_days', 30));

        return DB::table(self::KEYS)->where('last_seen_at', '<', now()->subDays($days))
            ->whereNotExists(fn ($q) => $q->select(DB::raw(1))->from(self::TABLE)
                ->whereColumn(self::TABLE . '.agent_id', self::KEYS . '.agent_id')
                ->whereColumn(self::TABLE . '.issuer', self::KEYS . '.issuer')
                ->where(self::TABLE . '.status', 'blocked'));
    }

    /** Upserts the agent row, counts the request, returns the row. */
    public static function seen(string $agentId, string $issuer, ?string $name): array
    {
        $agentId = mb_substr($agentId, 0, 255);
        $issuer = mb_substr($issuer, 0, 255);
        $now = now();
        $row = DB::table(self::TABLE)->where('agent_id', $agentId)->where('issuer', $issuer)->first();
        if ($row) {
            $update = ['last_seen_at' => $now, 'request_count' => DB::raw('request_count + 1')];
            if ($name !== null && $name !== '' && $name !== $row->name) {
                $update['name'] = mb_substr($name, 0, 255);
            }
            DB::table(self::TABLE)->where('id', $row->id)->update($update);
        } else {
            try {
                DB::table(self::TABLE)->insert([
                    'agent_id' => $agentId, 'issuer' => $issuer, 'name' => $name !== null ? mb_substr($name, 0, 255) : null,
                    'status' => 'allowed', 'first_seen_at' => $now, 'last_seen_at' => $now, 'request_count' => 1,
                ]);
            } catch (\Throwable $e) {
                // concurrent insert: fall through to the re-read
            }
        }

        return (array)DB::table(self::TABLE)->where('agent_id', $agentId)->where('issuer', $issuer)->first();
    }

    /**
     * Makes sure the agent is listed (so an admin can block it) without counting a request: person
     * server and authorization endpoint calls. Returns its row.
     */
    public static function listed(string $agentId, string $issuer, ?string $name): array
    {
        $agentId = mb_substr($agentId, 0, 255);
        $issuer = mb_substr($issuer, 0, 255);
        $now = now();
        $row = DB::table(self::TABLE)->where('agent_id', $agentId)->where('issuer', $issuer)->first();
        if ($row) {
            $stale = $row->last_seen_at === null || strtotime((string)$row->last_seen_at) < $now->getTimestamp() - self::LISTED_TOUCH;
            if ($stale) {
                DB::table(self::TABLE)->where('id', $row->id)->update(['last_seen_at' => $now]);
            }

            return (array)$row;
        }
        try {
            DB::table(self::TABLE)->insert([
                'agent_id' => $agentId, 'issuer' => $issuer, 'name' => $name !== null && $name !== '' ? mb_substr($name, 0, 255) : null,
                'status' => 'allowed', 'first_seen_at' => $now, 'last_seen_at' => $now, 'request_count' => 0,
            ]);
        } catch (\Throwable $e) {
            // concurrent insert: fall through to the re-read
        }

        return (array)DB::table(self::TABLE)->where('agent_id', $agentId)->where('issuer', $issuer)->first();
    }

    /**
     * Every agent, newest first. Each record names at most LIST_SHARES of the agents that share a
     * signing key with it (shares_key_with_truncated says when there are more), so one key bound to
     * many agent ids cannot make the list grow with the square of their number.
     */
    public static function list(): array
    {
        $rows = [];
        foreach (DB::table(self::TABLE)->orderByDesc('last_seen_at')->orderByDesc('id')->get() as $r) {
            $rows[(int)$r->id] = (array)$r;
        }
        [$byKey, $keysOf] = self::keyMembers(null, $rows);
        $out = [];
        foreach ($rows as $id => $r) {
            [$others, $more] = self::sharesOf($id, $byKey, $keysOf, self::LIST_SHARES);
            $out[] = self::wire($r, self::rowsOf($others, $rows), $more);
        }

        return $out;
    }

    public static function get(int $id): array
    {
        $row = DB::table(self::TABLE)->where('id', $id)->first();
        if (!$row) {
            throw new NotFoundException("Agent $id not found.");
        }

        return self::wireOne((array)$row);
    }

    public static function patch(int $id, array $data): array
    {
        $row = DB::table(self::TABLE)->where('id', $id)->first();
        if (!$row) {
            throw new NotFoundException("Agent $id not found.");
        }
        if (array_key_exists('status', $data)) {
            $status = (string)$data['status'];
            if (!in_array($status, ['allowed', 'blocked'], true)) {
                throw new BadRequestException("status must be 'allowed' or 'blocked'.");
            }
            DB::table(self::TABLE)->where('id', $id)->update(['status' => $status]);
        }

        return self::wireOne((array)DB::table(self::TABLE)->where('id', $id)->first());
    }

    /** One agent's record with every agent that shares a signing key with it. */
    private static function wireOne(array $row): array
    {
        $id = (int)$row['id'];
        if (self::isStandIn($row)) {
            // base64url has no % or \, and "_" matching any character only adds keys filtered out here
            $jkts = array_values(array_filter(
                DB::table(self::KEYS)->where('jkt', 'like', substr((string)$row['agent_id'], 4) . '%')->distinct()->pluck('jkt')->all(),
                fn ($jkt) => self::standIn((string)$jkt)['agent_id'] === (string)$row['agent_id']));
            if ($jkts === []) {
                return self::wire($row, [], false);
            }
            $scope = fn ($q) => $q->whereIn('k.jkt', $jkts);
        } else {
            $scope = fn ($q) => $q->whereIn('k.jkt', fn ($sub) => $sub->select('k2.jkt')->from(self::KEYS . ' as k2')
                ->join(self::TABLE . ' as a2', fn ($j) => $j->on('a2.agent_id', '=', 'k2.agent_id')->on('a2.issuer', '=', 'k2.issuer'))
                ->where('a2.id', $id));
        }
        [$byKey, $keysOf] = self::keyMembers($scope, [$id => $row]);
        [$others] = self::sharesOf($id, $byKey, $keysOf, null);
        $rows = [$id => $row];
        foreach (array_chunk(array_values(array_diff($others, [$id])), 500) as $chunk) {
            foreach (DB::table(self::TABLE)->whereIn('id', $chunk)->get() as $r) {
                $rows[(int)$r->id] = (array)$r;
            }
        }

        return self::wire($row, self::rowsOf($others, $rows), false);
    }

    /**
     * Which agent rows each signing key is bound to: its bindings, matched to agent rows by the
     * database itself (a join on agent_id and issuer, as blockedBinding() matches them, so an agent id
     * that differs only in case or trailing spaces on a case-insensitive collation is the same agent
     * here too), plus the key's "jkt:" stand-in row when that is listed. $scope limits the keys
     * (null: every key); $rows are agent rows already read, by id (the stand-in rows of the keys that
     * are not among them are read).
     *
     * @return array{0: array<string, array<int, true>>, 1: array<int, list<string>>} key => agent row ids, agent row id => keys
     */
    private static function keyMembers(?\Closure $scope, array $rows): array
    {
        $q = DB::table(self::KEYS . ' as k')
            ->join(self::TABLE . ' as a', fn ($j) => $j->on('a.agent_id', '=', 'k.agent_id')->on('a.issuer', '=', 'k.issuer'))
            ->orderBy('k.jkt')->orderBy('a.agent_id')->orderBy('a.id');
        if ($scope !== null) {
            $scope($q);
        }
        $byKey = [];
        foreach ($q->get(['k.jkt', 'a.id']) as $b) {
            $byKey[(string)$b->jkt][(int)$b->id] = true;
        }
        $standIns = [];
        foreach ($rows as $id => $r) {
            if (self::isStandIn($r)) {
                $standIns[(string)$r['agent_id']] = (int)$id;
            }
        }
        if ($scope !== null) {
            $wanted = array_values(array_diff(array_unique(array_map(fn ($jkt) => self::standIn((string)$jkt)['agent_id'], array_keys($byKey))), array_keys($standIns)));
            foreach (array_chunk($wanted, 500) as $chunk) {
                foreach (DB::table(self::TABLE)->where('issuer', '')->whereIn('agent_id', $chunk)->get(['id', 'agent_id']) as $r) {
                    $standIns[(string)$r->agent_id] = (int)$r->id;
                }
            }
        }
        $keysOf = [];
        foreach ($byKey as $jkt => $members) {
            $standIn = $standIns[self::standIn((string)$jkt)['agent_id']] ?? null;
            if ($standIn !== null) {
                $byKey[$jkt][$standIn] = true;
            }
            foreach (array_keys($byKey[$jkt]) as $id) {
                $keysOf[$id][] = (string)$jkt;
            }
        }

        return [$byKey, $keysOf];
    }

    /**
     * The other agent rows that share a key with agent $id, at most $limit of them (null: all), and
     * whether there are more. Stops as soon as the limit is passed, so the work for one agent is
     * bounded by its number of keys times the limit, however many agents a key is bound to.
     *
     * @return array{0: list<int>, 1: bool}
     */
    private static function sharesOf(int $id, array $byKey, array $keysOf, ?int $limit): array
    {
        $seen = [];
        foreach ($keysOf[$id] ?? [] as $jkt) {
            foreach ($byKey[$jkt] as $other => $_) {
                if ($other === $id || isset($seen[$other])) {
                    continue;
                }
                if ($limit !== null && count($seen) >= $limit) {
                    return [array_keys($seen), true];
                }
                $seen[$other] = true;
            }
        }

        return [array_keys($seen), false];
    }

    /** @return list<array> the rows of these agent ids that are known, by agent_id, issuer, id */
    private static function rowsOf(array $ids, array $rows): array
    {
        $out = [];
        foreach ($ids as $id) {
            if (isset($rows[$id])) {
                $out[] = $rows[$id];
            }
        }
        usort($out, fn ($a, $b) => strcmp((string)$a['agent_id'], (string)$b['agent_id'])
            ?: strcmp((string)$a['issuer'], (string)$b['issuer']) ?: (int)$a['id'] <=> (int)$b['id']);

        return $out;
    }

    private static function isStandIn(array $r): bool
    {
        return (string)$r['issuer'] === '' && str_starts_with((string)$r['agent_id'], 'jkt:');
    }

    /**
     * A blocked agent this key is bound to (the most recently seen), else its stand-in when that is
     * blocked, else null. Throws when the system database cannot be read.
     */
    private static function blockedBinding(string $jkt): ?array
    {
        $row = DB::table(self::KEYS . ' as k')
            ->join(self::TABLE . ' as a', fn ($j) => $j->on('a.agent_id', '=', 'k.agent_id')->on('a.issuer', '=', 'k.issuer'))
            ->where('k.jkt', $jkt)->where('a.status', 'blocked')
            ->orderByDesc('k.last_seen_at')->orderByDesc('k.id')
            ->first(['k.agent_id', 'k.issuer', 'k.name']);
        if ($row) {
            return self::binding($row);
        }
        $standIn = self::standIn($jkt);

        return self::isBlocked($standIn['agent_id'], $standIn['issuer']) ? $standIn : null;
    }

    /**
     * Adds (or refreshes) the key -> agent binding. Throws AAuthError (403 too_many_agents) for a new
     * agent on a key already bound to MAX_AGENTS_PER_KEY agents, and any other exception when the
     * binding cannot be stored.
     */
    private static function bind(string $jkt, array $identity): void
    {
        $match = fn () => DB::table(self::KEYS)->where('jkt', $jkt)->where('agent_id', $identity['agent_id'])->where('issuer', $identity['issuer']);
        $refresh = ['name' => $identity['name'], 'last_seen_at' => now()];
        if ($match()->update($refresh) > 0) {
            return;
        }
        if (!$match()->exists() && DB::table(self::KEYS)->where('jkt', $jkt)->count() >= self::MAX_AGENTS_PER_KEY) {
            throw new AAuthError(403, 'too_many_agents', 'This signing key has already presented agent tokens for '
                . self::MAX_AGENTS_PER_KEY . ' agent ids at this DreamFactory. Use a new key for a new agent.');
        }
        try {
            DB::table(self::KEYS)->insert(['jkt' => $jkt] + $identity + ['last_seen_at' => now()]);
        } catch (\Throwable $e) {
            if (!$match()->exists()) {
                throw $e;
            }
            $match()->update($refresh); // a concurrent request stored the same binding, or nothing changed
        }
    }

    /** @return array{agent_id: string, issuer: string, name: null} the identity of a key never seen with an agent token */
    private static function standIn(string $jkt): array
    {
        return ['agent_id' => 'jkt:' . substr($jkt, 0, 12), 'issuer' => '', 'name' => null];
    }

    private static function binding(object $row): array
    {
        return ['agent_id' => (string)$row->agent_id, 'issuer' => (string)$row->issuer, 'name' => $row->name];
    }

    private static function same(array $a, array $b): bool
    {
        return $a['agent_id'] === $b['agent_id'] && $a['issuer'] === $b['issuer'];
    }

    /**
     * @param list<array> $sharing the other agents that share a signing key with this one
     * @param bool $truncated there are more than $sharing names (the list's limit)
     */
    private static function wire(array $r, array $sharing, bool $truncated): array
    {
        return [
            'id' => (int)$r['id'],
            'agent_id' => $r['agent_id'],
            'issuer' => $r['issuer'],
            'name' => $r['name'],
            'status' => $r['status'],
            'first_seen_at' => \DreamFactory\Core\AAuth\Support\AAuth::iso($r['first_seen_at']),
            'last_seen_at' => \DreamFactory\Core\AAuth\Support\AAuth::iso($r['last_seen_at']),
            'request_count' => (int)$r['request_count'],
            'shares_key_with' => array_map(fn ($o) => [
                'id' => (int)$o['id'], 'agent_id' => $o['agent_id'], 'issuer' => $o['issuer'], 'name' => $o['name'], 'status' => $o['status'],
            ], $sharing),
            'shares_key_with_truncated' => $truncated,
        ];
    }
}
