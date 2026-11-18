<?php

namespace DreamFactory\Core\AAuth\PersonServer;

use Illuminate\Support\Facades\DB;

/**
 * aauth_ps_tokens: the agent (agent provider issuer, agent id, name) each person and auth token of
 * this person server was issued for, by jti, until the token has expired.
 *
 * Person and auth tokens do not name the agent (three-party privacy), and the agent token a signing
 * key presented last can name any agent id its agent provider likes. So the resource attributes this
 * DreamFactory's own tokens through this record (Agents::admit): Activity, request counts and blocks
 * follow the agent that got the person's approval or standing grant, not whatever id the key moved to.
 *
 * Kept in the system database, not the cache: a record must last as long as its token (up to an hour),
 * be the same on every node and never be evicted, because a token of ours without one is refused.
 */
final class IssuedTokens
{
    public const TABLE = 'aauth_ps_tokens';
    /** Records are kept this long after their token expired (clock differences between nodes). */
    private const KEEP_AFTER_EXPIRY = 3600;

    /**
     * Records a token before it is handed out. Throws when the token names no agent or the record
     * cannot be stored; the token is then not issued.
     */
    public static function record(string $jti, string $kind, array $agent, int $exp): void
    {
        $sub = (string)($agent['sub'] ?? '');
        $iss = (string)($agent['iss'] ?? '');
        if ($jti === '' || $sub === '' || $iss === '') {
            throw new \InvalidArgumentException('An issued token needs a jti and the agent (sub, iss) it is issued for.');
        }
        $name = isset($agent['name']) && is_string($agent['name']) && $agent['name'] !== '' ? mb_substr($agent['name'], 0, 255) : null;
        DB::table(self::TABLE)->insert([
            'jti' => $jti,
            'kind' => $kind,
            'agent_iss' => mb_substr($iss, 0, 255),
            'agent_sub' => mb_substr($sub, 0, 255),
            'agent_name' => $name,
            'expires_at' => $exp,
            'created_at' => now(),
        ]);
    }

    /**
     * The agent a token of this person server was issued for, or null when it issued no token with
     * this jti. Throws when the system database cannot be read.
     *
     * @return array{agent_id: string, issuer: string, name: ?string}|null
     */
    public static function agentFor(string $jti): ?array
    {
        if ($jti === '') {
            return null;
        }
        $row = DB::table(self::TABLE)->where('jti', $jti)->first(['agent_sub', 'agent_iss', 'agent_name']);

        return $row ? ['agent_id' => (string)$row->agent_sub, 'issuer' => (string)$row->agent_iss, 'name' => $row->agent_name] : null;
    }

    /** Deletes records of tokens that expired more than an hour ago; returns how many (none are removed when $dryRun). */
    public static function prune(bool $dryRun = false): int
    {
        $q = DB::table(self::TABLE)->where('expires_at', '<', time() - self::KEEP_AFTER_EXPIRY);

        return $dryRun ? (int)$q->count() : (int)$q->delete();
    }
}
