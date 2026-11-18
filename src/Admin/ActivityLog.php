<?php

namespace DreamFactory\Core\AAuth\Admin;

use DreamFactory\Core\AAuth\Support\Activity;
use DreamFactory\Core\Exceptions\BadRequestException;
use Illuminate\Support\Facades\DB;

final class ActivityLog
{
    /**
     * Newest first. `$outcome` optionally narrows the rows to one or more outcomes
     * (comma-separated string or list, e.g. "denied,blocked,error"); absent or empty means every outcome.
     */
    public static function list($limit = null, $beforeId = null, $outcome = null): array
    {
        $limit = self::positive($limit, 'limit') ?? 100;
        $limit = min(500, $limit);
        $beforeId = self::positive($beforeId, 'before_id');
        $outcomes = self::outcomes($outcome);
        $q = DB::table('aauth_activity as a')
            ->leftJoin('aauth_agents as g', 'g.id', '=', 'a.agent_row_id')
            ->leftJoin('user as u', 'u.id', '=', 'a.user_id')
            ->orderByDesc('a.id')->limit($limit + 1);
        if ($beforeId !== null) {
            $q->where('a.id', '<', $beforeId);
        }
        if ($outcomes) {
            $q->whereIn('a.outcome', $outcomes);
        }
        $rows = $q->get(['a.*', 'g.name as agent_name', 'u.email as user_email']);
        $more = $rows->count() > $limit;
        $out = [];
        foreach ($rows->take($limit) as $r) {
            $person = $r->user_email;
            if (!$person && $r->person_sub) {
                $host = $r->ps_issuer ? (string)parse_url($r->ps_issuer, PHP_URL_HOST) : '';
                $person = $r->person_sub . ($host !== '' ? '@' . $host : '');
            }
            $out[] = [
                'id' => (int)$r->id,
                'created_at' => \DreamFactory\Core\AAuth\Support\AAuth::iso($r->created_at),
                'agent_id' => $r->agent_id,
                'agent_name' => $r->agent_name,
                'person' => $person,
                'ps_issuer' => $r->ps_issuer,
                'scope' => $r->scope,
                'method' => $r->method,
                'path' => $r->path,
                'status' => (int)$r->status,
                'outcome' => $r->outcome,
                'detail' => $r->detail,
            ];
        }

        return ['resource' => $out, 'has_more' => $more];
    }

    /** [] when absent/empty (no filter); else the distinct known outcomes asked for; an unknown one is a 400. */
    private static function outcomes($value): array
    {
        if ($value === null || $value === '' || $value === []) {
            return [];
        }
        if (!is_string($value) && !is_array($value)) {
            throw new BadRequestException('outcome must be a comma-separated list of outcomes.');
        }
        $list = is_array($value) ? $value : explode(',', $value);
        $out = [];
        foreach ($list as $item) {
            $item = is_string($item) ? strtolower(trim($item)) : null;
            if ($item === '') {
                continue;
            }
            if ($item === null || !in_array($item, Activity::OUTCOMES, true)) {
                throw new BadRequestException('outcome must be one or more of: ' . implode(', ', Activity::OUTCOMES) . '.');
            }
            $out[$item] = $item;
        }

        return array_values($out);
    }

    /** null when absent/empty; a positive integer; else 400. */
    private static function positive($value, string $name): ?int
    {
        if ($value === null || $value === '') {
            return null;
        }
        $v = is_int($value) ? (string)$value : trim((string)$value);
        if (!ctype_digit($v) || (int)$v < 1) {
            throw new BadRequestException("$name must be a positive integer.");
        }

        return (int)$v;
    }
}
