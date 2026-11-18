<?php

namespace DreamFactory\Core\AAuth\Resource;

use DreamFactory\Core\AAuth\Protocol\AAuthError;
use DreamFactory\Core\AAuth\Protocol\Discovery;
use DreamFactory\Core\AAuth\Support\AAuth;
use DreamFactory\Core\AAuth\Support\Settings;
use DreamFactory\Core\Exceptions\BadRequestException;
use DreamFactory\Core\Exceptions\NotFoundException;
use Illuminate\Support\Facades\DB;

/**
 * Person servers this resource accepts person/auth tokens from. The local row (this DreamFactory's
 * own PS) is created lazily and trusts every enabled scope. Stored `scopes`: null = every enabled
 * scope (explicit opt-in), a JSON list = only those, '[]' = none. A newly added external PS starts
 * with no scopes: the admin chooses what it may vouch for.
 * Wire: {scopes: [...], all_scopes: bool}. PATCH {all_scopes: true} trusts every scope;
 * {scopes: [...]} (also []) sets the allow-list and clears all_scopes.
 */
final class PersonServers
{
    public const TABLE = 'aauth_person_servers';

    public static function ensureLocal(): ?array
    {
        $issuer = Settings::issuer();
        if (!$issuer) {
            return null;
        }
        $row = DB::table(self::TABLE)->where('is_local', true)->first();
        if ($row && $row->issuer !== $issuer) {
            // the issuer changed (env): keep the row, follow the issuer
            DB::table(self::TABLE)->where('issuer', $issuer)->where('is_local', false)->delete();
            DB::table(self::TABLE)->where('id', $row->id)->update(['issuer' => $issuer, 'updated_at' => now()]);
            $row = DB::table(self::TABLE)->where('id', $row->id)->first();
        }
        if (!$row) {
            $now = now();
            DB::table(self::TABLE)->insert([
                'issuer' => $issuer, 'name' => 'This DreamFactory', 'is_local' => true, 'enabled' => true,
                'scopes' => null, 'created_at' => $now, 'updated_at' => $now,
            ]);
            $row = DB::table(self::TABLE)->where('is_local', true)->first();
        }

        return self::decode($row);
    }

    /**
     * The person server a person or auth token is judged by: always its verified signer (iss),
     * never the self-declared `ps` claim. Auth tokens must come from a person server (dwk
     * aauth-person.json) that names itself in `ps`; DreamFactory federates with no access server,
     * so access-server tokens (dwk aauth-access.json) are refused. Throws 401 invalid_jwt.
     */
    public static function anchor(string $typ, array $claims): string
    {
        $iss = $claims['iss'] ?? null;
        if (!is_string($iss) || $iss === '') {
            throw AAuthError::signature('invalid_jwt', 'The token has no iss.');
        }
        if ($typ === 'aa-auth+jwt') {
            if (($claims['dwk'] ?? null) !== 'aauth-person.json') {
                throw AAuthError::signature('invalid_jwt', 'Auth tokens must be issued by a person server (dwk aauth-person.json).');
            }
            if (($claims['ps'] ?? null) !== $iss) {
                throw AAuthError::signature('invalid_jwt', 'The auth token ps claim does not name its issuer.');
            }
        }

        return $iss;
    }

    /**
     * Pre-verification policy check (before any discovery fetch): an issuer we do not trust is
     * refused early, as a credential problem (401 invalid_jwt) because nothing is verified yet.
     */
    public static function preCheck(string $typ, array $unverifiedClaims): void
    {
        if ($typ !== 'aa-person+jwt' && $typ !== 'aa-auth+jwt') {
            return;
        }
        $iss = self::anchor($typ, $unverifiedClaims);
        if (self::trusted($iss) === null) {
            throw AAuthError::signature('invalid_jwt', 'The token issuer is not a person server trusted by this DreamFactory.');
        }
    }

    /** The enabled row for a PS issuer, or null when that PS is not trusted. */
    public static function trusted(string $issuer): ?array
    {
        if ($issuer === Settings::issuer()) {
            $row = self::ensureLocal();

            return ($row && $row['enabled'] && Settings::localPersonServerEnabled()) ? $row : null;
        }
        $row = DB::table(self::TABLE)->where('issuer', $issuer)->where('enabled', true)->first();

        return $row ? self::decode($row) : null;
    }

    public static function touch(int $id): void
    {
        try {
            DB::table(self::TABLE)->where('id', $id)->update(['last_used_at' => now()]);
        } catch (\Throwable $e) {
        }
    }

    public static function list(): array
    {
        self::ensureLocal();
        $rows = DB::table(self::TABLE)->orderByDesc('is_local')->orderBy('name')->orderBy('id')->get();

        return array_map(fn ($r) => self::wire(self::decode($r)), $rows->all());
    }

    public static function add(string $issuer): array
    {
        $issuer = rtrim(trim($issuer), '/');
        try {
            Discovery::assertServerId($issuer, Settings::allowInsecure());
        } catch (\Throwable $e) {
            throw new BadRequestException('Enter the person server origin, like https://ps.example.com.');
        }
        if ($issuer === Settings::issuer()) {
            throw new BadRequestException('This DreamFactory is already listed.');
        }
        if (DB::table(self::TABLE)->where('issuer', $issuer)->exists()) {
            throw new BadRequestException('That person server is already listed.');
        }
        try {
            $meta = AAuth::metadata($issuer, 'aauth-person.json');
        } catch (\Throwable $e) {
            $detail = method_exists($e, 'toProblem') ? ($e->toProblem()['detail'] ?? $e->getMessage()) : $e->getMessage();
            throw new BadRequestException('Could not read ' . $issuer . '/.well-known/aauth-person.json: ' . $detail);
        }
        foreach (['person_token_endpoint', 'auth_token_endpoint', 'jwks_uri'] as $f) {
            if (empty($meta[$f])) {
                throw new BadRequestException("The person server metadata has no $f.");
            }
        }
        $name = trim((string)($meta['name'] ?? '')) ?: (string)parse_url($issuer, PHP_URL_HOST);
        $now = now();
        $id = DB::table(self::TABLE)->insertGetId([
            'issuer' => $issuer, 'name' => mb_substr($name, 0, 255), 'is_local' => false, 'enabled' => true,
            'scopes' => '[]', 'created_at' => $now, 'updated_at' => $now,
        ]);

        return self::get((int)$id);
    }

    public static function get(int $id): array
    {
        $row = DB::table(self::TABLE)->where('id', $id)->first();
        if (!$row) {
            throw new NotFoundException("Person server $id not found.");
        }

        return self::wire(self::decode($row));
    }

    public static function patch(int $id, array $data): array
    {
        self::get($id);
        $update = [];
        if (array_key_exists('enabled', $data)) {
            $update['enabled'] = filter_var($data['enabled'], FILTER_VALIDATE_BOOLEAN);
        }
        $all = array_key_exists('all_scopes', $data) ? filter_var($data['all_scopes'], FILTER_VALIDATE_BOOLEAN, FILTER_NULL_ON_FAILURE) : null;
        if (array_key_exists('all_scopes', $data) && $all === null) {
            throw new BadRequestException('all_scopes must be true or false.');
        }
        if ($all === true) {
            $update['scopes'] = null;
        } elseif ($all === false && !array_key_exists('scopes', $data)) {
            $update['scopes'] = '[]';
        }
        if ($all !== true && array_key_exists('scopes', $data)) {
            if ($data['scopes'] === null) {
                $update['scopes'] = null; // legacy: null = every scope
            } else {
                if (!is_array($data['scopes'])) {
                    throw new BadRequestException('scopes must be a list of scope names.');
                }
                $known = DB::table(Scopes::TABLE)->pluck('scope')->all();
                $list = [];
                foreach ($data['scopes'] as $s) {
                    $s = (string)$s;
                    if (!in_array($s, $known, true)) {
                        throw new BadRequestException("Unknown scope '$s'.");
                    }
                    $list[] = $s;
                }
                $update['scopes'] = json_encode(array_values(array_unique($list)));
            }
        }
        if ($update) {
            DB::table(self::TABLE)->where('id', $id)->update($update + ['updated_at' => now()]);
        }

        return self::get($id);
    }

    public static function delete(int $id): array
    {
        $row = self::get($id);
        if ($row['is_local']) {
            throw new BadRequestException('The local person server cannot be removed. Turn it off instead.');
        }
        DB::table(self::TABLE)->where('id', $id)->delete();

        return ['id' => $id];
    }

    private static function decode(object $row): array
    {
        $r = (array)$row;
        $r['id'] = (int)$r['id'];
        $r['is_local'] = (bool)$r['is_local'];
        $r['enabled'] = (bool)$r['enabled'];
        if ($r['scopes'] !== null) {
            $list = json_decode((string)$r['scopes'], true);
            $r['scopes'] = is_array($list) ? array_values(array_map('strval', $list)) : []; // unreadable = none
        }

        return $r;
    }

    private static function wire(array $r): array
    {
        return [
            'id' => $r['id'],
            'issuer' => $r['issuer'],
            'name' => $r['is_local'] ? 'This DreamFactory' : $r['name'],
            'is_local' => $r['is_local'],
            'enabled' => $r['enabled'],
            'scopes' => $r['scopes'] === null ? [] : $r['scopes'],
            'all_scopes' => $r['scopes'] === null,
            'last_used_at' => \DreamFactory\Core\AAuth\Support\AAuth::iso($r['last_used_at']),
        ];
    }
}
