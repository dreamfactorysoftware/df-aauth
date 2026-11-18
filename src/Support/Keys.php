<?php

namespace DreamFactory\Core\AAuth\Support;

use DreamFactory\Core\AAuth\Protocol\Jwk;
use Illuminate\Support\Facades\Crypt;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;

/**
 * Signing keys (aauth_keys), Ed25519, one signing key per purpose (resource | person | agent),
 * generated lazily. Private JWKs are stored with Crypt::encryptString (APP_KEY, so every node
 * with the same APP_KEY can sign); public JWKs in clear. Nothing is kept outside the database.
 *
 * Rotation (php artisan df:aauth rotate-keys): a new key starts signing at once; the previous
 * keys get retired_at and stay published in the JWKS and accepted for overlap() seconds, so tokens
 * they signed keep verifying until they expire. After that prune() deletes them (private key
 * included). revoke drops the previous keys at once (key compromise: their tokens stop verifying).
 */
final class Keys
{
    public const TABLE = 'aauth_keys';
    public const PURPOSES = ['resource', 'person', 'agent'];
    public const DWK_PURPOSE = [
        'aauth-resource.json' => 'resource',
        'aauth-person.json' => 'person',
        'aauth-agent.json' => 'agent',
    ];
    /** Token lifetimes (config keys) a retired key must outlive. */
    private const TTLS = ['auth_token_ttl' => 3600, 'person_token_ttl' => 3600, 'agent_token_ttl' => 3600, 'resource_token_ttl' => 300];

    /** @var array<string, array{public: array, private: array}> per-request memo of the signing keys */
    private static array $memo = [];
    /** retired_at exists (the 2026_11_12 migration ran); null = not checked in this request yet. */
    private static ?bool $rotation = null;

    public static function flush(): void
    {
        self::$memo = [];
        self::$rotation = null;
    }

    /**
     * True once the rotation column exists. Until `php artisan migrate` adds it, keys behave as
     * before (every active key published, the lowest id signs) and rotate() refuses.
     */
    public static function rotationReady(): bool
    {
        if (self::$rotation !== null) {
            return self::$rotation;
        }
        try {
            if (Store::cache()->get('aauth:keys:rotation') === 1) {
                return self::$rotation = true;
            }
        } catch (\Throwable $e) {
        }
        try {
            $ok = Schema::hasColumn(self::TABLE, 'retired_at');
        } catch (\Throwable $e) {
            $ok = false;
        }
        if ($ok) {
            try {
                Store::cache()->put('aauth:keys:rotation', 1, 3600);
            } catch (\Throwable $e) {
            }
        }

        return self::$rotation = $ok;
    }

    /** Private JWK of the signing key for $purpose (creating it on first use). */
    public static function privateJwk(string $purpose): array
    {
        return self::active($purpose)['private'];
    }

    public static function publicJwk(string $purpose): array
    {
        return self::active($purpose)['public'];
    }

    /** JWKS document: the signing key and every retired key still inside the overlap window. */
    public static function jwks(string $purpose): array
    {
        self::assertPurpose($purpose);
        self::active($purpose);
        $keys = [];
        foreach (self::published($purpose)->orderBy('id')->get(['public_jwk']) as $row) {
            $jwk = json_decode($row->public_jwk, true);
            if (is_array($jwk)) {
                $keys[] = $jwk;
            }
        }

        return ['keys' => $keys];
    }

    /** Public key of $purpose with $kid (null kid = the signing key), or null. Retired keys count during the overlap. */
    public static function find(string $purpose, ?string $kid): ?array
    {
        self::assertPurpose($purpose);
        if ($kid === null || $kid === '') {
            return self::publicJwk($purpose);
        }
        $row = self::published($purpose)->where('kid', $kid)->first(['public_jwk']);

        return $row ? json_decode($row->public_jwk, true) : null;
    }

    /** Seconds a retired key stays published: DF_AAUTH_KEY_OVERLAP, never less than the longest token lifetime + 5 min. */
    public static function overlap(): int
    {
        $longest = 0;
        foreach (self::TTLS as $key => $default) {
            $longest = max($longest, (int)config("df-aauth.$key", $default));
        }

        return max((int)config('df-aauth.key_overlap', 86400), $longest + 300);
    }

    /**
     * Starts a new signing key for $purpose. The previous ones are retired (published for overlap()
     * seconds) or, with $revoke, deleted at once.
     *
     * @return array{purpose: string, kid: string, retired: string[], revoked: string[]}
     */
    public static function rotate(string $purpose, bool $revoke = false): array
    {
        self::assertPurpose($purpose);
        if (!self::rotationReady()) {
            throw new \RuntimeException('The df-aauth key rotation migration has not run yet: php artisan migrate --force');
        }
        $out = DB::transaction(function () use ($purpose, $revoke) {
            $previous = DB::table(self::TABLE)->where('purpose', $purpose)->where('active', true)->whereNull('retired_at')->pluck('kid')->all();
            $id = self::insert($purpose);
            $kid = (string)DB::table(self::TABLE)->where('id', $id)->value('kid');
            $others = DB::table(self::TABLE)->where('purpose', $purpose)->where('id', '<>', $id);
            if ($revoke) {
                $revoked = (clone $others)->pluck('kid')->all();
                $others->delete();

                return ['purpose' => $purpose, 'kid' => $kid, 'retired' => [], 'revoked' => array_values(array_map('strval', $revoked))];
            }
            (clone $others)->whereNull('retired_at')->update(['retired_at' => now()]);

            return ['purpose' => $purpose, 'kid' => $kid, 'retired' => array_values(array_map('strval', $previous)), 'revoked' => []];
        });
        self::flush();

        return $out;
    }

    /** Created time (unix) of the signing key of $purpose, or null when none exists yet. */
    public static function signingKeyCreatedAt(string $purpose): ?int
    {
        self::assertPurpose($purpose);
        $ts = self::signing($purpose)->value('created_at');

        return $ts ? \Illuminate\Support\Carbon::parse((string)$ts)->getTimestamp() : null;
    }

    /**
     * Key metadata for operators (never private material).
     *
     * @return array<int, array{purpose: string, kid: string, state: string, created_at: ?string, retired_at: ?string, published_until: ?string}>
     */
    public static function inventory(): array
    {
        $overlap = self::overlap();
        $cols = self::rotationReady() ? ['id', 'purpose', 'kid', 'active', 'created_at', 'retired_at'] : ['id', 'purpose', 'kid', 'active', 'created_at'];
        $out = [];
        foreach (DB::table(self::TABLE)->orderBy('purpose')->orderBy('id')->get($cols) as $r) {
            $r->retired_at ??= null;
            $retired = $r->retired_at !== null ? \Illuminate\Support\Carbon::parse((string)$r->retired_at) : null;
            $until = $retired?->copy()->addSeconds($overlap);
            $state = !$r->active ? 'inactive' : ($retired === null ? 'signing' : ($until->isFuture() ? 'retiring' : 'expired'));
            $out[] = [
                'purpose' => (string)$r->purpose,
                'kid' => (string)$r->kid,
                'state' => $state,
                'created_at' => AAuth::iso($r->created_at),
                'retired_at' => AAuth::iso($r->retired_at),
                'published_until' => $until ? AAuth::iso($until->toDateTimeString()) : null,
            ];
        }

        return $out;
    }

    /** Deletes retired keys past the overlap window (and inactive rows). Returns how many (counted only when $dryRun). */
    public static function prune(bool $dryRun = false): int
    {
        try {
            $rotation = self::rotationReady();
            $q = DB::table(self::TABLE)->where(function ($w) use ($rotation) {
                $w->where('active', false);
                if ($rotation) {
                    $w->orWhere('retired_at', '<=', now()->subSeconds(self::overlap()));
                }
            });

            return $dryRun ? (int)$q->count() : (int)$q->delete();
        } catch (\Throwable $e) {
            return 0;
        }
    }

    /** Active keys of $purpose that are published: the signing key(s) and retired keys inside the overlap. */
    private static function published(string $purpose): \Illuminate\Database\Query\Builder
    {
        $q = DB::table(self::TABLE)->where('purpose', $purpose)->where('active', true);
        if (!self::rotationReady()) {
            return $q;
        }
        $since = now()->subSeconds(self::overlap());

        return $q->where(fn ($w) => $w->whereNull('retired_at')->orWhere('retired_at', '>', $since));
    }

    /** The signing key candidates of $purpose, lowest id first (the lowest one signs). */
    private static function signing(string $purpose): \Illuminate\Database\Query\Builder
    {
        $q = DB::table(self::TABLE)->where('purpose', $purpose)->where('active', true);
        if (self::rotationReady()) {
            $q->whereNull('retired_at');
        }

        return $q->orderBy('id');
    }

    /** @return array{public: array, private: array} */
    private static function active(string $purpose): array
    {
        self::assertPurpose($purpose);
        if (isset(self::$memo[$purpose])) {
            return self::$memo[$purpose];
        }
        $signing = fn () => self::signing($purpose)->first();
        $row = $signing();
        if (!$row) {
            self::insert($purpose);
            // Another request (or node) may have raced us: the lowest signing id wins everywhere.
            $row = $signing();
        }

        return self::$memo[$purpose] = [
            'public' => json_decode($row->public_jwk, true),
            'private' => json_decode(Crypt::decryptString($row->private_jwk), true),
        ];
    }

    private static function insert(string $purpose): int
    {
        $private = Jwk::generateEd25519();
        $public = Jwk::publicOf($private);

        return (int)DB::table(self::TABLE)->insertGetId([
            'purpose' => $purpose,
            'kid' => (string)($private['kid'] ?? ''),
            'public_jwk' => json_encode($public, JSON_UNESCAPED_SLASHES),
            'private_jwk' => Crypt::encryptString(json_encode($private, JSON_UNESCAPED_SLASHES)),
            'active' => true,
            'created_at' => now(),
        ]);
    }

    private static function assertPurpose(string $purpose): void
    {
        if (!in_array($purpose, self::PURPOSES, true)) {
            throw new \InvalidArgumentException("Unknown key purpose '$purpose'.");
        }
    }
}
