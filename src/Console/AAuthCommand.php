<?php

namespace DreamFactory\Core\AAuth\Console;

use DreamFactory\Core\AAuth\Http\Middleware\SecureSessionCookie;
use DreamFactory\Core\AAuth\PersonServer\Accounts;
use DreamFactory\Core\AAuth\PersonServer\Pending;
use DreamFactory\Core\AAuth\ServiceProvider;
use DreamFactory\Core\AAuth\Support\EgressPolicy;
use DreamFactory\Core\AAuth\Support\Keys;
use DreamFactory\Core\AAuth\Support\License;
use DreamFactory\Core\AAuth\Support\Maintenance;
use DreamFactory\Core\AAuth\Support\Settings;
use DreamFactory\Core\AAuth\Support\Store;
use Illuminate\Console\Command;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;

/**
 * php artisan df:aauth [status | rotate-keys | prune]
 *
 *   status        deployment readiness: issuer, cache store and consent sessions (shared across
 *                 nodes?), private-network egress, CA bundle, signing keys, sign-in methods
 *   rotate-keys   new signing keys; the previous ones stay published for the overlap window
 *                 (DF_AAUTH_KEY_OVERLAP) unless --revoke. --older-than=N only rotates keys older
 *                 than N days (what the scheduler runs when DF_AAUTH_KEY_ROTATION_DAYS is set)
 *   prune         expired pending requests, old activity, stale agent keys, expired signing keys,
 *                 scope-name reservations and issued-token records (scheduled daily)
 */
class AAuthCommand extends Command
{
    protected $signature = 'df:aauth
        {action? : status | rotate-keys | prune}
        {--purpose=* : rotate-keys: resource, person and/or agent (default: all three)}
        {--older-than= : rotate-keys: only rotate keys at least this many days old}
        {--revoke : rotate-keys: delete the previous keys now instead of after the overlap window (key compromise; their tokens stop working)}
        {--dry-run : prune: count what would be removed}
        {--json : machine-readable output}';

    protected $description = 'AAuth: deployment status, signing key rotation and housekeeping.';

    public function handle(): int
    {
        $action = (string)($this->argument('action') ?? 'status');
        try {
            if (!Schema::hasTable(Keys::TABLE)) {
                $this->error('The df-aauth tables are missing. Run: php artisan migrate --force');

                return self::FAILURE;
            }

            return match ($action) {
                'status' => $this->status(),
                'rotate-keys', 'rotate' => $this->rotate(),
                'prune' => $this->prune(),
                default => $this->unknown($action),
            };
        } catch (\Throwable $e) {
            $this->error($e->getMessage());

            return self::FAILURE;
        } finally {
            Settings::flush();
            Keys::flush();
        }
    }

    private function status(): int
    {
        $s = self::report();
        if ($this->option('json')) {
            $this->line(json_encode($s, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES));

            return self::SUCCESS;
        }
        $yes = fn (bool $b) => $b ? 'yes' : 'no';
        $this->line('AAuth ' . ServiceProvider::VERSION);
        $this->line('  Enabled              ' . $yes($s['enabled']));
        $this->line('  Issuer               ' . ($s['issuer'] ?? '(not set: DF_AAUTH_ISSUER)') . ($s['issuer_ok'] ? '' : '  [invalid]'));
        $this->line('  Cache store          ' . $s['cache']['store'] . ' (' . $s['cache']['driver'] . ', ' . ($s['cache']['shared'] ? 'shared' : 'this node only') . ')');
        $this->line('  Consent sessions     ' . $s['sessions']['driver'] . ' (' . ($s['sessions']['shared'] ? 'shared' : 'this node only') . ')');
        $this->line('  Private hosts        ' . ($s['egress']['private_hosts'] ? implode(', ', $s['egress']['private_hosts']) : '(none)'));
        $this->line('  Private networks     ' . ($s['egress']['private_networks'] ? implode(', ', $s['egress']['private_networks']) : '(none)'));
        $this->line('  CA bundle            ' . ($s['egress']['ca_bundle'] ?? 'system trust store') . ($s['egress']['ca_bundle'] && !$s['egress']['ca_bundle_readable'] ? '  [NOT READABLE]' : ''));
        $this->line('  Sign-in              ' . implode(', ', $s['sign_in']));
        $this->line('  Key overlap          ' . self::duration($s['keys']['overlap_seconds']) . ($s['keys']['rotation_days'] > 0 ? ', auto-rotate after ' . $s['keys']['rotation_days'] . ' days' : ', rotate by hand'));
        $this->line('  Pending (live)       ' . $s['pending_live']);
        $this->newLine();
        if ($s['keys']['list']) {
            $this->table(['Purpose', 'Key id', 'State', 'Created', 'Retired', 'Published until'], array_map(fn ($k) => [
                $k['purpose'], $k['kid'], $k['state'], $k['created_at'] ?? '', $k['retired_at'] ?? '', $k['published_until'] ?? '',
            ], $s['keys']['list']));
        } else {
            $this->line('No signing keys yet (created on first use).');
        }
        foreach ($s['warnings'] as $w) {
            $this->warn('! ' . $w);
        }

        return self::SUCCESS;
    }

    private function rotate(): int
    {
        $purposes = array_values(array_filter(array_map('strtolower', (array)$this->option('purpose'))));
        $purposes = $purposes ?: Keys::PURPOSES;
        foreach ($purposes as $p) {
            if (!in_array($p, Keys::PURPOSES, true)) {
                $this->error("Unknown purpose '$p' (resource, person or agent).");

                return self::FAILURE;
            }
        }
        $olderThan = $this->option('older-than');
        if ($olderThan !== null && (!ctype_digit((string)$olderThan) || (int)$olderThan < 1)) {
            $this->error('--older-than takes a whole number of days (1 or more).');

            return self::FAILURE;
        }
        $revoke = (bool)$this->option('revoke');
        if ($revoke && $this->input->isInteractive()
            && !$this->confirm('Revoke the previous keys now? Every token they signed stops verifying, and agents must ask again.', false)) {
            $this->line('Nothing changed.');

            return self::SUCCESS;
        }
        $results = [];
        foreach ($purposes as $p) {
            if ($olderThan !== null) {
                $created = Keys::signingKeyCreatedAt($p);
                if ($created === null || time() - $created < (int)$olderThan * 86400) {
                    $results[] = ['purpose' => $p, 'skipped' => $created === null ? 'no key yet' : 'younger than ' . (int)$olderThan . ' days'];
                    continue;
                }
            }
            $results[] = Keys::rotate($p, $revoke);
        }
        $until = date('Y-m-d H:i', time() + Keys::overlap()) . ' UTC';
        if ($this->option('json')) {
            $this->line(json_encode(['rotated' => $results, 'published_until' => $revoke ? null : $until], JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES));

            return self::SUCCESS;
        }
        foreach ($results as $r) {
            if (isset($r['skipped'])) {
                $this->line(sprintf('%-9s skipped (%s)', $r['purpose'], $r['skipped']));
                continue;
            }
            $line = sprintf('%-9s new key %s', $r['purpose'], $r['kid']);
            if ($r['revoked']) {
                $line .= '; revoked ' . implode(', ', $r['revoked']);
            } elseif ($r['retired']) {
                $line .= '; ' . implode(', ', $r['retired']) . " stays published until $until";
            }
            $this->line($line);
        }

        return self::SUCCESS;
    }

    private function prune(): int
    {
        $dry = (bool)$this->option('dry-run');
        $counts = Maintenance::prune($dry);
        if ($this->option('json')) {
            $this->line(json_encode(['dry_run' => $dry, 'removed' => $counts, 'errors' => Maintenance::$errors], JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES));
        } else {
            $labels = ['pending' => 'Expired pending requests', 'activity' => 'Activity rows', 'agent_keys' => 'Stale agent keys',
                       'signing_keys' => 'Expired signing keys', 'retired_scopes' => 'Expired scope reservations',
                       'issued_tokens' => 'Expired token records'];
            foreach ($counts as $k => $n) {
                $this->line(sprintf('%-28s %d%s', $labels[$k] ?? $k, $n, $dry ? ' (dry run)' : ''));
            }
            foreach (Maintenance::$errors as $e) {
                $this->warn('! ' . $e);
            }
        }

        return Maintenance::$errors ? self::FAILURE : self::SUCCESS;
    }

    private function unknown(string $action): int
    {
        $this->error("Unknown action '$action'. Use status, rotate-keys or prune.");

        return self::INVALID;
    }

    /** Deployment readiness facts and warnings (also used by tests). */
    public static function report(): array
    {
        $issuer = Settings::issuer();
        $issuerOk = Settings::issuerOk();
        $storeName = Store::name() ?? (string)config('cache.default', '');
        $sessionDriver = trim((string)config('df-aauth.session_driver', '')) ?: (string)config('session.driver', 'file');
        $sessionShared = !in_array(strtolower($sessionDriver), ['file', 'array'], true); // cookie: client side, any node
        $policy = EgressPolicy::fromConfig();
        $bundle = trim((string)config('df-aauth.ca_bundle', '')) ?: null;
        $bundleOk = $bundle === null || is_readable($bundle);
        $warnings = [];
        $gold = License::isGold();
        if (!$gold) {
            $warnings[] = 'AAuth needs a Gold license level: until then signed requests get no AAuth identity and the AAuth endpoints answer as when AAuth is off.';
        }
        if (!$issuerOk) {
            $warnings[] = 'DF_AAUTH_ISSUER must be the public https origin of this DreamFactory (https://host, no port or path).';
        }
        if (Settings::allowInsecure()) {
            $warnings[] = 'DF_AAUTH_ALLOW_INSECURE is on: development only (http issuers, private discovery targets).';
        }
        if (!Store::isShared()) {
            $warnings[] = "The AAuth cache store ($storeName) is local to this node. With more than one DreamFactory node set DF_AAUTH_CACHE_STORE to a shared store (redis) so replay protection and limits hold across nodes.";
        }
        if (!$sessionShared) {
            $warnings[] = "Consent pages use $sessionDriver sessions. With more than one node and no sticky sessions set DF_AAUTH_SESSION_DRIVER=redis (or database).";
        }
        if (!$bundleOk) {
            $warnings[] = 'DF_AAUTH_CA_BUNDLE is not readable: every discovery fetch fails.';
        }
        if (!Keys::rotationReady()) {
            $warnings[] = 'The key rotation migration has not run: php artisan migrate --force';
        }
        if ($sessionDriver === 'database' && !Schema::hasTable(SecureSessionCookie::TABLE)) {
            $warnings[] = 'DF_AAUTH_SESSION_DRIVER=database needs the aauth_sessions table: php artisan migrate --force';
        }
        $signIn = ['DreamFactory password'];
        try {
            $accounts = app(Accounts::class);
            foreach ($accounts->directories() as $d) {
                $signIn[] = 'directory ' . $d['name'];
            }
            if (\DreamFactory\Core\AAuth\PersonServer\SsoLogin::offered()) {
                $signIn[] = 'single sign-on (DreamFactory login page)';
            }
        } catch (\Throwable $e) {
        }
        try {
            $pendingLive = (int)DB::table(Pending::TABLE)->whereIn('status', Pending::LIVE)->where('expires_at', '>', now())->count();
        } catch (\Throwable $e) {
            $pendingLive = 0;
        }

        return [
            'enabled' => (bool)Settings::get('enabled', false) && $issuerOk && $gold,
            'issuer' => $issuer,
            'issuer_ok' => $issuerOk,
            'cache' => ['store' => $storeName, 'driver' => Store::driver(), 'shared' => Store::isShared()],
            'sessions' => ['driver' => $sessionDriver, 'shared' => $sessionShared],
            'egress' => [
                'private_hosts' => $policy->toArray()['hosts'],
                'private_networks' => $policy->toArray()['networks'],
                'ca_bundle' => $bundle,
                'ca_bundle_readable' => $bundleOk,
            ],
            'sign_in' => $signIn,
            'keys' => [
                'overlap_seconds' => Keys::overlap(),
                'rotation_days' => max(0, (int)config('df-aauth.key_rotation_days', 0)),
                'list' => Keys::inventory(),
            ],
            'pending_live' => $pendingLive,
            'warnings' => $warnings,
        ];
    }

    private static function duration(int $s): string
    {
        return $s % 86400 === 0 ? ($s / 86400) . 'd' : ($s % 3600 === 0 ? ($s / 3600) . 'h' : $s . 's');
    }
}
