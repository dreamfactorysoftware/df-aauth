<?php

namespace DreamFactory\Core\AAuth;

use DreamFactory\Core\AAuth\Console\AAuthCommand;
use DreamFactory\Core\AAuth\Http\Middleware\AAuthMiddleware;
use DreamFactory\Core\AAuth\PersonServer\Accounts;
use DreamFactory\Core\AAuth\PersonServer\DreamFactoryAccounts;
use DreamFactory\Core\AAuth\Resource\Scopes;
use DreamFactory\Core\AAuth\Resources\AAuth;
use DreamFactory\Core\AAuth\Support\AAuth as AAuthSupport;
use DreamFactory\Core\AAuth\Support\Keys;
use DreamFactory\Core\AAuth\Support\Settings;
use DreamFactory\Core\Enums\LicenseLevel;
use DreamFactory\Core\Exceptions\InternalServerErrorException;
use DreamFactory\Core\System\Components\SystemResourceManager;
use DreamFactory\Core\System\Components\SystemResourceType;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\ServiceProvider as BaseServiceProvider;

/**
 * Laravel auto-discovered provider (composer extra.laravel.providers).
 *
 * register(): config, the `aauth` system resource (/api/v2/system/aauth), the sign-in back end
 *   (Accounts), and the public routes, loaded while booting so they come before df-file's
 *   {storage}/{path} and df-core's api routes. Per-request memos are dropped when the app
 *   terminates (long-running workers such as Octane never carry settings or keys over).
 * boot(): migrations, the df:aauth command and its schedule (prune daily; rotate keys when
 *   DF_AAUTH_KEY_ROTATION_DAYS is set), cleanup listeners, and (after every provider booted) the
 *   df.aauth middleware spliced into df.api right before df.access_check (df-core builds that group
 *   in its own boot(), and a composer install would boot df-aauth first, so this must wait for booted()).
 */
class ServiceProvider extends BaseServiceProvider
{
    public const VERSION = '0.1.0';
    public const RESOURCE = 'aauth';
    public const MIDDLEWARE = 'df.aauth';

    public function register(): void
    {
        $this->mergeConfigFrom(__DIR__ . '/../config/df-aauth.php', 'df-aauth');
        $this->app->singletonIf(Accounts::class, DreamFactoryAccounts::class);
        if (method_exists($this->app, 'terminating')) {
            $this->app->terminating(static function (): void {
                static::flushState();
            });
        }

        $add = function (SystemResourceManager $df): void {
            static::addSystemResourceTypes($df);
        };
        if ($this->app->resolved('df.system.resource')) {
            $add($this->app->make('df.system.resource'));
        } else {
            $this->app->resolving('df.system.resource', $add);
        }

        $this->app->booting(function (): void {
            $this->loadRoutesFrom(__DIR__ . '/../routes/aauth.php');
        });

        $this->app->booted(function (): void {
            static::insertMiddleware($this->app['router']);
            static::widenCors();
        });
    }

    public function boot(): void
    {
        $this->publishes([__DIR__ . '/../config/df-aauth.php' => $this->app->configPath('df-aauth.php')], 'config');
        $this->loadMigrationsFrom(__DIR__ . '/../database/migrations');
        if ($this->app->runningInConsole()) {
            $this->commands([AAuthCommand::class]);
        }
        $this->callAfterResolving('Illuminate\Console\Scheduling\Schedule', function ($schedule) {
            static::schedule($schedule);
        });

        $events = $this->app['events'];
        // A role delete gives up the role's scope name only once the role row is really gone: the
        // DELETE can still fail after eloquent.deleting (a foreign key without cascade, such as a
        // login service's default role), and then nothing the role can notice may change. Before it,
        // the name is only noted and reserved for no role (harmless while the role exists, which may
        // always keep its own name); when even that cannot be stored the delete is refused.
        $events->listen('eloquent.deleting: DreamFactory\Core\Models\Role', function ($role): void {
            try {
                Scopes::roleDeleting((int)$role->getKey());
            } catch (\Throwable $e) {
                Log::error('df-aauth: role ' . $role->getKey() . ' not deleted, its AAuth scope name could not be released: ' . $e->getMessage());

                throw new InternalServerErrorException('AAuth could not release this role\'s scope name, so the role was not deleted. Try again.');
            }
        });
        // After it (inside the caller's transaction when there is one, as with rollback=true): the name
        // leaves grants and allow-lists, and the names the role renamed away earlier are reserved for
        // no role too. When that fails inside a transaction, the exception rolls the delete back.
        // Outside one the role is already gone, so the failure is logged and the cleanup is tried once
        // more when the request ends (flushState); its name is already reserved for no role, and a
        // role that takes it later starts without the grants and allow-list entries still naming it.
        $events->listen('eloquent.deleted: DreamFactory\Core\Models\Role', function ($role): void {
            try {
                Scopes::roleDeleted((int)$role->getKey());
            } catch (\Throwable $e) {
                if (DB::transactionLevel() > 0) {
                    Log::error('df-aauth: role ' . $role->getKey() . ' not deleted, its AAuth scope name could not be released: ' . $e->getMessage());

                    throw new InternalServerErrorException('AAuth could not release this role\'s scope name, so the role was not deleted. Try again.');
                }
                Log::error('df-aauth: role ' . $role->getKey() . ' deleted, but its AAuth scope name could not be removed from grants and person server lists: ' . $e->getMessage());
            }
        });
        $events->listen('DreamFactory\Core\Events\UserDeletedEvent', function ($event) {
            $this->cleanup(function () use ($event) {
                $id = $event->user->getKey();
                DB::table('aauth_ps_grants')->where('user_id', $id)->delete();
                DB::table('aauth_ps_subjects')->where('user_id', $id)->delete();
            });
        });
    }

    /** Daily housekeeping, and key rotation when DF_AAUTH_KEY_ROTATION_DAYS > 0 (DreamFactory images run schedule:run every minute). */
    public static function schedule($schedule): void
    {
        try {
            $schedule->command('df:aauth prune')->dailyAt('03:17')->onOneServer()->withoutOverlapping();
            $days = (int)config('df-aauth.key_rotation_days', 0);
            if ($days > 0) {
                $schedule->command('df:aauth rotate-keys --older-than=' . $days . ' --no-interaction')->dailyAt('03:47')->onOneServer()->withoutOverlapping();
            }
        } catch (\Throwable $e) {
            Log::warning('df-aauth: schedule not registered: ' . $e->getMessage());
        }
    }

    /**
     * End of request: finishes a role delete whose scope cleanup did not run or failed, then drops
     * every per-request memo (settings, signing keys, discovery).
     */
    public static function flushState(): void
    {
        Scopes::finishDeletes();
        Settings::flush();
        Keys::flush();
        AAuthSupport::flush();
    }

    public static function addSystemResourceTypes(SystemResourceManager $df): void
    {
        if ($df->getResourceType(self::RESOURCE) !== null) {
            return;
        }
        $df->addType(new SystemResourceType([
            'name' => self::RESOURCE,
            'label' => 'AAuth',
            'description' => 'Agent authorization: scopes, person servers, agents, activity and grants.',
            'class_name' => AAuth::class,
            'subscription_required' => LicenseLevel::GOLD,
            'singleton' => false,
            'read_only' => false,
        ]));
    }

    /** Runs df.aauth after df.auth_check and before df.access_check. Router methods only (never the Kernel sync). */
    public static function insertMiddleware($router): void
    {
        try {
            $router->aliasMiddleware(self::MIDDLEWARE, AAuthMiddleware::class);
            $group = $router->getMiddlewareGroups()['df.api'] ?? null;
            if (!is_array($group) || in_array(self::MIDDLEWARE, $group, true)) {
                return;
            }
            $at = array_search('df.access_check', $group, true);
            if ($at === false) {
                Log::warning('df-aauth: df.access_check not found in df.api; AAuth requests are not accepted.');

                return;
            }
            array_splice($group, $at, 0, [self::MIDDLEWARE]);
            $router->middlewareGroup('df.api', array_values($group));
        } catch (\Throwable $e) {
            Log::error('df-aauth: middleware not registered: ' . $e->getMessage());
        }
    }

    /**
     * Lets browsers send the signature headers and read the AAuth ones on the APIs. df-core (1.0.18,
     * DreamFactory 7.7.1) copies the enabled CORS entry that matches the request into config('cors')
     * while its providers boot, and Laravel's HandleCors applies config('cors') on every request, so
     * widening it here (booted(), after that copy) takes effect. No matching entry: nothing to widen.
     */
    public static function widenCors(): void
    {
        try {
            $c = config('cors', []);
            if (empty($c['allowed_origins']) && empty($c['allowedOrigins'])) {
                return;
            }
            // an entry with an empty field arrives as [''], which must not become a leading ", "
            $merge = fn (array $list, array $add) => in_array('*', $list, true) ? $list
                : array_values(array_unique(array_merge(array_filter(array_map('trim', $list), fn ($h) => $h !== ''), $add)));
            $req = ['Signature', 'Signature-Input', 'Signature-Key', 'Content-Digest'];
            $exp = ['AAuth-Requirement', 'Signature-Error', 'Location', 'Retry-After', 'AAuth-Scope'];
            config([
                'cors.allowed_headers' => $merge((array)($c['allowed_headers'] ?? []), $req),
                'cors.allowedHeaders' => $merge((array)($c['allowedHeaders'] ?? []), $req),
                'cors.exposed_headers' => $merge((array)($c['exposed_headers'] ?? []), $exp),
                'cors.exposedHeaders' => $merge((array)($c['exposedHeaders'] ?? []), $exp),
            ]);
        } catch (\Throwable $e) {
        }
    }

    private function cleanup(\Closure $fn): void
    {
        try {
            $fn();
        } catch (\Throwable $e) {
            Log::warning('df-aauth: cleanup failed: ' . $e->getMessage());
        }
    }
}
