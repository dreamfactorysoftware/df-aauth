<?php

namespace DreamFactory\Core\AAuth\Tests\Platform;

use DreamFactory\Core\AAuth\Support\AAuth;
use DreamFactory\Core\AAuth\Support\Keys;
use DreamFactory\Core\AAuth\Support\Settings;
use Illuminate\Cache\CacheManager;
use Illuminate\Config\Repository;
use Illuminate\Container\Container;
use Illuminate\Database\Capsule\Manager as Capsule;
use Illuminate\Encryption\Encrypter;
use Illuminate\Events\Dispatcher;
use Illuminate\Support\DateFactory;
use Illuminate\Support\Facades\Facade;
use Illuminate\Support\Facades\Schema;
use PHPUnit\Framework\TestCase as BaseTestCase;
use Psr\Log\NullLogger;

/**
 * Harness for df-aauth platform tests (copied from df-masking's approach): a bare container with
 * config (df-aauth defaults + issuer https://df.example.test), an array cache, an encrypter, events,
 * a null logger and an in-memory SQLite "system database" with stub DreamFactory tables (role, user,
 * user_to_app_to_role, app) plus every df-aauth migration. Nothing touches a live instance.
 */
abstract class TestCase extends BaseTestCase
{
    public const ISSUER = 'https://df.example.test';

    protected Container $app;
    protected Capsule $capsule;

    protected function setUp(): void
    {
        parent::setUp();
        $this->bootHarness();
    }

    protected function bootHarness(array $config = []): void
    {
        $app = new Container();
        Container::setInstance($app);
        $package = require dirname(__DIR__, 2) . '/config/df-aauth.php';
        $app->instance('config', new Repository(array_replace_recursive([
            'app' => ['timezone' => 'UTC', 'cipher' => 'AES-256-CBC', 'key' => 'base64:' . base64_encode(str_repeat('k', 32)), 'url' => 'http://127.0.0.1'],
            'cache' => ['default' => 'array', 'stores' => ['array' => ['driver' => 'array', 'serialize' => true]], 'prefix' => 'test'],
            'df-aauth' => array_replace($package, ['issuer' => self::ISSUER]),
        ], $config)));
        $app->instance('events', new Dispatcher($app));
        $app->instance('log', new NullLogger());
        $app->instance('date', new DateFactory());
        $app->instance('encrypter', new Encrypter(random_bytes(32), 'AES-256-CBC'));
        $app->singleton('cache', fn ($app) => new CacheManager($app));
        $app->singleton('cache.store', fn ($app) => $app['cache']->driver());

        $capsule = new Capsule($app);
        $capsule->addConnection(['driver' => 'sqlite', 'database' => ':memory:', 'prefix' => '', 'foreign_key_constraints' => true]);
        $capsule->setEventDispatcher($app['events']);
        $capsule->setAsGlobal();
        $capsule->bootEloquent();
        $app->instance('db', $capsule->getDatabaseManager());
        $app->bind('db.connection', fn ($app) => $app['db']->connection());
        $app->bind('db.schema', fn ($app) => $app['db']->connection()->getSchemaBuilder());
        $this->capsule = $capsule;

        Facade::clearResolvedInstances();
        Facade::setFacadeApplication($app);
        $this->app = $app;
        foreach (['Cache' => \Illuminate\Support\Facades\Cache::class, 'DB' => \Illuminate\Support\Facades\DB::class,
                  'Log' => \Illuminate\Support\Facades\Log::class, 'Crypt' => \Illuminate\Support\Facades\Crypt::class,
                  'Schema' => \Illuminate\Support\Facades\Schema::class, 'Config' => \Illuminate\Support\Facades\Config::class] as $alias => $class) {
            if (!class_exists($alias, false)) {
                class_alias($class, $alias);
            }
        }
        $this->stubTables();
        foreach (glob(dirname(__DIR__, 2) . '/database/migrations/*.php') ?: [] as $file) {
            $m = require $file;
            $m->up();
        }
        $this->forget();
    }

    protected function tearDown(): void
    {
        $this->forget();
        Facade::clearResolvedInstances();
        Facade::setFacadeApplication(null);
        Container::setInstance(null);
        parent::tearDown();
    }

    protected function forget(): void
    {
        Settings::flush();
        Keys::flush();
        AAuth::flush();
    }

    protected function db(): \Illuminate\Database\Connection
    {
        return $this->capsule->getConnection();
    }

    protected function role(int $id, string $name): void
    {
        $this->db()->table('role')->insert(['id' => $id, 'name' => $name, 'is_active' => true]);
    }

    protected function scope(int $roleId, string $scope, bool $enabled = true, ?string $description = null): void
    {
        $this->db()->table('aauth_scopes')->insert(['role_id' => $roleId, 'scope' => $scope, 'enabled' => $enabled, 'description' => $description]);
    }

    protected function user(int $id, string $email, bool $admin = false, array $roles = []): array
    {
        $this->db()->table('user')->insert(['id' => $id, 'name' => ucfirst(strtok($email, '@')), 'email' => $email, 'is_sys_admin' => $admin, 'is_active' => true]);
        foreach ($roles as $r) {
            $this->db()->table('user_to_app_to_role')->insert(['user_id' => $id, 'app_id' => 1, 'role_id' => $r]);
        }

        return (array)$this->db()->table('user')->where('id', $id)->first();
    }

    private function stubTables(): void
    {
        $schema = Schema::getFacadeRoot();
        $schema->create('role', function ($t) {
            $t->increments('id');
            $t->string('name', 64)->unique();
            $t->text('description')->nullable();
            $t->boolean('is_active')->default(true);
        });
        $schema->create('user', function ($t) {
            $t->increments('id');
            $t->string('name')->nullable();
            $t->string('first_name')->nullable();
            $t->string('last_name')->nullable();
            $t->string('email')->unique();
            $t->boolean('is_sys_admin')->default(false);
            $t->boolean('is_active')->default(true);
        });
        $schema->create('app', function ($t) {
            $t->increments('id');
            $t->string('name', 64)->unique();
        });
        $schema->create('user_to_app_to_role', function ($t) {
            $t->increments('id');
            $t->unsignedInteger('user_id');
            $t->unsignedInteger('app_id')->nullable();
            $t->unsignedInteger('role_id');
        });
    }
}
