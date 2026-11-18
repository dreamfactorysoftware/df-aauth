<?php

namespace DreamFactory\Core\AAuth\Tests\Platform;

use DreamFactory\Core\AAuth\Console\AAuthCommand;
use DreamFactory\Core\AAuth\Http\Middleware\SecureSessionCookie;
use DreamFactory\Core\AAuth\PersonServer\Pending;
use DreamFactory\Core\AAuth\Support\Store;
use DreamFactory\Core\AAuth\Support\Throttle;
use Illuminate\Cache\ArrayStore;
use Illuminate\Cache\Repository;

/**
 * Multi-node: every short-lived AAuth record goes through one configurable cache store
 * (DF_AAUTH_CACHE_STORE), counters always expire, and the consent pages can use a shared session
 * driver (DF_AAUTH_SESSION_DRIVER).
 */
final class StoreTest extends TestCase
{
    protected function setUp(): void
    {
        parent::setUp();
        $this->app['config']->set('cache.stores.shared', ['driver' => 'array', 'serialize' => true]);
        $this->app['config']->set('cache.stores.racy', ['driver' => 'racy']);
        $this->app['cache']->extend('racy', fn () => new Repository(new RacyArrayStore()));
    }

    public function testEverythingGoesToTheConfiguredStore(): void
    {
        $this->app['config']->set('df-aauth.cache_store', 'shared');
        $shared = $this->app['cache']->store('shared');
        $default = $this->app['cache']->store();
        Throttle::hit('login-ip', '1.2.3.4', 600);
        $p = Pending::create('person', ['sub' => 'aauth:a@agent.example', 'iss' => 'https://agent.example', 'jkt' => 'J'], self::ISSUER, 'DF');
        $this->assertTrue(Pending::claim($p, 'browser-on-node-a'));

        $default->flush(); // a node-local default store (another node) knows nothing...
        $this->assertSame(1, Throttle::count('login-ip', '1.2.3.4'), '...and changes nothing');
        $this->assertFalse(Pending::claim($p, 'browser-on-node-b'), 'single use holds across nodes sharing the store');
        $shared->flush();
        $this->assertSame(0, Throttle::count('login-ip', '1.2.3.4'));
    }

    public function testAnUndefinedStoreFallsBackToTheDefaultInsteadOfSwitchingLimitsOff(): void
    {
        $this->app['config']->set('df-aauth.cache_store', 'typo');
        $this->assertSame($this->app['cache']->store(), Store::cache());
        for ($i = 0; $i < 3; $i++) {
            Throttle::hit('code-ip', '5.5.5.5', 600);
        }
        $this->assertSame(3, Throttle::count('code-ip', '5.5.5.5'));
    }

    public function testACounterRecreatedByIncrementStillExpires(): void
    {
        $this->app['config']->set('df-aauth.cache_store', 'racy');
        $store = $this->app['cache']->store('racy')->getStore();
        Throttle::hit('login-ip', '9.9.9.9', 600);
        $store->expireBeforeNextIncrement = true; // the window ends between add() and increment()
        $this->assertSame(1, Throttle::hit('login-ip', '9.9.9.9', 600));
        foreach ($store->dump() as $key => $item) {
            $this->assertGreaterThan(0, $item['expiresAt'], "$key has no TTL: it would never reset");
        }
    }

    public function testSharedStoreDetection(): void
    {
        $this->app['config']->set('cache.default', 'array');
        $this->assertFalse(Store::isShared());
        $this->app['config']->set('cache.stores.redis', ['driver' => 'redis', 'connection' => 'cache']);
        $this->app['config']->set('df-aauth.cache_store', 'redis');
        $this->assertSame('redis', Store::driver());
        $this->assertTrue(Store::isShared());
    }

    public function testConsentSessionDriverOverride(): void
    {
        $this->app['config']->set('session.driver', 'file');
        $this->app['config']->set('session.table', 'sessions');
        SecureSessionCookie::applyDriver();
        $this->assertSame('file', config('session.driver'), 'unset: SESSION_DRIVER stays');
        $this->app['config']->set('df-aauth.session_driver', 'redis');
        SecureSessionCookie::applyDriver();
        $this->assertSame('redis', config('session.driver'));
        $this->app['config']->set('df-aauth.session_driver', 'database');
        SecureSessionCookie::applyDriver();
        $this->assertSame(['database', 'aauth_sessions'], [config('session.driver'), config('session.table')]);
        $this->assertTrue($this->db()->getSchemaBuilder()->hasTable('aauth_sessions'));
    }

    public function testStatusWarnsAboutNodeLocalState(): void
    {
        $this->app['config']->set('session.driver', 'file');
        $warnings = implode("\n", AAuthCommand::report()['warnings']);
        $this->assertStringContainsString('DF_AAUTH_CACHE_STORE', $warnings);
        $this->assertStringContainsString('DF_AAUTH_SESSION_DRIVER', $warnings);
        $this->app['config']->set('cache.stores.redis', ['driver' => 'redis']);
        $this->app['config']->set('df-aauth.cache_store', 'redis');
        $this->app['config']->set('df-aauth.session_driver', 'redis');
        $this->app['config']->set('df-aauth.ca_bundle', '/nonexistent.pem');
        $r = AAuthCommand::report();
        $this->assertTrue($r['cache']['shared']);
        $this->assertTrue($r['sessions']['shared']);
        $warnings = implode("\n", $r['warnings']);
        $this->assertStringNotContainsString('DF_AAUTH_CACHE_STORE', $warnings);
        $this->assertStringContainsString('DF_AAUTH_CA_BUNDLE', $warnings);
    }
}

/** An array store whose key can vanish right before increment(), as an expiring redis key would. */
final class RacyArrayStore extends ArrayStore
{
    public bool $expireBeforeNextIncrement = false;

    public function increment($key, $value = 1)
    {
        if ($this->expireBeforeNextIncrement) {
            $this->expireBeforeNextIncrement = false;
            $this->forget($key);
        }

        return parent::increment($key, $value);
    }

    public function dump(): array
    {
        return $this->storage;
    }
}
