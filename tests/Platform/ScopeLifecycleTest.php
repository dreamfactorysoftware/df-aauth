<?php

namespace DreamFactory\Core\AAuth\Tests\Platform;

use DreamFactory\Core\AAuth\Http\Middleware\AAuthMiddleware;
use DreamFactory\Core\AAuth\PersonServer\Grants;
use DreamFactory\Core\AAuth\PersonServer\IssuedTokens;
use DreamFactory\Core\AAuth\PersonServer\Subjects;
use DreamFactory\Core\AAuth\Protocol\HttpSignature;
use DreamFactory\Core\AAuth\Protocol\Ids;
use DreamFactory\Core\AAuth\Protocol\Jwk;
use DreamFactory\Core\AAuth\Protocol\Jwt;
use DreamFactory\Core\AAuth\Resource\PersonServers;
use DreamFactory\Core\AAuth\Resource\ScopeResolver;
use DreamFactory\Core\AAuth\Resource\Scopes;
use DreamFactory\Core\AAuth\ServiceProvider;
use DreamFactory\Core\AAuth\Support\Keys;
use DreamFactory\Core\AAuth\Support\Settings;
use DreamFactory\Core\Exceptions\BadRequestException;
use DreamFactory\Core\Exceptions\InternalServerErrorException;
use DreamFactory\Core\Models\Role;
use Illuminate\Container\Container;
use Illuminate\Http\Request;
use Illuminate\Session\ArraySessionHandler;
use Illuminate\Session\Store as SessionStore;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Schema;
use Symfony\Component\HttpFoundation\Response;

/**
 * A scope name changes hands (role deleted or renamed, the name taken by another role later): tokens
 * issued for the earlier holder never reach the new one, whatever their lifetime; the name leaves
 * grants and person server allow-lists atomically with the rename, or the rename does not happen; a
 * role delete gives the name up only once the role row is gone (a delete that fails changes nothing
 * the role can notice), together with the name of a rename that raced it, and a cleanup that did not
 * run or failed is finished when the request ends; a name a role takes starts without grants or
 * allow-list entries; a deleted role's names are reserved for no role at all.
 */
final class ScopeLifecycleTest extends TestCase
{
    private array $key;

    protected function setUp(): void
    {
        parent::setUp();
        $this->role(1, 'Refunds');
        $this->role(2, 'Refunds v2');
        $this->key = Jwk::generateEd25519();
    }

    /** Session, df-core's lookup tables and role cache, so a request that passes df.aauth is served. */
    private function serving(): void
    {
        if (!class_exists(\DreamFactory\Core\Utility\Session::class)) {
            $this->markTestSkipped('needs df-core (the DreamFactory image vendor/)');
        }
        $session = new SessionStore('aauth_test', new ArraySessionHandler(10));
        $session->start();
        $this->app->instance('session', $session);
        if (!class_exists('Session', false)) {
            class_alias(\Illuminate\Support\Facades\Session::class, 'Session');
        }
        foreach ([1, 2] as $id) {
            Cache::forever("role:$id", ['id' => $id, 'name' => "Role $id", 'is_active' => true, 'role_service_access_by_role_id' => []]);
        }
        foreach (['lookup', 'app_lookup', 'role_lookup', 'user_lookup'] as $t) {
            Schema::create($t, function ($b) {
                $b->increments('id');
                $b->unsignedInteger('app_id')->nullable();
                $b->unsignedInteger('role_id')->nullable();
                $b->unsignedInteger('user_id')->nullable();
                $b->string('name')->nullable();
                $b->text('value')->nullable();
                $b->boolean('private')->default(false);
                $b->text('description')->nullable();
            });
        }
        Settings::set('enabled', true);
    }

    /** Registers df-aauth's real listeners (ServiceProvider::boot) on this harness's events. */
    private function bootProviderListeners(): void
    {
        if (!class_exists(Role::class)) {
            $this->markTestSkipped('needs df-core (the DreamFactory image vendor/)');
        }
        $fake = new class extends Container {
            public function runningInConsole(): bool
            {
                return false;
            }

            public function configPath($path = ''): string
            {
                return sys_get_temp_dir() . '/' . $path;
            }
        };
        $fake->instance('events', $this->app['events']);
        (new ServiceProvider($fake))->boot();
    }

    /** sales.refund on role 2, trusted by one person server's list, in one standing grant. */
    private function refundScopeInUse(): array
    {
        Scopes::patch(2, ['scope' => 'sales.refund', 'enabled' => true]);
        $ps = $this->db()->table(PersonServers::TABLE)->insertGetId(['issuer' => 'https://ps1.example', 'is_local' => false, 'enabled' => true, 'scopes' => json_encode(['sales.refund'])]);
        $grant = $this->db()->table(Grants::TABLE)->insertGetId(['user_id' => 1, 'resource' => self::ISSUER, 'agent_iss' => 'https://a.example',
            'agent_sub' => 'aauth:x@a.example', 'scope' => 'sales.refund', 'created_at' => now()]);

        return [$ps, $grant];
    }

    /** Makes one table the cleanup writes unavailable (a transient database failure). */
    private function breakPersonServers(bool $broken): void
    {
        $this->breakTable('aauth_person_servers', $broken);
    }

    private function breakTable(string $table, bool $broken): void
    {
        $this->db()->statement($broken ? "ALTER TABLE $table RENAME TO {$table}_away" : "ALTER TABLE {$table}_away RENAME TO $table");
    }

    /**
     * Like a login service's default role (ldap_config.default_role; oauth, oidc, saml and azure_ad
     * configs alike): a reference to role.id without ON DELETE CASCADE, which refuses the delete.
     */
    private function referenceWithoutCascade(int $roleId): void
    {
        Schema::create('ldap_config', function ($t) {
            $t->increments('service_id');
            $t->unsignedInteger('default_role')->nullable();
            $t->foreign('default_role')->references('id')->on('role');
        });
        $this->db()->table('ldap_config')->insert(['default_role' => $roleId]);
    }

    private function reservations(): array
    {
        return json_decode((string)$this->db()->table('aauth_settings')->where('name', 'retired_scopes')->value('value'), true) ?: [];
    }

    /** An auth token from this DreamFactory's person server, issued at $iat (recorded as Minter does). */
    private function authToken(array $user, string $scope, int $iat): string
    {
        $jti = Ids::random();
        IssuedTokens::record($jti, 'auth', ['sub' => 'aauth:x@a.example', 'iss' => 'https://a.example'], $iat + 3600);

        return Jwt::sign('aa-auth+jwt', [
            'iss' => self::ISSUER, 'dwk' => 'aauth-person.json', 'aud' => self::ISSUER, 'ps' => self::ISSUER,
            'sub' => Subjects::record((int)$user['id'], self::ISSUER), 'cnf' => ['jwk' => Jwk::publicOf($this->key)],
            'scope' => $scope, 'jti' => $jti, 'iat' => $iat, 'exp' => $iat + 3600,
        ], Keys::privateJwk('person'));
    }

    private function api(string $jwt): Response
    {
        $url = self::ISSUER . '/api/v2';
        $h = HttpSignature::sign('GET', $url, $jwt, $this->key);
        $server = ['REMOTE_ADDR' => '198.51.100.7'];
        foreach ($h as $name => $value) {
            $server['HTTP_' . strtoupper(str_replace('-', '_', $name))] = $value;
        }
        $mw = new AAuthMiddleware(new ScopeResolver(fn () => true, fn () => [0, 0]));

        return $mw->handle(Request::create($url, 'GET', [], [], [], $server), fn () => new Response('SERVED', 200));
    }

    public function testATokenIssuedBeforeARoleTookTheNameNeverReachesIt(): void
    {
        $this->serving();
        $user = $this->user(5, 'jordan@corp.test', false, [1, 2]);
        Scopes::patch(1, ['scope' => 'sales.refund', 'enabled' => true]);
        $issuedForRole1 = time() - 1800;
        Scopes::roleDeleting(1);
        $this->db()->table('role')->where('id', 1)->delete();
        Scopes::roleDeleted(1);

        // an hour later the reservation is over and role 2 takes the name; the old token was minted
        // late (an external person server's deferred approval) and is still within its hour
        Settings::set('retired_scopes', []);
        Scopes::patch(2, ['scope' => 'sales.refund', 'enabled' => true]);
        $old = $this->authToken($user, 'sales.refund', $issuedForRole1);
        $r = $this->api($old);
        $this->assertSame(401, $r->getStatusCode(), (string)$r->getContent());
        $this->assertSame('insufficient_scope', json_decode((string)$r->getContent(), true)['error'], 'a step-up, as for a scope never granted');
        $this->assertStringContainsString('resource-token=', (string)$r->headers->get('AAuth-Requirement'));

        $r = $this->api($this->authToken($user, 'sales.refund', time()));
        $this->assertSame(200, $r->getStatusCode(), (string)$r->getContent());
        $this->assertSame('SERVED', $r->getContent());
        $this->assertSame('sales.refund', $r->headers->get('AAuth-Scope'));
    }

    public function testDeletingADreamFactoryRoleRunsTheCleanupThroughTheProviderListeners(): void
    {
        $this->bootProviderListeners();
        [$ps, $grant] = $this->refundScopeInUse();
        Role::find(2)->delete();

        $this->assertNull($this->db()->table('role')->where('id', 2)->first());
        $this->assertNull($this->db()->table('aauth_scopes')->where('role_id', 2)->first());
        $this->assertSame([], PersonServers::get($ps)['scopes']);
        $this->assertNull($this->db()->table(Grants::TABLE)->where('id', $grant)->first());
        $this->assertSame(Scopes::NO_ROLE, $this->reservations()['sales.refund']['role_id']);
    }

    /**
     * The DELETE fails after df-aauth's deleting listener ran (a foreign key without cascade): the
     * role keeps its scope, grants, person server entries and its own name, which it can re-save.
     */
    public function testARoleDeleteThatFailsAfterTheListenerChangesNothing(): void
    {
        $this->bootProviderListeners();
        [$ps, $grant] = $this->refundScopeInUse();
        $this->referenceWithoutCascade(2);
        try {
            Role::find(2)->delete();
            $this->fail('the role was deleted although a row references it');
        } catch (\Throwable $e) {
            $this->assertStringContainsString('FOREIGN KEY', $e->getMessage());
        }

        $this->assertNotNull($this->db()->table('role')->where('id', 2)->first(), 'the role is still there');
        $this->assertSame('sales.refund', $this->db()->table('aauth_scopes')->where('role_id', 2)->value('scope'));
        $this->assertSame('sales.refund', $this->db()->table(Grants::TABLE)->where('id', $grant)->value('scope'), 'its "Always allow" is kept');
        $this->assertSame(['sales.refund'], PersonServers::get($ps)['scopes'], 'and so is the person server\'s trust');
        // the name was reserved for no role before the DELETE, which the role that holds it never notices
        $this->assertSame(Scopes::NO_ROLE, $this->reservations()['sales.refund']['role_id']);
        $this->assertSame('sales.refund', Scopes::patch(2, ['scope' => 'sales.refund', 'description' => 'Refunds'])['scope'], 're-saving its own name');
        $this->assertSame('sales.refund2', Scopes::patch(2, ['scope' => 'sales.refund2'])['scope'], 'renaming works as before');
        $this->assertSame('sales.refund2', $this->db()->table(Grants::TABLE)->where('id', $grant)->value('scope'));
        $this->assertSame(2, $this->reservations()['sales.refund']['role_id'], 'the name it renamed away is its own again');
        $this->assertSame('sales.refund', Scopes::patch(2, ['scope' => 'sales.refund'])['scope'], 'and it may take it back');
        $this->assertSame('sales.refund2', Scopes::patch(2, ['scope' => 'sales.refund2'])['scope']);
        ServiceProvider::flushState(); // the end of the refused request: its note is dropped, nothing is cleaned up
        $this->assertSame('sales.refund2', $this->db()->table(Grants::TABLE)->where('id', $grant)->value('scope'));

        // once nothing references it, the delete goes through and gives both names up
        $this->db()->table('ldap_config')->delete();
        Role::find(2)->delete();
        $this->assertNull($this->db()->table('role')->where('id', 2)->first());
        $this->assertNull($this->db()->table(Grants::TABLE)->where('id', $grant)->first());
        $this->assertSame([], PersonServers::get($ps)['scopes']);
        $this->assertSame(['sales.refund' => Scopes::NO_ROLE, 'sales.refund2' => Scopes::NO_ROLE], array_map(fn ($v) => $v['role_id'], $this->reservations()));
    }

    /** A role re-sending the name it holds is never refused, whatever reservation names it. */
    public function testARoleMayAlwaysResaveItsOwnName(): void
    {
        Scopes::patch(2, ['scope' => 'sales.refund', 'enabled' => true]);
        Settings::set('retired_scopes', ['sales.refund' => ['role_id' => Scopes::NO_ROLE, 'until' => time() + 3600]]);
        $this->assertSame('Refunds', Scopes::patch(2, ['scope' => 'sales.refund', 'description' => 'Refunds'])['description']);
        try {
            Scopes::patch(1, ['scope' => 'sales.refund']);
            $this->fail('another role took a name in use');
        } catch (BadRequestException $e) {
            $this->assertStringContainsString('already used by another role', $e->getMessage());
        }
    }

    public function testARoleDeleteIsRefusedWhenItsNameCannotBeReserved(): void
    {
        $this->bootProviderListeners();
        [$ps, $grant] = $this->refundScopeInUse();
        $this->breakTable('aauth_settings', true);
        try {
            Role::find(2)->delete();
            $this->fail('the role was deleted without its scope name reserved');
        } catch (InternalServerErrorException $e) {
            $this->assertStringContainsString('the role was not deleted', $e->getMessage());
        } finally {
            $this->breakTable('aauth_settings', false);
        }
        $this->assertNotNull($this->db()->table('role')->where('id', 2)->first(), 'the role is kept');
        $this->assertSame('sales.refund', $this->db()->table(Grants::TABLE)->where('id', $grant)->value('scope'));
        $this->assertSame(['sales.refund'], PersonServers::get($ps)['scopes']);

        Role::find(2)->delete(); // the admin tries again
        $this->assertNull($this->db()->table('role')->where('id', 2)->first());
        $this->assertNull($this->db()->table(Grants::TABLE)->where('id', $grant)->first());
        $this->assertSame(Scopes::NO_ROLE, $this->reservations()['sales.refund']['role_id']);
    }

    /** rollback=true: the cleanup runs inside the caller's transaction, and its failure rolls the delete back. */
    public function testACleanupThatFailsInsideATransactionRollsTheDeleteBack(): void
    {
        $this->bootProviderListeners();
        [$ps, $grant] = $this->refundScopeInUse();
        $this->breakPersonServers(true);
        try {
            $this->db()->transaction(fn () => Role::find(2)->delete());
            $this->fail('the role was deleted with its scope name still in a grant');
        } catch (InternalServerErrorException $e) {
            $this->assertStringContainsString('the role was not deleted', $e->getMessage());
        } finally {
            $this->breakPersonServers(false);
        }
        $this->assertNotNull($this->db()->table('role')->where('id', 2)->first(), 'rolled back');
        $this->assertSame('sales.refund', $this->db()->table('aauth_scopes')->where('role_id', 2)->value('scope'));
        $this->assertSame('sales.refund', $this->db()->table(Grants::TABLE)->where('id', $grant)->value('scope'));
        $this->assertArrayNotHasKey('sales.refund', $this->reservations(), 'nothing half done');
    }

    /**
     * Outside a transaction the role is gone before the cleanup runs; when that fails (and fails
     * again when the request ends), the name stays reserved for no role, and the role that takes it
     * later starts without the grants and person server entries that still name it.
     */
    public function testACleanupThatFailsAfterTheRoleIsGoneLeavesNothingToInherit(): void
    {
        $this->bootProviderListeners();
        $this->role(3, 'Someone else');
        [$ps, $grant] = $this->refundScopeInUse();
        $this->breakPersonServers(true);
        try {
            Role::find(2)->delete(); // logged, not thrown: the row is already gone
            ServiceProvider::flushState(); // tried once more when the request ends, and failing again
        } finally {
            $this->breakPersonServers(false);
        }
        $this->assertNull($this->db()->table('role')->where('id', 2)->first());
        $this->assertSame('sales.refund', $this->db()->table(Grants::TABLE)->where('id', $grant)->value('scope'), 'the cleanup did not run');
        $this->assertSame(Scopes::NO_ROLE, $this->reservations()['sales.refund']['role_id'], 'reserved for no role before the delete');
        try {
            Scopes::patch(3, ['scope' => 'sales.refund']);
            $this->fail('another role took the deleted role\'s name within the hour');
        } catch (BadRequestException $e) {
            $this->assertStringContainsString('until recently', $e->getMessage());
        }

        Settings::set('retired_scopes', []); // an hour later
        $this->assertSame('sales.refund', Scopes::patch(3, ['scope' => 'sales.refund', 'enabled' => true])['scope']);
        $this->assertNull($this->db()->table(Grants::TABLE)->where('id', $grant)->first(), 'the grant left behind is not inherited');
        $this->assertSame([], PersonServers::get($ps)['scopes'], 'nor the person server entry');
    }

    /** A cleanup that failed after the delete is tried once more when the request ends. */
    public function testACleanupThatFailedIsFinishedWhenTheRequestEnds(): void
    {
        $this->bootProviderListeners();
        [$ps, $grant] = $this->refundScopeInUse();
        $this->breakPersonServers(true);
        try {
            Role::find(2)->delete();
        } finally {
            $this->breakPersonServers(false);
        }
        $this->assertSame('sales.refund', $this->db()->table(Grants::TABLE)->where('id', $grant)->value('scope'), 'not yet');

        ServiceProvider::flushState();
        $this->assertNull($this->db()->table(Grants::TABLE)->where('id', $grant)->first());
        $this->assertSame([], PersonServers::get($ps)['scopes']);
        $this->assertSame(Scopes::NO_ROLE, $this->reservations()['sales.refund']['role_id']);
    }

    /**
     * A deleted listener registered before df-aauth's throws, so df-aauth's never runs: the cleanup is
     * done when the request ends, including the names the role renamed away earlier.
     */
    public function testACleanupThatDidNotRunIsFinishedWhenTheRequestEnds(): void
    {
        if (!class_exists(Role::class)) {
            $this->markTestSkipped('needs df-core (the DreamFactory image vendor/)');
        }
        $this->app['events']->listen('eloquent.deleted: ' . Role::class, function () {
            throw new \RuntimeException('a subscriber that runs first fails');
        });
        $this->bootProviderListeners();
        Scopes::patch(2, ['scope' => 'old.name', 'enabled' => true]);
        [$ps, $grant] = $this->refundScopeInUse(); // a rename: old.name stays reserved for role 2
        try {
            Role::find(2)->delete();
            $this->fail('the other listener did not throw');
        } catch (\RuntimeException $e) {
        }
        $this->assertNull($this->db()->table('role')->where('id', 2)->first());
        $this->assertSame('sales.refund', $this->db()->table(Grants::TABLE)->where('id', $grant)->value('scope'), 'df-aauth\'s listener did not run');
        $this->assertSame(['old.name' => 2, 'sales.refund' => Scopes::NO_ROLE], array_map(fn ($v) => $v['role_id'], $this->reservations()));

        ServiceProvider::flushState();
        $this->assertNull($this->db()->table(Grants::TABLE)->where('id', $grant)->first());
        $this->assertSame([], PersonServers::get($ps)['scopes']);
        $this->assertSame(['old.name' => Scopes::NO_ROLE, 'sales.refund' => Scopes::NO_ROLE], array_map(fn ($v) => $v['role_id'], $this->reservations()));
    }

    /**
     * Another admin request renames the scope between df-aauth's deleting listener and the DELETE: the
     * name the role held at the DELETE is given up too (grants, allow-lists, reservation), not only
     * the one noted before it.
     */
    public function testARenameThatRacesTheDeleteIsGivenUpToo(): void
    {
        $this->bootProviderListeners();
        $this->role(3, 'Someone else');
        [$ps, $grant] = $this->refundScopeInUse();
        $renamed = false;
        $this->app['events']->listen('eloquent.deleting: ' . Role::class, function () use (&$renamed) {
            if (!$renamed) {
                $renamed = true;
                Scopes::patch(2, ['scope' => 'sales.refund2']); // the other request
            }
        });
        Role::find(2)->delete();

        $this->assertTrue($renamed);
        $this->assertNull($this->db()->table(Grants::TABLE)->where('id', $grant)->first(), 'the grant followed the rename and went with the role');
        $this->assertSame([], PersonServers::get($ps)['scopes']);
        $this->assertSame(['sales.refund' => Scopes::NO_ROLE, 'sales.refund2' => Scopes::NO_ROLE], array_map(fn ($v) => $v['role_id'], $this->reservations()));
        foreach (['sales.refund', 'sales.refund2'] as $name) {
            try {
                Scopes::patch(3, ['scope' => $name]);
                $this->fail("another role took $name within the hour");
            } catch (BadRequestException $e) {
                $this->assertStringContainsString('until recently', $e->getMessage());
            }
        }
    }

    /** Following renames never gives up a name another role holds now. */
    public function testGivingUpADeletedRolesNamesLeavesAnotherRolesNameAlone(): void
    {
        $this->role(3, 'Someone else');
        Scopes::patch(2, ['scope' => 'sales.refund', 'enabled' => true]);
        Scopes::patch(3, ['scope' => 'sales.other', 'enabled' => true]);
        $grant = $this->db()->table(Grants::TABLE)->insertGetId(['user_id' => 1, 'resource' => self::ISSUER, 'agent_iss' => 'https://a.example',
            'agent_sub' => 'aauth:x@a.example', 'scope' => 'sales.other', 'created_at' => now()]);
        Scopes::roleDeleting(2);
        // a damaged list naming role 3's name as role 2's successor
        Settings::set('retired_scopes', ['sales.refund' => ['role_id' => 2, 'until' => time() + 600, 'to' => 'sales.other']]);
        $this->db()->table('role')->where('id', 2)->delete();
        Scopes::roleDeleted(2);
        $this->assertSame('sales.other', $this->db()->table(Grants::TABLE)->where('id', $grant)->value('scope'));
        $this->assertArrayNotHasKey('sales.other', $this->reservations());
        $this->assertSame('sales.other', Scopes::patch(3, ['scope' => 'sales.other', 'description' => 'x'])['scope']);
    }

    public function testAGrantSavedWhileTheRoleIsBeingDeletedIsRemovedAfterTheDelete(): void
    {
        $this->bootProviderListeners();
        $this->refundScopeInUse();
        // an approval already under way saves its grant between the cleanup and the DELETE
        $this->app['events']->listen('eloquent.deleting: ' . Role::class, function () {
            Grants::save(1, self::ISSUER, 'DF', 'https://a.example', 'aauth:late@a.example', null, ['sales.refund', 'email']);
        });
        Role::find(2)->delete();
        $this->assertSame(['email'], Grants::find(1, self::ISSUER, 'https://a.example', 'aauth:late@a.example')['scopes']);
    }

    public function testAFailedRenameIsNotMadeAndCanBeRetried(): void
    {
        [$ps, $grant] = $this->refundScopeInUse();
        $this->breakPersonServers(true);
        try {
            Scopes::patch(2, ['scope' => 'sales.refund2']);
            $this->fail('the rename went through without its cleanup');
        } catch (\Throwable $e) {
        }
        $this->breakPersonServers(false);
        $this->assertSame('sales.refund', Scopes::get(2)['scope'], 'rolled back');
        $this->assertArrayNotHasKey('sales.refund', $this->reservations());

        $this->assertSame('sales.refund2', Scopes::patch(2, ['scope' => 'sales.refund2'])['scope']);
        $this->assertSame('sales.refund2', $this->db()->table(Grants::TABLE)->where('id', $grant)->value('scope'));
        $this->assertSame(['sales.refund2'], PersonServers::get($ps)['scopes']);
        $this->assertSame(2, $this->reservations()['sales.refund']['role_id']);
    }

    public function testADeletedRolesNamesStayReservedEvenForARoleThatGetsItsIdAgain(): void
    {
        Scopes::patch(2, ['scope' => 'sales.refund', 'enabled' => true]);
        Scopes::patch(2, ['scope' => 'sales.refund2']); // reserved for role 2, which may take it back ...
        Scopes::roleDeleting(2);
        $this->db()->table('role')->where('id', 2)->delete();
        Scopes::roleDeleted(2);
        $this->assertSame(['sales.refund' => Scopes::NO_ROLE, 'sales.refund2' => Scopes::NO_ROLE], array_map(fn ($v) => $v['role_id'], $this->reservations()));

        // ... until it is deleted: MySQL 5.7 gives the next role the highest deleted id after a restart
        $this->role(2, 'Someone else');
        foreach (['sales.refund', 'sales.refund2'] as $name) {
            try {
                Scopes::patch(2, ['scope' => $name]);
                $this->fail("a new role with the deleted role's id took $name");
            } catch (BadRequestException $e) {
                $this->assertStringContainsString('until recently', $e->getMessage());
            }
        }
        $this->db()->table('role')->where('id', 2)->update(['name' => 'sales.refund']);
        $this->assertSame('sales.refund-2', Scopes::patch(2, ['enabled' => true])['scope'], 'nor is it suggested to it');
    }

    public function testReservationsAreRewrittenFromTheStoredListNotAStaleCopy(): void
    {
        Scopes::patch(1, ['scope' => 'sales.read']);
        Scopes::patch(2, ['scope' => 'sales.refund']);
        $this->assertSame([], Settings::get('retired_scopes', []), 'this request has read the list');
        // meanwhile another node reserves a name
        $this->db()->table('aauth_settings')->insert(['name' => 'retired_scopes', 'value' => json_encode(['old.name' => ['role_id' => 9, 'until' => time() + 600]])]);
        Scopes::patch(1, ['scope' => 'sales.view']);
        $this->assertArrayHasKey('sales.read', $this->reservations());
        $this->assertArrayHasKey('old.name', $this->reservations(), 'the other node\'s reservation is kept');
    }
}
