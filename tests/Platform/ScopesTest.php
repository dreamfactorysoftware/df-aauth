<?php

namespace DreamFactory\Core\AAuth\Tests\Platform;

use DreamFactory\Core\AAuth\Resource\PersonServers;
use DreamFactory\Core\AAuth\Resource\Scopes;
use DreamFactory\Core\AAuth\Support\Metadata;
use DreamFactory\Core\AAuth\Support\Settings;
use DreamFactory\Core\Exceptions\BadRequestException;
use DreamFactory\Core\Exceptions\NotFoundException;

final class ScopesTest extends TestCase
{
    protected function setUp(): void
    {
        parent::setUp();
        $this->role(1, 'Sales read');
        $this->role(2, 'Sales Refunds (EU)');
    }

    public function testUnconfiguredRolesGetASuggestedDisabledScope(): void
    {
        $all = Scopes::all();
        $scopes = array_column($all, 'scope', 'role_id');
        ksort($scopes);
        $this->assertSame([1 => 'sales-read', 2 => 'sales-refunds-eu'], $scopes);
        $this->assertSame([false, false], array_column($all, 'enabled'));
        $this->assertSame([], Scopes::descriptions());
    }

    public function testPatchCreatesValidatesAndPublishes(): void
    {
        $row = Scopes::patch(1, ['enabled' => true]);
        $this->assertSame('sales-read', $row['scope']);
        $this->assertTrue($row['enabled']);
        $row = Scopes::patch(1, ['scope' => 'Sales.Read', 'description' => 'Read customers and orders']);
        $this->assertSame('sales.read', $row['scope']);
        $this->assertSame(['sales.read' => 'Read customers and orders'], Scopes::descriptions());
        Scopes::patch(2, ['enabled' => true]);
        $this->assertSame(['sales.read' => 'Read customers and orders', 'sales-refunds-eu' => 'Sales Refunds (EU)'], Scopes::descriptions());
        $this->assertSame('auth-token', Metadata::resource()['access_mode']);
        $this->assertSame(['@query', 'content-type', 'content-digest'], Metadata::resource()['additional_signature_components']);
        $this->assertArrayNotHasKey('interaction_endpoint', Metadata::person(), 'the consent page is not a §7.6 relay endpoint');
    }

    public function testRejectsBadDuplicateAndReservedScopes(): void
    {
        Scopes::patch(1, ['scope' => 'sales.read']);
        foreach (['', 'has space', '-lead', str_repeat('a', 65), 'sales.read', 'profile'] as $bad) {
            try {
                Scopes::patch(2, ['scope' => $bad]);
                $this->fail("accepted '$bad'");
            } catch (BadRequestException $e) {
                $this->assertNotSame('', $e->getMessage());
            }
        }
        $this->expectException(NotFoundException::class);
        Scopes::patch(99, ['enabled' => true]);
    }

    public function testRenameKeepsReferencesOnTheRoleAndReservesTheOldName(): void
    {
        Scopes::patch(1, ['scope' => 'sales.read', 'enabled' => true]);
        Scopes::patch(2, ['scope' => 'sales.refund', 'enabled' => true]);
        $ps = $this->db()->table('aauth_person_servers')->insertGetId(['issuer' => 'https://ps.example', 'is_local' => false, 'enabled' => true, 'scopes' => json_encode(['sales.read'])]);
        $this->db()->table('aauth_ps_grants')->insert(['user_id' => 1, 'resource' => self::ISSUER, 'agent_iss' => 'https://a.example', 'agent_sub' => 'aauth:x@a.example', 'scope' => 'sales.read email', 'created_at' => now()]);

        Scopes::patch(1, ['scope' => 'sales.view']);
        $this->assertSame(['sales.view'], json_decode($this->db()->table('aauth_person_servers')->where('id', $ps)->value('scopes'), true));
        $this->assertSame('sales.view email', $this->db()->table('aauth_ps_grants')->value('scope'));
        try {
            Scopes::patch(2, ['scope' => 'sales.read']);
            $this->fail('another role took a just-retired scope name');
        } catch (BadRequestException $e) {
            $this->assertStringContainsString('until recently', $e->getMessage());
        }
        $this->assertSame('sales.read', Scopes::patch(1, ['scope' => 'sales.read'])['scope'], 'the same role may take its old name back');
    }

    public function testDeletingARoleTakesItsScopeNameOutOfGrantsAndPersonServers(): void
    {
        Scopes::patch(1, ['scope' => 'sales.read', 'enabled' => true]);
        Scopes::patch(2, ['scope' => 'sales.refund', 'enabled' => true]);
        $ps = fn (string $issuer, ?array $scopes) => $this->db()->table('aauth_person_servers')->insertGetId(
            ['issuer' => $issuer, 'is_local' => false, 'enabled' => true, 'scopes' => $scopes === null ? null : json_encode($scopes)]);
        $only = $ps('https://ps1.example', ['sales.refund']);
        $both = $ps('https://ps2.example', ['sales.read', 'sales.refund']);
        $every = $ps('https://ps3.example', null);
        $grant = fn (string $resource, string $scope, string $sub) => $this->db()->table('aauth_ps_grants')->insertGetId(
            ['user_id' => 1, 'resource' => $resource, 'agent_iss' => 'https://a.example', 'agent_sub' => $sub, 'scope' => $scope, 'created_at' => now()]);
        $refundOnly = $grant(self::ISSUER, 'sales.refund', 'aauth:x@a.example');
        $mixed = $grant(self::ISSUER, 'sales.read sales.refund email', 'aauth:y@a.example');
        $elsewhere = $grant('https://other-resource.example', 'sales.refund', 'aauth:x@a.example');

        Scopes::roleDeleting(2); // what the eloquent.deleting listener runs
        $this->assertSame(['sales.refund'], PersonServers::get($only)['scopes'], 'nothing is given up before the row is gone');
        $this->assertSame('sales.refund', $this->db()->table('aauth_ps_grants')->where('id', $refundOnly)->value('scope'));
        $this->db()->table('role')->where('id', 2)->delete();
        Scopes::roleDeleted(2); // and the eloquent.deleted listener

        $this->assertSame([], PersonServers::get($only)['scopes'], 'trusts no scope now');
        $this->assertFalse(PersonServers::get($only)['all_scopes'], 'an emptied list never becomes "all scopes"');
        $this->assertSame(['sales.read'], PersonServers::get($both)['scopes']);
        $this->assertTrue(PersonServers::get($every)['all_scopes']);
        $grants = $this->db()->table('aauth_ps_grants')->pluck('scope', 'id')->all();
        $this->assertArrayNotHasKey($refundOnly, $grants, 'a grant left with no scope is deleted');
        $this->assertSame('sales.read email', $grants[$mixed]);
        $this->assertSame('sales.refund', $grants[$elsewhere], 'another resource\'s scope names are not ours');

        // the name stays reserved, so a new role cannot pick it up while tokens may still carry it
        $this->role(3, 'Refunds v2');
        try {
            Scopes::patch(3, ['scope' => 'sales.refund']);
            $this->fail('a new role took a deleted role\'s scope name at once');
        } catch (BadRequestException $e) {
            $this->assertStringContainsString('until recently', $e->getMessage());
        }
    }

    public function testAGivenUpNameIsReservedForTheLongestAuthTokenDreamFactoryAccepts(): void
    {
        // tokens from any person server may live an hour (and carry an iat up to a minute ahead),
        // whatever DF_AAUTH_AUTH_TOKEN_TTL says (DreamFactory's own tokens are capped at an hour too)
        foreach ([60, 600, 3600, 7200] as $ttl) {
            $this->app['config']->set('df-aauth.auth_token_ttl', $ttl);
            $this->assertSame(3660, Scopes::reserved(), "TTL $ttl");
        }

        $this->app['config']->set('df-aauth.auth_token_ttl', 600);
        Scopes::patch(1, ['scope' => 'sales.read']);
        $before = time();
        Scopes::patch(1, ['scope' => 'sales.view']);
        $until = Settings::get('retired_scopes')['sales.read']['until'];
        $this->assertGreaterThanOrEqual($before + 3660, $until);
        $this->assertLessThanOrEqual(time() + 3660, $until);
    }

    public function testARoleHoldsItsScopeNameFromWhenItTookIt(): void
    {
        $before = time();
        Scopes::patch(1, ['scope' => 'sales.read', 'enabled' => true]);
        $since = (int)$this->db()->table('aauth_scopes')->where('role_id', 1)->value('scope_since');
        $this->assertGreaterThanOrEqual($before, $since);
        $this->assertLessThanOrEqual(time(), $since);
        Scopes::patch(1, ['description' => 'Read', 'enabled' => false]);
        $this->assertSame($since, (int)$this->db()->table('aauth_scopes')->where('role_id', 1)->value('scope_since'), 'only a new name moves it');
        $this->db()->table('aauth_scopes')->where('role_id', 1)->update(['scope_since' => $since - 100]);
        Scopes::patch(1, ['scope' => 'sales.view']);
        $this->assertGreaterThanOrEqual($since, (int)$this->db()->table('aauth_scopes')->where('role_id', 1)->value('scope_since'), 'a rename does');

        $row = ['scope_since' => 1000];
        $this->assertTrue(Scopes::heldAt($row, 1000));
        $this->assertTrue(Scopes::heldAt($row, 4000));
        $this->assertFalse(Scopes::heldAt($row, 999), 'issued before the role took the name');
        $this->assertTrue(Scopes::heldAt(['scope_since' => null], 1), 'rows from before the column existed');
    }
}
