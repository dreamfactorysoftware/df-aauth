<?php

namespace DreamFactory\Core\AAuth\Tests\Platform;

use DreamFactory\Core\AAuth\PersonServer\IssuedTokens;
use DreamFactory\Core\AAuth\PersonServer\Pending;
use DreamFactory\Core\AAuth\Resource\Agents;
use DreamFactory\Core\AAuth\Resource\Scopes;
use DreamFactory\Core\AAuth\Support\Activity;
use DreamFactory\Core\AAuth\Support\Keys;
use DreamFactory\Core\AAuth\Support\Maintenance;
use DreamFactory\Core\AAuth\Support\Settings;

/** df:aauth prune: what goes, what stays, and the dry run. */
final class MaintenanceTest extends TestCase
{
    private function seed(): void
    {
        // first everything that may run the 1-in-N prune lottery, then the backdating
        Activity::log(['method' => 'GET', 'path' => '/api/v2/x', 'status' => 200, 'outcome' => 'allowed']);
        $agent = ['sub' => 'aauth:a@agent.example', 'iss' => 'https://agent.example', 'jkt' => 'J'];
        Pending::create('person', $agent, self::ISSUER, 'DF');
        $old = Pending::create('person', $agent, self::ISSUER, 'DF');
        $recent = Pending::create('person', $agent, self::ISSUER, 'DF');
        $this->db()->table(Pending::TABLE)->where('id', $old['id'])->update(['expires_at' => now()->subHours(2)]);
        $this->db()->table(Pending::TABLE)->where('id', $recent['id'])->update(['expires_at' => now()->subMinutes(10)]);

        $this->db()->table(Activity::TABLE)->insert(['created_at' => now()->subDays(40), 'method' => 'GET', 'path' => '/old', 'status' => 200, 'outcome' => 'allowed']);

        Agents::rememberKey('fresh-jkt', 'aauth:a@agent.example', 'https://agent.example', null);
        $this->db()->table(Agents::KEYS)->insert(['jkt' => 'stale-jkt', 'agent_id' => 'aauth:b@agent.example', 'issuer' => 'https://agent.example', 'last_seen_at' => now()->subDays(45)]);

        $old = Keys::publicJwk('resource')['kid'];
        Keys::rotate('resource');
        $this->db()->table(Keys::TABLE)->where('kid', $old)->update(['retired_at' => now()->subSeconds(Keys::overlap() + 1)]);

        Settings::set('retired_scopes', ['gone' => ['role_id' => 3, 'until' => time() - 5], 'kept' => ['role_id' => 4, 'until' => time() + 600]]);

        // a token record is kept for an hour after its token expired (nodes' clocks differ)
        foreach (['old' => -7200, 'recent' => -600, 'live' => 600] as $jti => $exp) {
            IssuedTokens::record($jti, 'auth', $agent, time() + $exp);
        }
    }

    public function testPruneRemovesOnlyWhatExpired(): void
    {
        $this->seed();
        $expected = ['pending' => 1, 'activity' => 1, 'agent_keys' => 1, 'signing_keys' => 1, 'retired_scopes' => 1, 'issued_tokens' => 1];
        $this->assertSame($expected, Maintenance::prune(true), 'dry run');
        $this->assertSame(3, $this->db()->table(Pending::TABLE)->count(), 'dry run removes nothing');
        $this->assertSame($expected, Maintenance::prune());
        $this->assertSame([], Maintenance::$errors);
        $this->assertSame(2, $this->db()->table(Pending::TABLE)->count(), 'live and recently expired requests stay (agents get their 408/410)');
        $this->assertSame(['/api/v2/x'], $this->db()->table(Activity::TABLE)->pluck('path')->all());
        $this->assertSame(['fresh-jkt'], $this->db()->table(Agents::KEYS)->pluck('jkt')->all());
        $this->assertSame(1, $this->db()->table(Keys::TABLE)->where('purpose', 'resource')->count());
        $this->assertSame(['kept'], array_keys(Settings::get('retired_scopes')));
        $this->assertSame(['live', 'recent'], $this->db()->table(IssuedTokens::TABLE)->orderBy('jti')->pluck('jti')->all());
        $this->assertSame(['pending' => 0, 'activity' => 0, 'agent_keys' => 0, 'signing_keys' => 0, 'retired_scopes' => 0, 'issued_tokens' => 0],
            Maintenance::prune(), 'idempotent');
    }

    public function testZeroRetentionKeepsActivityAndAgentKeys(): void
    {
        $this->seed();
        $this->app['config']->set('df-aauth.activity_retention_days', 0);
        $counts = Maintenance::prune();
        $this->assertSame(0, $counts['activity']);
        $this->assertSame(0, $counts['agent_keys']);
        $this->assertSame(1, $counts['pending']);
        $this->assertSame(2, $this->db()->table(Activity::TABLE)->count());
    }

    public function testRenamedScopeNamesAreReservedInTheDatabase(): void
    {
        $this->role(1, 'Sales');
        $this->role(2, 'Admin');
        Scopes::patch(1, ['scope' => 'sales.read', 'enabled' => true]);
        Scopes::patch(1, ['scope' => 'sales.view']);
        $this->app['cache']->store()->flush(); // another node, or an evicted cache, must not release it
        $this->forget();
        $this->assertSame(1, Settings::get('retired_scopes')['sales.read']['role_id']);
        try {
            Scopes::patch(2, ['scope' => 'sales.read']);
            $this->fail('another role took a reserved scope name');
        } catch (\Throwable $e) {
            $this->assertStringContainsString('belonged to another role', $e->getMessage());
        }
        $this->role(3, 'sales.read');
        $this->assertNotSame('sales.read', Scopes::patch(3, ['enabled' => false])['scope'], 'a suggested slug avoids reserved names too');
        Scopes::patch(1, ['scope' => 'sales.read']);
        $this->assertSame('sales.read', Scopes::get(1)['scope'], 'the role that gave the name up may take it back');

        Settings::set('retired_scopes', ['sales.view' => ['role_id' => 1, 'until' => time() - 1]]);
        Scopes::patch(2, ['scope' => 'sales.view']);
        $this->assertSame('sales.view', Scopes::get(2)['scope'], 'free again after the reservation expires');
    }
}
