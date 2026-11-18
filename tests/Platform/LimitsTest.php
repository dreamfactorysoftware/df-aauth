<?php

namespace DreamFactory\Core\AAuth\Tests\Platform;

use DreamFactory\Core\AAuth\PersonServer\Pending;
use DreamFactory\Core\AAuth\PersonServer\SignIn;
use DreamFactory\Core\AAuth\Resource\Agents;
use DreamFactory\Core\AAuth\Support\ClientIp;
use DreamFactory\Core\AAuth\Support\Throttle;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Cache;

/** Client address behind a proxy, failure limits, single-use codes, pending caps, durable agent keys. */
final class LimitsTest extends TestCase
{
    private function req(string $peer, ?string $xff = null): Request
    {
        $server = ['REMOTE_ADDR' => $peer];
        if ($xff !== null) {
            $server['HTTP_X_FORWARDED_FOR'] = $xff;
        }

        return Request::create('https://df.example.test/aauth/interact', 'POST', [], [], [], $server);
    }

    public function testForwardedForIsBelievedOnlyFromATrustedProxy(): void
    {
        $this->assertSame('203.0.113.9', ClientIp::of($this->req('203.0.113.9', '1.2.3.4')), 'no trusted proxies: XFF ignored');
        $this->app['config']->set('df-aauth.trusted_proxies', '172.24.0.1, 10.0.0.0/8');
        $this->assertSame('1.2.3.4', ClientIp::of($this->req('172.24.0.1', '1.2.3.4')));
        $this->assertSame('5.6.7.8', ClientIp::of($this->req('172.24.0.1', '1.2.3.4, 5.6.7.8')), 'right-most untrusted hop');
        $this->assertSame('5.6.7.8', ClientIp::of($this->req('172.24.0.1', '1.2.3.4, 5.6.7.8, 10.1.1.1')));
        $this->assertSame('203.0.113.9', ClientIp::of($this->req('203.0.113.9', '1.2.3.4')), 'direct clients cannot forge XFF');
        $this->assertSame('172.24.0.1', ClientIp::of($this->req('172.24.0.1', 'garbage')));
        $this->assertTrue(ClientIp::matches('2001:db8::5', '2001:db8::/32'));
        $this->assertFalse(ClientIp::matches('2001:db9::5', '2001:db8::/32'));
    }

    public function testSignInLocksPerAddressAndPerAccount(): void
    {
        $this->assertFalse(SignIn::locked('1.1.1.1', 'admin@x'));
        for ($i = 0; $i < SignIn::IP_LIMIT; $i++) {
            Throttle::hit('login-ip', '1.1.1.1', 600);
        }
        $this->assertTrue(SignIn::locked('1.1.1.1', 'someone@x'));
        $this->assertFalse(SignIn::locked('2.2.2.2', 'someone@x'), 'another client is not affected');
        for ($i = 0; $i < SignIn::ACCOUNT_LIMIT; $i++) {
            Throttle::hit('login-acct', 'admin@x', 900);
        }
        $this->assertTrue(SignIn::locked('3.3.3.3', 'admin@x'), 'guessing one account from many addresses is capped');
        $throttled = SignIn::attempt($this->req('3.3.3.3'), 'Admin@X', 'guess');
        $this->assertSame('throttled', $throttled['status'], 'a locked account is not even checked');
    }

    public function testInteractionCodesAreSingleUsePerBrowser(): void
    {
        $p = Pending::create('person', ['sub' => 'aauth:a@agent.example', 'iss' => 'https://agent.example', 'jkt' => 'J'], self::ISSUER, 'DF');
        $this->assertFalse(Pending::claimedElsewhere($p, 'browser-2'), 'nobody owns an unclaimed request');
        $this->assertTrue(Pending::claim($p, 'browser-1'));
        $this->assertTrue(Pending::claim($p, 'browser-1'), 'the owner may reopen it');
        $this->assertFalse(Pending::claim($p, 'browser-2'), 'a second browser is refused');
        $this->assertFalse(Pending::claimedElsewhere($p, 'browser-1'));
        $this->assertTrue(Pending::claimedElsewhere($p, 'browser-2'));
    }

    public function testRepeatedFailedSignInsEndTheRequest(): void
    {
        $p = Pending::create('person', ['sub' => 'aauth:a@agent.example', 'iss' => 'https://agent.example', 'jkt' => 'J'], self::ISSUER, 'DF');
        $this->assertTrue(Pending::fail($p['id']));
        [$status, $body] = Pending::poll(Pending::find($p['id']));
        $this->assertSame(410, $status);
        $this->assertSame('invalid_code', $body['error']);
        $this->assertNull(Pending::findLiveByCode($p['code']));
        $this->assertSame('failed', Pending::findByCode($p['code'])['status']);
    }

    public function testLiveCountAndPrune(): void
    {
        $agent = ['sub' => 'aauth:a@agent.example', 'iss' => 'https://agent.example', 'jkt' => 'J'];
        Pending::create('person', $agent, self::ISSUER, 'DF');
        Pending::create('person', $agent, self::ISSUER, 'DF');
        Pending::create('person', ['sub' => 'aauth:b@agent.example'] + $agent, self::ISSUER, 'DF');
        $this->assertSame(2, Pending::liveCountForAgent('https://agent.example', 'aauth:a@agent.example'));
        $old = Pending::create('person', $agent, self::ISSUER, 'DF');
        $this->db()->table('aauth_ps_pending')->where('id', $old['id'])->update(['expires_at' => now()->subHours(2)]);
        $this->assertSame(1, Pending::prune());
        $this->assertNull(Pending::find($old['id']));
    }

    public function testAgentKeysAreDurableSoBlocksSurviveTheCache(): void
    {
        Agents::rememberKey('JKT-AAAAAAAAAAAA', 'aauth:bot@evil.example', 'https://evil.example', 'Bot');
        Cache::flush();
        $id = Agents::identityForKey('JKT-AAAAAAAAAAAA');
        $this->assertSame('aauth:bot@evil.example', $id['agent_id'], 'mapping read back from aauth_agent_keys');
        $this->assertSame('https://evil.example', $id['issuer']);
        $this->assertSame('jkt:JKT-unknownX', Agents::identityForKey('JKT-unknownXYZ')['agent_id']);

        $row = Agents::seen($id['agent_id'], $id['issuer'], 'Bot');
        $this->assertFalse(Agents::isBlocked('aauth:bot@evil.example', 'https://evil.example'));
        Agents::patch((int)$row['id'], ['status' => 'blocked']);
        $this->assertTrue(Agents::isBlocked('aauth:bot@evil.example', 'https://evil.example'));
        try {
            Agents::delete((int)$row['id']);
            $this->fail('deleted a blocked agent');
        } catch (\DreamFactory\Core\Exceptions\BadRequestException $e) {
        }
        Agents::patch((int)$row['id'], ['status' => 'allowed']);
        $this->db()->table('aauth_activity')->insert(['created_at' => now(), 'agent_row_id' => $row['id'], 'method' => 'GET', 'path' => '/x', 'status' => 200, 'outcome' => 'allowed']);
        Agents::delete((int)$row['id']);
        $this->assertSame(0, $this->db()->table('aauth_agents')->count());
        $this->assertNull($this->db()->table('aauth_activity')->value('agent_row_id'), 'activity kept, detached');
        $this->assertSame(0, $this->db()->table('aauth_agent_keys')->count());
    }
}
