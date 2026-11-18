<?php

namespace DreamFactory\Core\AAuth\Tests\Platform;

use DreamFactory\Core\AAuth\Protocol\AAuthError;
use DreamFactory\Core\AAuth\Support\EgressPolicy;
use DreamFactory\Core\AAuth\Support\SafeHttp;

/**
 * Private-network admission for discovery (DF_AAUTH_PRIVATE_HOSTS / DF_AAUTH_PRIVATE_NETWORKS) and the
 * internal CA bundle (DF_AAUTH_CA_BUNDLE). No network: hostnames resolve through a fake resolver.
 */
final class EgressPolicyTest extends TestCase
{
    private const METADATA = ['169.254.169.254', '169.254.0.1', 'fd00:ec2::254', '100.100.100.200', 'fe80::1', '0.0.0.0', '::',
        '::ffff:169.254.169.254', '64:ff9b::a9fe:a9fe', '2002:a9fe:a9fe::1', '::a9fe:a9fe', '224.0.0.1', 'ff02::1', '255.255.255.255'];

    private function admit(string $url, array $hosts = [], array $networks = [], array $dns = [], bool $insecure = false): array
    {
        return SafeHttp::admit($url, $insecure, new EgressPolicy(EgressPolicy::parseHosts($hosts), EgressPolicy::parseNetworks($networks)),
            fn (string $host) => $dns[$host] ?? []);
    }

    private function refused(callable $fn, string $why): void
    {
        try {
            $fn();
            $this->fail("admitted: $why");
        } catch (AAuthError $e) {
            $this->assertSame('unknown_key', $e->error, $why);
            $this->assertSame(401, $e->status, $why);
        }
    }

    public function testDefaultsKeepPublicOnlyEgress(): void
    {
        $policy = EgressPolicy::fromConfig();
        $this->assertTrue($policy->isEmpty());
        $dns = ['agents.corp.internal' => ['10.1.2.3']];
        $this->refused(fn () => $this->admit('https://agents.corp.internal/.well-known/aauth-agent.json', [], [], $dns), 'unlisted private host');
        $this->assertSame(['agent.example.com', 443, '8.8.8.8'], $this->admit('https://agent.example.com/x', [], [], ['agent.example.com' => ['8.8.8.8']]));
    }

    public function testListedHostnamesMayResolveToPrivateUseAddresses(): void
    {
        $hosts = ['agents.corp.internal', '*.svc.corp.internal'];
        $dns = [
            'agents.corp.internal' => ['10.1.2.3'], 'ps.svc.corp.internal' => ['172.20.0.9'], 'a.b.svc.corp.internal' => ['192.168.4.4'],
            'cgnat.svc.corp.internal' => ['100.64.1.1'], 'v6.svc.corp.internal' => ['fd12:3456::7'], 'svc.corp.internal' => ['10.9.9.9'],
            'other.corp.internal' => ['10.1.2.4'], 'loop.svc.corp.internal' => ['127.0.0.1'], 'loop6.svc.corp.internal' => ['::1'],
            'mixed.svc.corp.internal' => ['10.1.1.1', '169.254.169.254'],
        ];
        $this->assertSame('10.1.2.3', $this->admit('https://agents.corp.internal/x', $hosts, [], $dns)[2]);
        foreach (['ps', 'a.b', 'cgnat', 'v6'] as $h) {
            $this->admit("https://$h.svc.corp.internal/x", $hosts, [], $dns);
        }
        $this->refused(fn () => $this->admit('https://svc.corp.internal/x', $hosts, [], $dns), '*.x does not cover x itself');
        $this->refused(fn () => $this->admit('https://other.corp.internal/x', $hosts, [], $dns), 'host not listed');
        $this->refused(fn () => $this->admit('https://loop.svc.corp.internal/x', $hosts, [], $dns), 'a listed host never reaches loopback');
        $this->refused(fn () => $this->admit('https://loop6.svc.corp.internal/x', $hosts, [], $dns), 'nor IPv6 loopback');
        $this->refused(fn () => $this->admit('https://mixed.svc.corp.internal/x', $hosts, [], $dns), 'every resolved address must pass');
        $this->refused(fn () => $this->admit('http://agents.corp.internal/x', $hosts, [], $dns), 'still https only');
    }

    public function testListedNetworksAdmitAnyHostInside(): void
    {
        $nets = ['10.20.0.0/16', '127.0.0.1', 'fd12:3456::/48'];
        $dns = ['a.example' => ['10.20.7.7'], 'b.example' => ['10.21.0.1'], 'sidecar.local' => ['127.0.0.1'], 'c.example' => ['::ffff:10.20.1.1'],
                'd.example' => ['fd12:3456:0:1::5'], 'e.example' => ['127.0.0.2']];
        $this->admit('https://a.example/x', [], $nets, $dns);
        $this->admit('https://sidecar.local/x', [], $nets, $dns);
        $this->admit('https://c.example/x', [], $nets, $dns);
        $this->admit('https://d.example/x', [], $nets, $dns);
        $this->assertSame(['10.20.3.4', 443, '10.20.3.4'], $this->admit('https://10.20.3.4/jwks.json', [], $nets));
        $this->refused(fn () => $this->admit('https://b.example/x', [], $nets, $dns), 'outside the network');
        $this->refused(fn () => $this->admit('https://e.example/x', [], $nets, $dns), 'single address, not a /8');
    }

    public function testLinkLocalAndMetadataAreNeverAdmitted(): void
    {
        $everything = ['0.0.0.0/0', '::/0', '169.254.0.0/16', 'fd00::/8', '100.64.0.0/10'];
        foreach (self::METADATA as $ip) {
            $this->assertTrue(EgressPolicy::isForbidden($ip), $ip);
            $policy = new EgressPolicy(['*.corp.internal'], EgressPolicy::parseNetworks($everything));
            $this->assertFalse($policy->admits('x.corp.internal', $ip), "$ip admitted by config");
            $this->refused(fn () => $this->admit('https://x.corp.internal/latest/meta-data', ['*.corp.internal'], $everything, ['x.corp.internal' => [$ip]]), $ip);
            $this->refused(fn () => $this->admit('https://x.corp.internal/', [], [], ['x.corp.internal' => [$ip]], true), "$ip in insecure (dev) mode");
        }
        $this->refused(fn () => $this->admit('https://169.254.169.254/latest/meta-data', [], $everything), 'IP literal');
        $this->refused(fn () => $this->admit('https://[fd00:ec2::254]/latest/meta-data', [], $everything), 'AWS IMDS over IPv6');
        foreach (['8.8.8.8', '10.0.0.1', '127.0.0.1', '::1', 'fd12::1', '2606:4700:4700::1111'] as $ok) {
            $this->assertFalse(EgressPolicy::isForbidden($ok), $ok);
        }
    }

    public function testConfigParsingDropsInvalidEntries(): void
    {
        $this->assertSame(['agents.corp.internal', '*.corp.internal', 'ps.example'],
            EgressPolicy::parseHosts(' Agents.Corp.Internal , *.corp.internal, *, *.*.x, bad host, ps.example., , -x.com'));
        $this->assertSame(['10.0.0.0/8', 'fd00::/8', '127.0.0.1'],
            EgressPolicy::parseNetworks('10.0.0.0/8, 10.0.0.0/33, fd00::/8, nope, 127.0.0.1, 1.2.3.4/x'));
        $this->app['config']->set('df-aauth.private_hosts', '*.corp.internal');
        $this->app['config']->set('df-aauth.private_networks', '10.20.0.0/16');
        $this->assertSame(['hosts' => ['*.corp.internal'], 'networks' => ['10.20.0.0/16']], EgressPolicy::fromConfig()->toArray());
    }

    public function testEmbeddedIpv4Forms(): void
    {
        $this->assertSame('10.1.2.3', EgressPolicy::embeddedV4('::ffff:10.1.2.3'));
        $this->assertSame('169.254.169.254', EgressPolicy::embeddedV4('64:ff9b::a9fe:a9fe'));
        $this->assertSame('169.254.169.254', EgressPolicy::embeddedV4('2002:a9fe:a9fe::1'));
        $this->assertSame('169.254.169.254', EgressPolicy::embeddedV4('::a9fe:a9fe'));
        $this->assertNull(EgressPolicy::embeddedV4('::1'));
        $this->assertNull(EgressPolicy::embeddedV4('2001:4860:4860::8888'));
        $this->assertNull(EgressPolicy::embeddedV4('10.1.2.3'));
    }

    public function testCaBundle(): void
    {
        $this->assertSame([], SafeHttp::tlsOptions(), 'default: system trust store');
        $file = tempnam(sys_get_temp_dir(), 'ca');
        file_put_contents($file, "-----BEGIN CERTIFICATE-----\n-----END CERTIFICATE-----\n");
        try {
            $this->app['config']->set('df-aauth.ca_bundle', $file);
            $this->assertSame([CURLOPT_CAINFO => $file], SafeHttp::tlsOptions());
            $this->app['config']->set('df-aauth.ca_bundle', sys_get_temp_dir());
            $this->assertSame([CURLOPT_CAPATH => sys_get_temp_dir()], SafeHttp::tlsOptions(), 'a hashed directory');
            $this->app['config']->set('df-aauth.ca_bundle', '/nonexistent/ca.pem');
            $this->refused(fn () => SafeHttp::tlsOptions(), 'unreadable bundle fails closed');
            try {
                (new SafeHttp())->getJson('https://8.8.8.8/.well-known/aauth-agent.json');
                $this->fail('fetched with an unreadable CA bundle');
            } catch (AAuthError $e) {
                $this->assertStringContainsString('CA bundle', $e->detail);
                $this->assertStringNotContainsString('/nonexistent', $e->detail, 'the path is logged, not sent to the agent');
            }
        } finally {
            @unlink($file);
        }
    }
}
