<?php

namespace DreamFactory\Core\AAuth\Tests\Platform;

use DreamFactory\Core\AAuth\Protocol\AAuthError;
use DreamFactory\Core\AAuth\Support\SafeHttp;

/** Egress admission for discovery fetches (no network needed: IP-literal hosts). */
final class SafeHttpTest extends TestCase
{
    public function testPublicIpClassification(): void
    {
        foreach (['8.8.8.8', '9.9.9.9', '2606:4700:4700::1111'] as $ip) {
            $this->assertTrue(SafeHttp::isPublicIp($ip), $ip);
        }
        foreach (['127.0.0.1', '10.1.2.3', '172.24.0.4', '192.168.1.1', '169.254.169.254', '100.64.0.1', '0.0.0.0',
                  '224.0.0.1', '::1', 'fe80::1', 'fd00:ec2::254', 'fc00::1', '::ffff:127.0.0.1', 'not-an-ip'] as $ip) {
            $this->assertFalse(SafeHttp::isPublicIp($ip), $ip);
        }
    }

    public function testIpv6FormsEmbeddingInternalIpv4AreRefused(): void
    {
        foreach (['64:ff9b::a9fe:a9fe', '64:ff9b::7f00:1', '2002:a9fe:a9fe::1', '2002:0a00:0001::1', 'fec0::1', '::ffff:0:a9fe:a9fe',
                  '64:ff9b:1::a9fe:a9fe', '100::1', '2001:db8::1', '2001::1', '2001:10::1', '::', '::a9fe:a9fe', 'ff02::1', '3fff::1'] as $ip) {
            $this->assertFalse(SafeHttp::isPublicIp($ip), $ip);
        }
        foreach (['64:ff9b::808:808', '2002:808:808::1', '2a00:1450:4001::1', '2001:4860:4860::8888'] as $ip) {
            $this->assertTrue(SafeHttp::isPublicIp($ip), $ip);
        }
    }

    public function testFailuresAreCachedPerUrl(): void
    {
        $http = new SafeHttp();
        $url = 'https://10.9.8.7/.well-known/aauth-agent.json';
        foreach ([1, 2] as $i) {
            try {
                $http->getJson($url);
                $this->fail('fetched a private address');
            } catch (AAuthError $e) {
                $this->assertSame('unknown_key', $e->error);
                $this->assertSame($i === 2, str_contains($e->detail, '(cached)'), $e->detail);
            }
        }
    }

    public function testAdmitRejectsInsecureAndPrivateTargets(): void
    {
        foreach (['http://8.8.8.8/x', 'https://127.0.0.1/x', 'https://169.254.169.254/latest/meta-data', 'https://[::1]/x',
                  'https://10.0.0.5/.well-known/aauth-agent.json', 'ftp://8.8.8.8/x', 'https://user:pw@8.8.8.8/x'] as $url) {
            try {
                SafeHttp::admit($url);
                $this->fail("admitted $url");
            } catch (AAuthError $e) {
                $this->assertSame(401, $e->status);
                $this->assertSame('unknown_key', $e->error);
            }
        }
        $this->assertSame(['8.8.8.8', 443, '8.8.8.8'], SafeHttp::admit('https://8.8.8.8/jwks.json'));
    }

    public function testAllowInsecureIsTheDevEscapeHatch(): void
    {
        $this->assertSame(['127.0.0.1', 8796, '127.0.0.1'], SafeHttp::admit('http://127.0.0.1:8796/x', true));
    }
}
