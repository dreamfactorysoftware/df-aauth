<?php

namespace DreamFactory\Core\AAuth\Tests\Platform;

use DreamFactory\Core\AAuth\PersonServer\Minter;
use DreamFactory\Core\AAuth\Support\Settings;

final class SettingsTest extends TestCase
{
    public function testDefaultsAndRoundTrip(): void
    {
        $this->assertFalse(Settings::get('enabled'));
        $this->assertTrue(Settings::get('ps_local_enabled'));
        $this->assertFalse(Settings::enabled());
        Settings::set('enabled', true);
        $this->assertTrue(Settings::enabled());
        Settings::set('enabled', false);
        $this->assertFalse(Settings::enabled());
        Settings::set('name', ['nested' => 1]);
        $this->assertSame(['nested' => 1], Settings::get('name'));
        $this->assertSame(2, $this->db()->table('aauth_settings')->count());
    }

    public function testIssuerFacts(): void
    {
        $this->assertSame(self::ISSUER, Settings::issuer());
        $this->assertTrue(Settings::issuerOk());
        $this->assertSame('df.example.test', Settings::issuerAuthority());
        $this->assertSame(self::ISSUER . '/aauth/interact', Settings::url('/aauth/interact'));
    }

    public function testIssuerFallsBackToHttpsAppUrlOnly(): void
    {
        config(['df-aauth.issuer' => null, 'app.url' => 'https://API.Example.com/']);
        $this->assertSame('https://api.example.com', Settings::issuer());
        $this->assertTrue(Settings::issuerOk());
        config(['app.url' => 'http://192.0.2.10:8796']);
        $this->assertNull(Settings::issuer());
        $this->assertFalse(Settings::issuerOk());
    }

    public function testEnablingNeedsAValidIssuer(): void
    {
        Settings::set('enabled', true);
        config(['df-aauth.issuer' => 'http://insecure.example.com']);
        $this->assertFalse(Settings::issuerOk());
        $this->assertFalse(Settings::enabled());
        config(['df-aauth.allow_insecure' => true]);
        $this->assertTrue(Settings::enabled());
        config(['df-aauth.allow_insecure' => false, 'df-aauth.issuer' => 'https://ok.example.com:8443']);
        $this->assertFalse(Settings::issuerOk(), 'ports are not allowed in server identifiers');
    }

    public function testPersonAndAuthTokenLifetimesStayWithinTheVerifierCap(): void
    {
        config(['df-aauth.person_token_ttl' => 900, 'df-aauth.auth_token_ttl' => 86400]);
        $this->assertSame(900, Minter::lifetime('person_token_ttl'));
        $this->assertSame(3600, Minter::lifetime('auth_token_ttl'), 'tokens over an hour would fail verification');
        config(['df-aauth.person_token_ttl' => 0]);
        $this->assertSame(60, Minter::lifetime('person_token_ttl'));
    }

    public function testCorsWideningAddsTheAAuthHeadersWithoutEmptyEntries(): void
    {
        $this->app['config']->set('cors', ['allowed_origins' => ['https://app.example.org'], 'allowedOrigins' => ['https://app.example.org'],
            'allowed_headers' => ['Content-Type'], 'allowedHeaders' => ['Content-Type'], 'exposed_headers' => [''], 'exposedHeaders' => ['']]);
        \DreamFactory\Core\AAuth\ServiceProvider::widenCors();
        $c = $this->app['config']->get('cors');
        $this->assertSame(['Content-Type', 'Signature', 'Signature-Input', 'Signature-Key', 'Content-Digest'], $c['allowed_headers']);
        $this->assertSame($c['allowed_headers'], $c['allowedHeaders']);
        $this->assertSame(['AAuth-Requirement', 'Signature-Error', 'Location', 'Retry-After', 'AAuth-Scope'], $c['exposed_headers'], 'no empty first element (", AAuth-Requirement")');
        $this->assertSame($c['exposed_headers'], $c['exposedHeaders']);

        $this->app['config']->set('cors', ['allowed_origins' => ['*'], 'allowed_headers' => ['*'], 'exposed_headers' => ['*']]);
        \DreamFactory\Core\AAuth\ServiceProvider::widenCors();
        $this->assertSame(['*'], $this->app['config']->get('cors.allowed_headers'), 'a wildcard stays a wildcard');
        $this->assertSame(['*'], $this->app['config']->get('cors.exposed_headers'));
    }
}
