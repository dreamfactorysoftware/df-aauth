<?php

namespace DreamFactory\Core\AAuth\Tests\Protocol;

use DreamFactory\Core\AAuth\Protocol\AAuthError;
use DreamFactory\Core\AAuth\Protocol\Discovery;
use DreamFactory\Core\AAuth\Protocol\Jwk;
use DreamFactory\Core\AAuth\Protocol\Jwt;
use DreamFactory\Core\AAuth\Tests\Protocol\Support\Assertions;
use DreamFactory\Core\AAuth\Tests\Protocol\Support\FakeFetcher;
use DreamFactory\Core\AAuth\Tests\Protocol\Support\FakeRefreshingFetcher;
use PHPUnit\Framework\TestCase;

final class DiscoveryTest extends TestCase
{
    use Assertions;

    private const ISS = 'https://agent.example';
    private const META = self::ISS . '/.well-known/aauth-agent.json';
    private const JWKS = self::ISS . '/jwks.json';

    private array $key;

    protected function setUp(): void
    {
        $this->key = Jwk::generateEd25519();
    }

    private function docs(array $jwksDocs, array $meta = []): array
    {
        return [
            self::META => $meta + ['issuer' => self::ISS, 'jwks_uri' => self::JWKS, 'name' => 'Agent'],
            self::JWKS => $jwksDocs,
        ];
    }

    public function testResolvesKeyAndMetadata(): void
    {
        $other = Jwk::generateEd25519();
        $f = new FakeFetcher($this->docs(['keys' => [
            ['kty' => 'RSA', 'kid' => 'junk'], // unusable member must not break selection
            Jwk::publicOf($other),
            Jwk::publicOf($this->key),
        ]]));
        $d = new Discovery($f);
        $r = $d->resolve(self::ISS, 'aauth-agent.json', $this->key['kid']);
        $this->assertTrue(Jwk::sameKey($this->key, $r['jwk']));
        $this->assertArrayNotHasKey('d', $r['jwk']);
        $this->assertSame('Agent', $r['meta']['name']);
        // memoized per instance
        $d->resolve(self::ISS, 'aauth-agent.json', $other['kid']);
        $this->assertSame([self::META, self::JWKS], $f->log);
    }

    public function testIssuerMismatchAndMissing(): void
    {
        $d = new Discovery(new FakeFetcher($this->docs(['keys' => []], ['issuer' => 'https://evil.example'])));
        $this->assertAAuthError('issuer_mismatch', fn () => $d->resolve(self::ISS, 'aauth-agent.json', 'k'), 401);
        $d = new Discovery(new FakeFetcher($this->docs(['keys' => []], ['issuer' => self::ISS . '/'])));
        $this->assertAAuthError('issuer_mismatch', fn () => $d->metadata(self::ISS, 'aauth-agent.json'));
        $d = new Discovery(new FakeFetcher([self::META => ['jwks_uri' => self::JWKS]]));
        $this->assertAAuthError('issuer_missing', fn () => $d->metadata(self::ISS, 'aauth-agent.json'));
    }

    public function testUnknownKidRefreshesOnce(): void
    {
        $rotated = Jwk::generateEd25519();
        $f = new FakeFetcher($this->docs([
            ['keys' => [Jwk::publicOf($this->key)]],
            ['keys' => [Jwk::publicOf($this->key), Jwk::publicOf($rotated)]],
        ]));
        $d = new Discovery($f);
        $d->resolve(self::ISS, 'aauth-agent.json', $this->key['kid']);
        $r = $d->resolve(self::ISS, 'aauth-agent.json', $rotated['kid']);
        $this->assertTrue(Jwk::sameKey($rotated, $r['jwk']));
        $this->assertSame(2, $f->count(self::JWKS));

        $this->assertAAuthError('unknown_key', fn () => $d->resolve(self::ISS, 'aauth-agent.json', 'nope'), 401);
        $this->assertSame(3, $f->count(self::JWKS), 'exactly one refresh per unknown kid');
    }

    public function testRefreshUsesFreshFetcherWhenAvailable(): void
    {
        $rotated = Jwk::generateEd25519();
        $f = new FakeRefreshingFetcher(
            $this->docs(['keys' => [Jwk::publicOf($this->key)]]),
            [self::JWKS => ['keys' => [Jwk::publicOf($rotated)]]]
        );
        $r = (new Discovery($f))->resolve(self::ISS, 'aauth-agent.json', $rotated['kid']);
        $this->assertTrue(Jwk::sameKey($rotated, $r['jwk']));
        $this->assertSame([self::JWKS], $f->freshLog);
    }

    public function testNullKidNeedsSingleKey(): void
    {
        $d = new Discovery(new FakeFetcher($this->docs(['keys' => [Jwk::publicOf($this->key)]])));
        $this->assertTrue(Jwk::sameKey($this->key, $d->resolve(self::ISS, 'aauth-agent.json', null)['jwk']));
        $d = new Discovery(new FakeFetcher($this->docs(['keys' => [Jwk::publicOf($this->key), Jwk::publicOf(Jwk::generateEd25519())]])));
        $this->assertAAuthError('unknown_key', fn () => $d->resolve(self::ISS, 'aauth-agent.json', null));
    }

    public function testSelectedKeyMustBeSupported(): void
    {
        $bad = Jwk::publicOf($this->key);
        unset($bad['alg']);
        $d = new Discovery(new FakeFetcher($this->docs(['keys' => [$bad]])));
        $this->assertAAuthError('unsupported_algorithm', fn () => $d->resolve(self::ISS, 'aauth-agent.json', $this->key['kid']));
    }

    public function testFetchFailuresMapToUnknownKey(): void
    {
        $d = new Discovery(new FakeFetcher([]));
        $e = $this->assertAAuthError('unknown_key', fn () => $d->resolve(self::ISS, 'aauth-agent.json', 'k'), 401);
        $this->assertStringContainsString('404', $e->detail);
        $d = new Discovery(new FakeFetcher([self::META => ['issuer' => self::ISS]]));
        $this->assertAAuthError('unknown_key', fn () => $d->resolve(self::ISS, 'aauth-agent.json', 'k'));
        $d = new Discovery(new FakeFetcher($this->docs([], ['jwks_uri' => 'http://agent.example/jwks.json'])));
        $this->assertAAuthError('unknown_key', fn () => $d->resolve(self::ISS, 'aauth-agent.json', 'k'));
        $d = new Discovery(new FakeFetcher($this->docs(['nokeys' => 1])));
        $this->assertAAuthError('unknown_key', fn () => $d->resolve(self::ISS, 'aauth-agent.json', 'k'));
    }

    public function testInvalidIssuerIsRejectedBeforeFetching(): void
    {
        $f = new FakeFetcher([]);
        $d = new Discovery($f);
        foreach (['http://agent.example', 'https://agent.example:8443', 'https://agent.example/', 'https://169.254.169.254/x'] as $iss) {
            $this->assertAAuthError('invalid_jwt', fn () => $d->resolve($iss, 'aauth-agent.json', 'k'), 401);
        }
        $this->assertAAuthError('invalid_jwt', fn () => $d->resolve(self::ISS, '../../etc/passwd', 'k'));
        $this->assertSame([], $f->log);
    }

    public function testAllowInsecureForDev(): void
    {
        $iss = 'http://localhost:8799';
        $f = new FakeFetcher([
            $iss . '/.well-known/aauth-agent.json' => ['issuer' => $iss, 'jwks_uri' => $iss . '/jwks.json'],
            $iss . '/jwks.json' => ['keys' => [Jwk::publicOf($this->key)]],
        ]);
        $r = (new Discovery($f, null, true))->resolve($iss, 'aauth-agent.json', $this->key['kid']);
        $this->assertTrue(Jwk::sameKey($this->key, $r['jwk']));
    }

    public function testLocalSelfResolutionSkipsHttp(): void
    {
        $f = new FakeFetcher([]);
        $seen = [];
        $local = function (string $iss, string $dwk, ?string $kid) use (&$seen) {
            $seen[] = [$iss, $dwk, $kid];
            if ($iss !== 'https://df.example') {
                return null;
            }
            return $kid === $this->key['kid'] ? ['jwk' => $this->key, 'meta' => ['issuer' => $iss]] : [];
        };
        $d = new Discovery($f, $local);
        $r = $d->resolve('https://df.example', 'aauth-person.json', $this->key['kid']);
        $this->assertArrayNotHasKey('d', $r['jwk'], 'private part stripped');
        $this->assertAAuthError('unknown_key', fn () => $d->resolve('https://df.example', 'aauth-person.json', 'other'));
        $this->assertSame([], $f->log);
        // non-local issuers fall through to HTTP
        $this->assertAAuthError('unknown_key', fn () => $d->resolve(self::ISS, 'aauth-agent.json', 'k'));
        $this->assertSame([self::META], $f->log);
    }

    public function testDiscoveryDrivesJwtVerify(): void
    {
        $agent = Jwk::generateEd25519();
        $jwt = Jwt::sign('aa-agent+jwt', [
            'iss' => self::ISS, 'dwk' => 'aauth-agent.json', 'sub' => 'aauth:x@agent.example',
            'cnf' => ['jwk' => Jwk::publicOf($agent)], 'jti' => 'j', 'iat' => 1000, 'exp' => 2000,
        ], $this->key);
        $v = Jwt::verify($jwt, 'aa-agent+jwt', new Discovery(new FakeFetcher($this->docs(['keys' => [Jwk::publicOf($this->key)]]))), 1500);
        $this->assertSame('Agent', $v['meta']['name']);
        // metadata issuer mismatch surfaces through Jwt::verify
        $d = new Discovery(new FakeFetcher($this->docs(['keys' => [Jwk::publicOf($this->key)]], ['issuer' => 'https://other.example'])));
        $this->assertAAuthError('issuer_mismatch', fn () => Jwt::verify($jwt, 'aa-agent+jwt', $d, 1500));
    }

    /** @return array<string, array{string, bool, bool}> id, allowInsecure, valid */
    public static function serverIds(): array
    {
        return [
            'plain' => ['https://ps.example', false, true],
            'subdomain' => ['https://df.api.example.com', false, true],
            'trailing slash' => ['https://ps.example/', false, false],
            'path' => ['https://ps.example/ps', false, false],
            'query' => ['https://ps.example?x=1', false, false],
            'fragment' => ['https://ps.example#f', false, false],
            'port' => ['https://ps.example:443', false, false],
            'http' => ['http://ps.example', false, false],
            'uppercase' => ['https://PS.example', false, false],
            'userinfo' => ['https://u@ps.example', false, false],
            'idn u-label' => ["https://b\xc3\xbccher.example", false, false],
            'idn a-label' => ['https://xn--bcher-kva.example', false, true],
            'empty' => ['', false, false],
            'relative' => ['ps.example', false, false],
            'space' => ['https://ps.example ', false, false],
            'http dev' => ['http://192.0.2.10:8796', true, true],
            'http dev path' => ['http://localhost:8796/', true, false],
        ];
    }

    #[\PHPUnit\Framework\Attributes\DataProvider('serverIds')]
    public function testAssertServerId(string $id, bool $insecure, bool $valid): void
    {
        try {
            Discovery::assertServerId($id, $insecure);
            $this->assertTrue($valid, "accepted {$id}");
        } catch (AAuthError $e) {
            $this->assertFalse($valid, "rejected {$id}: {$e->detail}");
            $this->assertSame(400, $e->status);
            $this->assertSame('invalid_request', $e->error);
        }
    }
}
