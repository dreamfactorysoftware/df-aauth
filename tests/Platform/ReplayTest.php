<?php

namespace DreamFactory\Core\AAuth\Tests\Platform;

use DreamFactory\Core\AAuth\AgentProvider\AgentProvider;
use DreamFactory\Core\AAuth\Protocol\HttpRequestParts;
use DreamFactory\Core\AAuth\Protocol\HttpSignature;
use DreamFactory\Core\AAuth\Protocol\Jwk;
use DreamFactory\Core\AAuth\Protocol\Jws;
use DreamFactory\Core\AAuth\Resource\RequestVerifier;
use DreamFactory\Core\AAuth\Tests\Protocol\Support\Assertions;

/**
 * The replay record of a signed non-GET/HEAD request is keyed on what was signed (agent key +
 * signature base), so an ES256 request cannot be replayed with its malleated twin signature.
 */
final class ReplayTest extends TestCase
{
    use Assertions;

    /** P-256 group order n. */
    private const P256_N = 'FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551';
    private const URL = self::ISSUER . '/api/v2/sales/_table/orders/14';
    private const BODY = '{"status":"refunded"}';

    /** @return array{0: array, 1: HttpRequestParts} the agent key and a signed PATCH */
    private function signed(array $key, string $method = 'PATCH', string $body = self::BODY): array
    {
        $jwt = AgentProvider::agentToken(Jwk::publicOf($key), 'aauth:reports@df.example.test');
        $h = HttpSignature::sign($method, self::URL, $jwt, $key, [], $body);

        return [$key, HttpRequestParts::fromUrl($method, self::URL, array_change_key_case($h, CASE_LOWER), $body)];
    }

    private static function withSignature(HttpRequestParts $p, string $sig): HttpRequestParts
    {
        return new HttpRequestParts($p->method, $p->authority, $p->path, $p->query, ['signature' => 'sig=:' . base64_encode($sig) . ':'] + $p->headers, $p->body);
    }

    private static function signatureOf(HttpRequestParts $p): string
    {
        preg_match('/^sig=:([^:]+):$/', $p->headers['signature'], $m);

        return base64_decode($m[1]);
    }

    /** ECDSA malleability: (r, s) -> (r, n - s), a second valid signature over the same input. Plain byte arithmetic, no gmp/bcmath. */
    private static function twin(string $sig): string
    {
        $n = hex2bin(self::P256_N);
        $s = substr($sig, 32);
        $out = '';
        $borrow = 0;
        for ($i = 31; $i >= 0; $i--) {
            $d = ord($n[$i]) - ord($s[$i]) - $borrow;
            $borrow = $d < 0 ? 1 : 0;
            $out = chr($d + 256 * $borrow) . $out;
        }

        return substr($sig, 0, 32) . $out;
    }

    public function testMalleatedEs256SignatureIsAReplay(): void
    {
        [$key, $parts] = $this->signed(Jwk::generateEs256());
        $sig = self::signatureOf($parts);
        $twin = self::twin($sig);
        $this->assertNotSame($sig, $twin);
        $this->assertSame('aa-agent+jwt', RequestVerifier::verify($parts, [RequestVerifier::AGENT])['typ'], 'accepted once');

        // the twin is a valid signature over the same base: only the replay record can stop it
        $v = HttpSignature::verify(self::withSignature($parts, $twin), Jwk::publicOf($key), time());
        $this->assertTrue(Jws::verify($v['base'], $twin, Jwk::publicOf($key)));

        $e = $this->assertAAuthError('invalid_signature', fn () => RequestVerifier::verify(self::withSignature($parts, $twin), [RequestVerifier::AGENT]), 401);
        $this->assertSame('This signature was already used.', $e->detail);
    }

    public function testTwoSignaturesOverOneBaseCollide(): void
    {
        // ES256 signing is randomized: signing the same base again gives other bytes, same request
        [$key, $parts] = $this->signed(Jwk::generateEs256());
        $v = HttpSignature::verify($parts, Jwk::publicOf($key), time());
        $again = Jws::sign($v['base'], $key);
        $this->assertNotSame(self::signatureOf($parts), $again);
        RequestVerifier::verify(self::withSignature($parts, $again), [RequestVerifier::AGENT]);
        $e = $this->assertAAuthError('invalid_signature', fn () => RequestVerifier::verify($parts, [RequestVerifier::AGENT]));
        $this->assertSame('This signature was already used.', $e->detail);
    }

    public function testEd25519AndGetBehaveAsBefore(): void
    {
        [, $parts] = $this->signed(Jwk::generateEd25519());
        RequestVerifier::verify($parts, [RequestVerifier::AGENT]);
        $this->assertAAuthError('invalid_signature', fn () => RequestVerifier::verify($parts, [RequestVerifier::AGENT]));

        [, $get] = $this->signed(Jwk::generateEd25519(), 'GET', '');
        RequestVerifier::verify($get, [RequestVerifier::AGENT]);
        RequestVerifier::verify($get, [RequestVerifier::AGENT]);
        $this->addToAssertionCount(1); // GET is read-only and only bounded by the created window
    }
}
