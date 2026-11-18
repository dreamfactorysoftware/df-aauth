<?php

namespace DreamFactory\Core\AAuth\Tests\Protocol;

use DreamFactory\Core\AAuth\Protocol\AAuthError;
use DreamFactory\Core\AAuth\Protocol\Discovery;
use DreamFactory\Core\AAuth\Protocol\HttpRequestParts;
use DreamFactory\Core\AAuth\Protocol\HttpSignature;
use DreamFactory\Core\AAuth\Protocol\Jwk;
use DreamFactory\Core\AAuth\Protocol\Jwt;
use DreamFactory\Core\AAuth\Protocol\SignatureKey;
use DreamFactory\Core\AAuth\Tests\Protocol\Support\FakeFetcher;
use PHPUnit\Framework\TestCase;

/**
 * Cross-implementation fixtures produced with the reference demo's JavaScript (shared/aauth.mjs) by
 * agent/interop.test.mjs. Format: tests/fixtures/README.md. Skipped when the files are absent.
 * AAUTH_FIXTURE_DIR overrides the directory.
 */
final class DemoFixtureTest extends TestCase
{
    private static function load(string $name): ?array
    {
        $dir = getenv('AAUTH_FIXTURE_DIR') ?: dirname(__DIR__) . '/fixtures';
        $file = rtrim($dir, '/') . '/' . $name;
        if (!is_file($file)) {
            return null;
        }
        return json_decode((string) file_get_contents($file), true, 64, JSON_THROW_ON_ERROR);
    }

    /** Real Discovery over a fake fetcher serving {issuer}/.well-known/{dwk} and the JWKS. */
    private static function discovery(string $iss, string $dwk, array $metadata, array $jwks): Discovery
    {
        $metadata += ['issuer' => $iss, 'jwks_uri' => $iss . '/jwks.json'];
        return new Discovery(new FakeFetcher([
            $iss . '/.well-known/' . $dwk => $metadata,
            $metadata['jwks_uri'] => $jwks,
        ]));
    }

    private static function parts(array $r): HttpRequestParts
    {
        return new HttpRequestParts($r['method'], $r['authority'], $r['path'], $r['query'] ?? null, $r['headers'], (string) ($r['body'] ?? ''));
    }

    /** Agent-token verification as the resource middleware does it; returns [token, signature] results. */
    private static function verifyRequest(array $f, array $r, int $now, bool $requireQuery = false): array
    {
        $req = self::parts($r);
        $sk = SignatureKey::parse($req->header('signature-key') ?? '');
        $ap = $f['agent_provider'];
        $tok = Jwt::verify($sk['jwt'], $f['expect']['typ'] ?? 'aa-agent+jwt', self::discovery($ap['issuer'], $ap['dwk'], $ap['metadata'], $ap['jwks']), $now);
        $sig = HttpSignature::verify($req, $tok['cnf_jwk'], $now, (int) ($f['window'] ?? 60), $requireQuery);
        return [$tok, $sig, $sk];
    }

    public function testDemoSignedRequests(): void
    {
        $f = self::load('demo-signed-request.json');
        if ($f === null) {
            $this->markTestSkipped('tests/fixtures/demo-signed-request.json not present (written by agent/interop.test.mjs)');
        }
        $now = (int) $f['now'];

        [$tok, $sig, $sk] = self::verifyRequest($f, $f['request'], $now);
        $this->assertSame($f['agent_token'], $sk['jwt']);
        $this->assertTrue(Jwk::sameKey($f['agent_public_jwk'], $tok['cnf_jwk']));
        $this->assertSame($f['agent_jkt'], Jwk::thumbprint($tok['cnf_jwk']));
        $this->assertSame($f['agent_token_claims'], $tok['payload']);
        $this->assertSame($f['expect']['components'], $sig['components']);
        $this->assertSame($f['expect']['created'], $sig['created']);

        if (isset($f['get_request'])) {
            [, $gsig] = self::verifyRequest($f, $f['get_request'], $now, true);
            $this->assertSame($f['expect']['get_components'], $gsig['components']);
        }
    }

    public function testDemoNegativeCases(): void
    {
        $f = self::load('demo-signed-request.json');
        if ($f === null) {
            $this->markTestSkipped('tests/fixtures/demo-signed-request.json not present (written by agent/interop.test.mjs)');
        }
        $this->assertNotEmpty($f['negative'] ?? []);
        foreach ($f['negative'] as $n) {
            $r = array_replace($f[$n['target']], $n['change'] ?? []);
            try {
                self::verifyRequest($f, $r, (int) ($n['now'] ?? $f['now']), (bool) ($n['require_query'] ?? false));
                $this->fail("{$n['name']}: verified, expected {$n['error']}");
            } catch (AAuthError $e) {
                $this->assertSame($n['error'], $e->error, "{$n['name']}: {$e->detail}");
                $this->assertSame(401, $e->status);
            }
        }
    }

    public function testDemoJwt(): void
    {
        $f = self::load('demo-jwt.json');
        if ($f === null) {
            $this->markTestSkipped('tests/fixtures/demo-jwt.json not present (written by agent/interop.test.mjs)');
        }
        $v = Jwt::verify($f['jwt'], $f['typ'], self::discovery($f['issuer'], $f['dwk'], $f['metadata'], $f['jwks']), (int) $f['now']);
        $this->assertSame($f['header'], $v['header']);
        $this->assertSame($f['payload'], $v['payload']);
        $this->assertSame($f['cnf_jkt'], Jwk::thumbprint($v['cnf_jwk']));
    }
}
