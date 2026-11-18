<?php

namespace DreamFactory\Core\AAuth\Tests\Protocol;

use DreamFactory\Core\AAuth\Protocol\B64;
use DreamFactory\Core\AAuth\Protocol\Jwk;
use DreamFactory\Core\AAuth\Protocol\Jws;
use DreamFactory\Core\AAuth\Tests\Protocol\Support\Assertions;
use PHPUnit\Framework\TestCase;

final class JwkJwsTest extends TestCase
{
    use Assertions;

    /** RFC 8037 Appendix A.1 key. */
    private const RFC8037 = [
        'kty' => 'OKP', 'crv' => 'Ed25519',
        'd' => 'nWGxne_9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A',
        'x' => '11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo',
        'alg' => 'Ed25519',
    ];

    /** RFC 7515 Appendix A.3 key. */
    private const RFC7515_EC = [
        'kty' => 'EC', 'crv' => 'P-256',
        'x' => 'f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU',
        'y' => 'x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0',
        'd' => 'jpsQnnGQmL-YBIffH1136cspYG6-0iY7X1fCE9-E9LI',
        'alg' => 'ES256',
    ];

    public function testRfc8037Thumbprint(): void
    {
        $this->assertSame('kPrK_qmxVWaYVA9wwBF6Iuo3vVzz7TxHCTwXBygrS4k', Jwk::thumbprint(self::RFC8037));
        $this->assertSame('kPrK_qmxVWaYVA9wwBF6Iuo3vVzz7TxHCTwXBygrS4k', Jwk::thumbprint(Jwk::publicOf(self::RFC8037)));
    }

    /** RFC 8037 Appendix A.4: Ed25519 is deterministic, so the signature must match byte for byte. */
    public function testRfc8037Ed25519Signature(): void
    {
        $input = 'eyJhbGciOiJFZERTQSJ9.RXhhbXBsZSBvZiBFZDI1NTE5IHNpZ25pbmc';
        $expected = 'hgyY0il_MGCjP0JzlnLWG1PPOt7-09PGcvMg3AIbQR6dWbhijcNR4ki4iylGjg5BhVsPt9g7sVvpAr_MuM0KAg';
        $sig = Jws::sign($input, self::RFC8037);
        $this->assertSame($expected, B64::url($sig));
        $this->assertTrue(Jws::verify($input, $sig, Jwk::publicOf(self::RFC8037)));
        $this->assertFalse(Jws::verify($input . 'x', $sig, Jwk::publicOf(self::RFC8037)));
        $this->assertFalse(Jws::verify($input, substr($sig, 1), Jwk::publicOf(self::RFC8037)), 'short signature');
    }

    /** RFC 7515 Appendix A.3: verify the published ES256 signature (raw R||S). */
    public function testRfc7515Es256Verify(): void
    {
        $input = 'eyJhbGciOiJFUzI1NiJ9.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ';
        $sig = B64::urlDecode('DtEhU3ljbEg8L38VWAfUAqOyKAM6-Xx-F4GawxaepmXFCgfTjDxw5djxLa8ISlSApmWQxfKTUJqPP3-Kg6NU1Q');
        $pub = Jwk::publicOf(self::RFC7515_EC);
        $this->assertTrue(Jws::verify($input, $sig, $pub));
        $this->assertFalse(Jws::verify($input . 'x', $sig, $pub));
        $tampered = $sig;
        $tampered[10] = chr(ord($tampered[10]) ^ 1);
        $this->assertFalse(Jws::verify($input, $tampered, $pub));
        // our own ES256 signature with the RFC key verifies too, and is raw (64 bytes)
        $mine = Jws::sign($input, self::RFC7515_EC);
        $this->assertSame(64, strlen($mine));
        $this->assertTrue(Jws::verify($input, $mine, $pub));
        // DER is not accepted where raw is required
        $this->assertFalse(Jws::verify($input, Jws::rawToDer($mine), $pub));
    }

    public function testEs256InteropWithOpensslDer(): void
    {
        $jwk = Jwk::generateEs256();
        $der = '';
        $this->assertTrue(openssl_sign('hello', $der, Jws::p256PrivatePem($jwk), OPENSSL_ALGO_SHA256));
        $raw = Jws::derToRaw($der, 32);
        $this->assertTrue(Jws::verify('hello', $raw, Jwk::publicOf($jwk)));
        $this->assertSame(1, openssl_verify('hello', Jws::rawToDer($raw), Jws::p256PublicPem($jwk), OPENSSL_ALGO_SHA256));
        // many round trips exercise leading-zero / high-bit integer encodings
        for ($i = 0; $i < 40; $i++) {
            $sig = Jws::sign("m{$i}", $jwk);
            $this->assertSame($sig, Jws::derToRaw(Jws::rawToDer($sig), 32));
            $this->assertTrue(Jws::verify("m{$i}", $sig, $jwk));
        }
    }

    public function testGenerateEd25519(): void
    {
        $jwk = Jwk::generateEd25519();
        $this->assertSame(['kty', 'crv', 'x', 'd', 'alg', 'kid'], array_keys($jwk));
        $this->assertSame('Ed25519', $jwk['alg']);
        $this->assertSame(substr(Jwk::thumbprint($jwk), 0, 16), $jwk['kid']);
        $pub = Jwk::publicOf($jwk);
        $this->assertArrayNotHasKey('d', $pub);
        $this->assertSame('Ed25519', Jwk::algOf($pub));
        $sig = Jws::sign('msg', $jwk);
        $this->assertTrue(Jws::verify('msg', $sig, $pub));
        $this->assertFalse(Jws::verify('msg', $sig, Jwk::publicOf(Jwk::generateEd25519())));
        $this->assertTrue(Jwk::sameKey($jwk, $pub));
        $this->assertFalse(Jwk::sameKey($jwk, Jwk::generateEd25519()));
    }

    public function testGenerateEs256(): void
    {
        $jwk = Jwk::generateEs256();
        $pub = Jwk::publicOf($jwk);
        $this->assertSame(['kty', 'crv', 'x', 'y', 'alg', 'kid'], array_keys($pub));
        $this->assertSame('ES256', Jwk::algOf($pub));
        $this->assertSame(43, strlen(Jwk::thumbprint($pub)));
    }

    public function testThumbprintEc(): void
    {
        $expected = B64::url(hash('sha256', '{"crv":"P-256","kty":"EC","x":"f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU","y":"x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0"}', true));
        $this->assertSame($expected, Jwk::thumbprint(self::RFC7515_EC));
    }

    public function testThumbprintErrors(): void
    {
        $this->assertAAuthError('invalid_key', fn () => Jwk::thumbprint(['kty' => 'oct', 'k' => 'x']));
        $this->assertAAuthError('invalid_key', fn () => Jwk::thumbprint(['kty' => 'OKP', 'crv' => 'Ed25519']));
    }

    public function testAssertSupportedPublic(): void
    {
        $pub = Jwk::publicOf(self::RFC8037);
        Jwk::assertSupportedPublic($pub);
        Jwk::assertSupportedPublic(Jwk::publicOf(self::RFC7515_EC));

        $noAlg = $pub;
        unset($noAlg['alg']);
        $e = $this->assertAAuthError('unsupported_algorithm', fn () => Jwk::assertSupportedPublic($noAlg), 401);
        $this->assertSame('Ed25519, ES256', $e->headers['Accept-Signature-Alg']);

        $this->assertAAuthError('unsupported_algorithm', fn () => Jwk::assertSupportedPublic(['alg' => 'EdDSA'] + $pub));
        $this->assertSame('Ed25519', Jwk::algOf(['alg' => 'EdDSA'] + $pub, true), 'EdDSA tolerated only when asked');
        $this->assertAAuthError('unsupported_algorithm', fn () => Jwk::assertSupportedPublic(['alg' => 'none'] + $pub));
        $this->assertAAuthError('unsupported_algorithm', fn () => Jwk::assertSupportedPublic(['alg' => 'HS256'] + $pub));
        $this->assertAAuthError('unsupported_algorithm', fn () => Jwk::assertSupportedPublic(['alg' => 'RS256', 'kty' => 'RSA', 'n' => 'x', 'e' => 'AQAB']));

        $this->assertAAuthError('invalid_key', fn () => Jwk::assertSupportedPublic(['alg' => 'ES256'] + $pub), 401);
        $this->assertAAuthError('invalid_key', fn () => Jwk::assertSupportedPublic(['crv' => 'X25519'] + $pub));
        $this->assertAAuthError('invalid_key', fn () => Jwk::assertSupportedPublic(['x' => 'AAAA'] + $pub));
        $this->assertAAuthError('invalid_key', fn () => Jwk::assertSupportedPublic(['x' => '!!!'] + $pub));
        $ec = Jwk::publicOf(self::RFC7515_EC);
        unset($ec['y']);
        $this->assertAAuthError('invalid_key', fn () => Jwk::assertSupportedPublic($ec));
    }

    public function testSignRejectsMismatchedPrivateKey(): void
    {
        $bad = ['x' => Jwk::generateEd25519()['x']] + self::RFC8037;
        $this->assertAAuthError('invalid_key', fn () => Jws::sign('m', $bad));
        $this->assertAAuthError('invalid_key', fn () => Jws::sign('m', Jwk::publicOf(self::RFC8037)));
    }

    public function testVerifyNeverThrowsOnBadKey(): void
    {
        $this->assertFalse(Jws::verify('m', str_repeat("\0", 64), ['kty' => 'OKP']));
        $this->assertFalse(Jws::verify('m', str_repeat("\0", 64), ['alg' => 'ES256', 'kty' => 'EC', 'crv' => 'P-256', 'x' => B64::url(str_repeat("\0", 32)), 'y' => B64::url(str_repeat("\0", 32))]));
    }
}
