<?php

namespace DreamFactory\Core\AAuth\Tests\Protocol;

use DreamFactory\Core\AAuth\Protocol\SignatureKey;
use DreamFactory\Core\AAuth\Tests\Protocol\Support\Assertions;
use PHPUnit\Framework\TestCase;

final class SignatureKeyTest extends TestCase
{
    use Assertions;

    private const JWT = 'eyJhbGciOiJFZDI1NTE5In0.eyJpc3MiOiJ4In0.c2ln';

    public function testStrictWireForm(): void
    {
        $this->assertSame('sig=jwt;jwt="' . self::JWT . '"', SignatureKey::jwt('sig', self::JWT));
    }

    public function testParse(): void
    {
        $p = SignatureKey::parse('sig=jwt;jwt="' . self::JWT . '"');
        $this->assertSame(['label' => 'sig', 'scheme' => 'jwt', 'jwt' => self::JWT, 'params' => ['jwt' => self::JWT]], $p);
        // spaces after ";" and the bare-boolean cache param are fine
        $p = SignatureKey::parse('sig=jwt; jwt="' . self::JWT . '";cache');
        $this->assertSame(self::JWT, $p['jwt']);
        $this->assertTrue($p['params']['cache']);
        // any label when it is the only member; "sig" preferred otherwise
        $this->assertSame('agent', SignatureKey::parse('agent=jwt;jwt="' . self::JWT . '"')['label']);
        $this->assertSame('sig', SignatureKey::parse('x=hwk;kty="OKP", sig=jwt;jwt="' . self::JWT . '"')['label']);
        $this->assertSame('x', SignatureKey::parse('x=jwt;jwt="a.b.c", sig=hwk', 'x')['label']);
    }

    public function testUnsupportedSchemes(): void
    {
        foreach ([
            'sig=hwk;kty="OKP";crv="Ed25519";x="abc";alg="Ed25519"',
            'sig=jwks_uri;id="https://ps.example";dwk="aauth-person.json";kid="k"',
            'sig=x509;x5u="https://x"',
            'sig=bogus',
        ] as $h) {
            $e = $this->assertAAuthError('unsupported_scheme', fn () => SignatureKey::parse($h), 401);
            $this->assertSame('jwt', $e->headers['Accept-Signature-Scheme']);
            $this->assertSame('error=unsupported_scheme', $e->headers['Signature-Error']);
        }
    }

    public function testMalformed(): void
    {
        $this->assertAAuthError('invalid_signature', fn () => SignatureKey::parse('sig=jwt;jwt="unterminated'));
        $this->assertAAuthError('invalid_signature', fn () => SignatureKey::parse(''));
        $this->assertAAuthError('invalid_signature', fn () => SignatureKey::parse('a=jwt;jwt="x", b=jwt;jwt="y"'));
        $this->assertAAuthError('invalid_signature', fn () => SignatureKey::parse('sig="jwt";jwt="x"'));
        $this->assertAAuthError('invalid_signature', fn () => SignatureKey::parse('sig=(jwt)'));
        $this->assertAAuthError('invalid_key', fn () => SignatureKey::parse('sig=jwt'));
        $this->assertAAuthError('invalid_key', fn () => SignatureKey::parse('sig=jwt;jwt=token'));
        $this->assertAAuthError('invalid_key', fn () => SignatureKey::parse('sig=jwt;jwt=""'));
    }
}
