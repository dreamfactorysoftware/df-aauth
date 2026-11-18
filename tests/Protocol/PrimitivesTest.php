<?php

namespace DreamFactory\Core\AAuth\Tests\Protocol;

use DreamFactory\Core\AAuth\Protocol\AAuthError;
use DreamFactory\Core\AAuth\Protocol\B64;
use DreamFactory\Core\AAuth\Protocol\ContentDigest;
use DreamFactory\Core\AAuth\Protocol\Ids;
use DreamFactory\Core\AAuth\Protocol\InteractionCode;
use DreamFactory\Core\AAuth\Protocol\Requirement;
use PHPUnit\Framework\TestCase;

final class PrimitivesTest extends TestCase
{
    public function testB64Url(): void
    {
        $this->assertSame('-_8', B64::url("\xfb\xff"));
        $this->assertSame("\xfb\xff", B64::urlDecode('-_8'));
        $this->assertSame("\xfb\xff", B64::urlDecode('-_8='));
        $this->assertSame('', B64::urlDecode(''));
        foreach (['+/8', 'a b', 'abcde', '-_8==='] as $bad) {
            try {
                B64::urlDecode($bad);
                $this->fail("accepted {$bad}");
            } catch (\InvalidArgumentException) {
                $this->addToAssertionCount(1);
            }
        }
    }

    public function testB64Std(): void
    {
        $this->assertSame('+/8=', B64::std("\xfb\xff"));
        $this->assertSame("\xfb\xff", B64::stdDecode('+/8='));
        $this->assertSame("\xfb\xff", B64::stdDecode('+/8'));
        $this->expectException(\InvalidArgumentException::class);
        B64::stdDecode('-_8=');
    }

    public function testIds(): void
    {
        $a = Ids::random();
        $this->assertMatchesRegularExpression('/^[A-Za-z0-9_-]{22}$/', $a);
        $this->assertNotSame($a, Ids::random());
        $this->assertSame(43, strlen(Ids::random(32)));
    }

    public function testInteractionCode(): void
    {
        for ($i = 0; $i < 50; $i++) {
            $c = InteractionCode::generate();
            $this->assertMatchesRegularExpression('/^[0-9A-HJKMNP-TV-Z]{4}-[0-9A-HJKMNP-TV-Z]{4}$/', $c);
            $this->assertTrue(InteractionCode::isWellFormed($c));
        }
        $this->assertSame('A1B2C3D4', InteractionCode::normalize('a1b2-c3d4'));
        $this->assertSame('1100ABCD', InteractionCode::normalize(' iL0o-abcd '));
        $this->assertSame('', InteractionCode::normalize('ABCD-EFGU'));
        $this->assertFalse(InteractionCode::isWellFormed('ABC-DEF'));
        $this->assertSame('A1B2-C3D4', InteractionCode::format('a1b2c3d4'));
    }

    /** RFC 9530 Appendix D and B.1/B.2 sample values. */
    public function testContentDigestRfc9530Vectors(): void
    {
        $this->assertSame('sha-256=:X48E9qOokqqrvdts8nOJRJN3OWDUoyWxBf7kbu9DBPE=:', ContentDigest::sha256('{"hello": "world"}'));
        $this->assertSame('sha-256=:RK/0qy18MlBSVnWgjwz6lZEWjP/lF5HF9bvEF8FabDg=:', ContentDigest::sha256("{\"hello\": \"world\"}\n"));
        $this->assertSame('sha-256=:47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=:', ContentDigest::sha256(''));

        $this->assertTrue(ContentDigest::verify('sha-256=:X48E9qOokqqrvdts8nOJRJN3OWDUoyWxBf7kbu9DBPE=:', '{"hello": "world"}'));
        // RFC 9421 test-request: sha-512 digest only
        $this->assertTrue(ContentDigest::verify(
            'sha-512=:WZDPaVn/7XgHaAy8pmojAkGWoRx2UFChF41A2svX+TaPm+AbwAgBWnrIiYllu7BNNyealdVLvRwEmTHWXvJwew==:',
            '{"hello": "world"}'
        ));
        // both, and an unknown algorithm is ignored
        $this->assertTrue(ContentDigest::verify(
            'md5=:Sd/dVLAcvNLSq16eXua5uQ==:, sha-256=:X48E9qOokqqrvdts8nOJRJN3OWDUoyWxBf7kbu9DBPE=:',
            '{"hello": "world"}'
        ));
    }

    public function testContentDigestNegative(): void
    {
        $body = '{"hello": "world"}';
        $this->assertFalse(ContentDigest::verify(ContentDigest::sha256($body), $body . ' '));
        $this->assertFalse(ContentDigest::verify('md5=:Sd/dVLAcvNLSq16eXua5uQ==:', $body), 'no supported digest');
        $this->assertFalse(ContentDigest::verify('sha-256=X48E9q', $body), 'not a byte sequence');
        $this->assertFalse(ContentDigest::verify('sha-256=:not base64!:', $body));
        $this->assertFalse(ContentDigest::verify('', $body));
        // one good, one bad supported digest
        $this->assertFalse(ContentDigest::verify(
            ContentDigest::sha256($body) . ', sha-512=:WZDPaVn/7XgHaAy8pmojAkGWoRx2UFChF41A2svX+TaPm+AbwAgBWnrIiYllu7BNNyealdVLvRwEmTHWXvJwew==:',
            $body . 'x'
        ));
    }

    public function testRequirementHeader(): void
    {
        $this->assertSame('requirement=person-token', Requirement::header('person-token'));
        $this->assertSame('requirement=agent-token', Requirement::header('agent-token'));
        $this->assertSame(
            'requirement=auth-token; resource-token="eyJ.a.b"',
            Requirement::header('auth-token', ['resource-token' => 'eyJ.a.b'])
        );
        $this->assertSame(
            'requirement=interaction; url="https://ps.example/interact"; code="A1B2-C3D4"',
            Requirement::header('interaction', ['url' => 'https://ps.example/interact', 'code' => 'A1B2-C3D4'])
        );
        $this->assertSame('requirement=x; q="a\\"b\\\\c"', Requirement::header('x', ['q' => 'a"b\\c']));
    }

    public function testRequirementParse(): void
    {
        $this->assertSame(['requirement' => 'person-token'], Requirement::parse('requirement=person-token'));
        $this->assertSame(
            ['requirement' => 'auth-token', 'resource-token' => 'eyJ.a.b'],
            Requirement::parse('requirement=auth-token; resource-token="eyJ.a.b"')
        );
        $this->assertSame(
            ['requirement' => 'interaction', 'url' => 'https://ps.example/interact', 'code' => 'A1B2-C3D4'],
            Requirement::parse('requirement=interaction;url="https://ps.example/interact";code="A1B2-C3D4"')
        );
        $round = Requirement::header('x', ['q' => 'a"b\\c']);
        $this->assertSame('a"b\\c', Requirement::parse($round)['q']);
        $this->assertSame([], Requirement::parse(''));
        $this->assertSame([], Requirement::parse('requirement="quoted-string-not-token"'));
        $this->assertSame([], Requirement::parse('garbage;;'));
    }

    public function testAAuthErrorShapes(): void
    {
        $e = AAuthError::signature('invalid_signature', 'bad');
        $this->assertSame(401, $e->status);
        $this->assertSame(['Signature-Error' => 'error=invalid_signature'], $e->headers);
        $this->assertSame(['type' => 'urn:ietf:params:sig-error:invalid_signature', 'error' => 'invalid_signature', 'detail' => 'bad'], $e->toProblem());

        $e = AAuthError::signature('unsupported_algorithm', 'x');
        $this->assertSame('Ed25519, ES256', $e->headers['Accept-Signature-Alg']);
        $e = AAuthError::signature('unsupported_scheme', 'x');
        $this->assertSame('jwt', $e->headers['Accept-Signature-Scheme']);

        $e = AAuthError::invalidInput(['@method', '@authority', '@path', 'signature-key', 'content-digest'], 'missing');
        $this->assertSame(401, $e->status);
        $this->assertSame('error=invalid_input, required_input=("@method" "@authority" "@path" "signature-key" "content-digest")', $e->headers['Signature-Error']);

        $e = new AAuthError(403, 'insufficient_scope', 'No scope');
        $this->assertFalse($e->isSignatureError());
        $this->assertSame(['error' => 'insufficient_scope', 'detail' => 'No scope'], $e->toProblem());
        $this->assertSame('No scope', $e->getMessage());
    }
}
