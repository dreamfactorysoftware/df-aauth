<?php

namespace DreamFactory\Core\AAuth\Tests\Protocol;

use DreamFactory\Core\AAuth\Protocol\B64;
use DreamFactory\Core\AAuth\Protocol\Jwk;
use DreamFactory\Core\AAuth\Protocol\Jws;
use DreamFactory\Core\AAuth\Protocol\Jwt;
use DreamFactory\Core\AAuth\Tests\Protocol\Support\Assertions;
use DreamFactory\Core\AAuth\Tests\Protocol\Support\StaticResolver;
use PHPUnit\Framework\TestCase;

final class JwtTest extends TestCase
{
    use Assertions;

    private const AP = 'https://agent.example';
    private const PS = 'https://ps.example';
    private const NOW = 1730217600;

    private array $apKey;
    private array $agentKey;

    protected function setUp(): void
    {
        $this->apKey = Jwk::generateEd25519();
        $this->agentKey = Jwk::generateEd25519();
    }

    private function agentPayload(array $over = []): array
    {
        return $over + [
            'iss' => self::AP,
            'dwk' => 'aauth-agent.json',
            'sub' => 'aauth:a1@agent.example',
            'cnf' => ['jwk' => Jwk::publicOf($this->agentKey)],
            'ps' => self::PS,
            'jti' => 'j1',
            'iat' => self::NOW,
            'exp' => self::NOW + 3600,
        ];
    }

    /** Assemble a JWT with an arbitrary header, signed by $key. */
    private function rawJwt(array $header, array $payload, array $key): string
    {
        $input = B64::url(json_encode($header)) . '.' . B64::url(json_encode($payload, JSON_UNESCAPED_SLASHES));
        return $input . '.' . B64::url(Jws::sign($input, $key));
    }

    public function testRoundTrip(): void
    {
        $jwt = Jwt::sign('aa-agent+jwt', $this->agentPayload(), $this->apKey);
        $d = Jwt::decode($jwt);
        $this->assertSame(['alg' => 'Ed25519', 'typ' => 'aa-agent+jwt', 'kid' => $this->apKey['kid']], $d['header']);

        $r = StaticResolver::single(self::AP, $this->apKey, ['name' => 'Agent']);
        $v = Jwt::verify($jwt, 'aa-agent+jwt', $r, self::NOW + 10);
        $this->assertSame('aauth:a1@agent.example', $v['payload']['sub']);
        $this->assertSame('Agent', $v['meta']['name']);
        $this->assertTrue(Jwk::sameKey($this->apKey, $v['jwk']));
        $this->assertTrue(Jwk::sameKey($this->agentKey, $v['cnf_jwk']));
        $this->assertSame(1, $r->calls);
    }

    public function testEs256Jwt(): void
    {
        $ec = Jwk::generateEs256();
        $jwt = Jwt::sign('aa-agent+jwt', $this->agentPayload(), $ec);
        $this->assertSame('ES256', Jwt::decode($jwt)['header']['alg']);
        $v = Jwt::verify($jwt, 'aa-agent+jwt', StaticResolver::single(self::AP, $ec), self::NOW);
        $this->assertSame('j1', $v['payload']['jti']);
    }

    public function testPolymorphicEdDsaIsRejected(): void
    {
        $jwt = $this->rawJwt(['alg' => 'EdDSA', 'typ' => 'aa-agent+jwt', 'kid' => $this->apKey['kid']], $this->agentPayload(), $this->apKey);
        $this->assertAAuthError('unsupported_algorithm', fn () => Jwt::verify($jwt, 'aa-agent+jwt', StaticResolver::single(self::AP, $this->apKey), self::NOW), 401);
    }

    public function testTypMismatchCheckedFirst(): void
    {
        $jwt = Jwt::sign('aa-person+jwt', $this->agentPayload(['dwk' => 'aauth-person.json']), $this->apKey);
        $r = StaticResolver::single(self::AP, $this->apKey);
        $this->assertAAuthError('invalid_jwt', fn () => Jwt::verify($jwt, 'aa-auth+jwt', $r, self::NOW), 401);
        $this->assertSame(0, $r->calls, 'typ is checked before any key resolution');
    }

    public function testAlgNoneAndHsRejected(): void
    {
        $p = B64::url(json_encode($this->agentPayload(), JSON_UNESCAPED_SLASHES));
        $none = B64::url('{"alg":"none","typ":"aa-agent+jwt"}') . '.' . $p . '.AA';
        $r = StaticResolver::single(self::AP, $this->apKey);
        $e = $this->assertAAuthError('unsupported_algorithm', fn () => Jwt::verify($none, 'aa-agent+jwt', $r, self::NOW));
        $this->assertSame('Ed25519, ES256', $e->headers['Accept-Signature-Alg']);
        $hs = B64::url('{"alg":"HS256","typ":"aa-agent+jwt"}') . '.' . $p . '.' . B64::url(hash_hmac('sha256', 'x', 'k', true));
        $this->assertAAuthError('unsupported_algorithm', fn () => Jwt::verify($hs, 'aa-agent+jwt', $r, self::NOW));
        $noAlg = B64::url('{"typ":"aa-agent+jwt"}') . '.' . $p . '.AA';
        $this->assertAAuthError('unsupported_algorithm', fn () => Jwt::verify($noAlg, 'aa-agent+jwt', $r, self::NOW));
        // unsigned "none" with an empty signature part is just malformed
        $this->assertAAuthError('invalid_jwt', fn () => Jwt::verify(B64::url('{"alg":"none","typ":"aa-agent+jwt"}') . '.' . $p . '.', 'aa-agent+jwt', $r, self::NOW));
        $this->assertSame(0, $r->calls);
    }

    public function testAlgMustMatchKey(): void
    {
        $jwt = $this->rawJwt(['alg' => 'ES256', 'typ' => 'aa-agent+jwt', 'kid' => $this->apKey['kid']], $this->agentPayload(), $this->apKey);
        $this->assertAAuthError('invalid_jwt', fn () => Jwt::verify($jwt, 'aa-agent+jwt', StaticResolver::single(self::AP, $this->apKey), self::NOW));
    }

    public function testDwkRules(): void
    {
        $r = StaticResolver::single(self::AP, $this->apKey);
        $jwt = Jwt::sign('aa-agent+jwt', $this->agentPayload(['dwk' => 'aauth-person.json']), $this->apKey);
        $this->assertAAuthError('invalid_jwt', fn () => Jwt::verify($jwt, 'aa-agent+jwt', $r, self::NOW));
        $noDwk = $this->agentPayload();
        unset($noDwk['dwk']);
        $this->assertAAuthError('invalid_jwt', fn () => Jwt::verify(Jwt::sign('aa-agent+jwt', $noDwk, $this->apKey), 'aa-agent+jwt', $r, self::NOW));

        // aa-auth+jwt: person servers only. DreamFactory federates with no access server, so an
        // AS-style token (dwk aauth-access.json) is refused before any key is resolved.
        $auth = Jwt::sign('aa-auth+jwt', $this->agentPayload(['dwk' => 'aauth-person.json', 'aud' => 'https://r.example']), $this->apKey);
        $this->assertSame('aauth-person.json', Jwt::verify($auth, 'aa-auth+jwt', $r, self::NOW)['payload']['dwk']);
        $as = Jwt::sign('aa-auth+jwt', $this->agentPayload(['dwk' => 'aauth-access.json', 'aud' => 'https://r.example']), $this->apKey);
        $calls = $r->calls;
        $this->assertAAuthError('invalid_jwt', fn () => Jwt::verify($as, 'aa-auth+jwt', $r, self::NOW), 401);
        $this->assertSame($calls, $r->calls, 'an AS dwk is refused before discovery');
        $this->assertSame(['aauth-person.json'], Jwt::allowedDwk('aa-auth+jwt'));
        $this->assertSame(['aauth-person.json'], Jwt::allowedDwk('aa-person+jwt'));
        $this->assertSame([], Jwt::allowedDwk('aa-other+jwt'));
    }

    public function testExpiryAndIat(): void
    {
        $r = StaticResolver::single(self::AP, $this->apKey);
        $jwt = Jwt::sign('aa-agent+jwt', $this->agentPayload(), $this->apKey);
        $this->assertAAuthError('expired_jwt', fn () => Jwt::verify($jwt, 'aa-agent+jwt', $r, self::NOW + 3600), 401);
        Jwt::verify($jwt, 'aa-agent+jwt', $r, self::NOW + 3599);

        $future = Jwt::sign('aa-agent+jwt', $this->agentPayload(['iat' => self::NOW + 61]), $this->apKey);
        $this->assertAAuthError('clock_skew', fn () => Jwt::verify($future, 'aa-agent+jwt', $r, self::NOW));
        $ok = Jwt::sign('aa-agent+jwt', $this->agentPayload(['iat' => self::NOW + 60]), $this->apKey);
        Jwt::verify($ok, 'aa-agent+jwt', $r, self::NOW);

        $noIat = $this->agentPayload();
        unset($noIat['iat']);
        $this->assertAAuthError('invalid_jwt', fn () => Jwt::verify(Jwt::sign('aa-agent+jwt', $noIat, $this->apKey), 'aa-agent+jwt', $r, self::NOW));
        $strExp = Jwt::sign('aa-agent+jwt', $this->agentPayload(['exp' => (string) (self::NOW + 100)]), $this->apKey);
        $this->assertAAuthError('invalid_jwt', fn () => Jwt::verify($strExp, 'aa-agent+jwt', $r, self::NOW));
    }

    public function testPersonAndAuthLifetimeCappedAtOneHour(): void
    {
        $r = StaticResolver::single(self::PS, $this->apKey);
        $p = $this->agentPayload(['iss' => self::PS, 'dwk' => 'aauth-person.json', 'aud' => 'https://r.example', 'exp' => self::NOW + 3601]);
        $this->assertAAuthError('invalid_jwt', fn () => Jwt::verify(Jwt::sign('aa-person+jwt', $p, $this->apKey), 'aa-person+jwt', $r, self::NOW));
        $p['exp'] = self::NOW + 3600;
        Jwt::verify(Jwt::sign('aa-person+jwt', $p, $this->apKey), 'aa-person+jwt', $r, self::NOW);
        // agent tokens may be longer (SHOULD NOT exceed 24h is not enforced)
        Jwt::verify(Jwt::sign('aa-agent+jwt', $this->agentPayload(['exp' => self::NOW + 86400]), $this->apKey), 'aa-agent+jwt', StaticResolver::single(self::AP, $this->apKey), self::NOW);
    }

    public function testCnfRequiredForBoundTypes(): void
    {
        $r = StaticResolver::single(self::AP, $this->apKey);
        $p = $this->agentPayload();
        unset($p['cnf']);
        $this->assertAAuthError('invalid_jwt', fn () => Jwt::verify(Jwt::sign('aa-agent+jwt', $p, $this->apKey), 'aa-agent+jwt', $r, self::NOW));
        $p['cnf'] = ['jwk' => $this->agentKey];
        $this->assertAAuthError('invalid_key', fn () => Jwt::verify(Jwt::sign('aa-agent+jwt', $p, $this->apKey), 'aa-agent+jwt', $r, self::NOW), 401);
        $noAlg = Jwk::publicOf($this->agentKey);
        unset($noAlg['alg']);
        $p['cnf'] = ['jwk' => $noAlg];
        $this->assertAAuthError('unsupported_algorithm', fn () => Jwt::verify(Jwt::sign('aa-agent+jwt', $p, $this->apKey), 'aa-agent+jwt', $r, self::NOW));
        $p['cnf'] = ['jwk' => ['alg' => 'EdDSA'] + Jwk::publicOf($this->agentKey)];
        $this->assertAAuthError('unsupported_algorithm', fn () => Jwt::verify(Jwt::sign('aa-agent+jwt', $p, $this->apKey), 'aa-agent+jwt', $r, self::NOW));

        // resource tokens carry no cnf
        $rt = Jwt::sign('aa-resource+jwt', ['iss' => self::AP, 'dwk' => 'aauth-resource.json', 'agent_jkt' => 'x', 'iat' => self::NOW, 'exp' => self::NOW + 300], $this->apKey);
        $this->assertNull(Jwt::verify($rt, 'aa-resource+jwt', $r, self::NOW)['cnf_jwk']);
    }

    public function testTamperedPayloadAndSignature(): void
    {
        $r = StaticResolver::single(self::AP, $this->apKey);
        $jwt = Jwt::sign('aa-agent+jwt', $this->agentPayload(), $this->apKey);
        [$h, , $s] = explode('.', $jwt);
        $evil = $h . '.' . B64::url(json_encode($this->agentPayload(['sub' => 'aauth:evil@agent.example']), JSON_UNESCAPED_SLASHES)) . '.' . $s;
        $this->assertAAuthError('invalid_jwt', fn () => Jwt::verify($evil, 'aa-agent+jwt', $r, self::NOW));
        $other = Jwk::generateEd25519();
        $other['kid'] = $this->apKey['kid'];
        $forged = Jwt::sign('aa-agent+jwt', $this->agentPayload(), $other);
        $this->assertAAuthError('invalid_jwt', fn () => Jwt::verify($forged, 'aa-agent+jwt', $r, self::NOW));
        $this->assertSame(2, $r->freshCalls, 'one refresh attempt per verification before invalid_jwt');
    }

    public function testRefreshOnceAfterRotation(): void
    {
        $new = Jwk::generateEd25519();
        $new['kid'] = $this->apKey['kid']; // same kid, rotated material
        $r = StaticResolver::single(self::AP, $this->apKey);
        $r->freshIssuers = [self::AP => ['keys' => [Jwk::publicOf($new)], 'meta' => ['issuer' => self::AP]]];
        $jwt = Jwt::sign('aa-agent+jwt', $this->agentPayload(), $new);
        $v = Jwt::verify($jwt, 'aa-agent+jwt', $r, self::NOW);
        $this->assertTrue(Jwk::sameKey($new, $v['jwk']));
        $this->assertSame(1, $r->freshCalls);
    }

    public function testUnknownKidPropagates(): void
    {
        $k = $this->apKey;
        $k['kid'] = 'other';
        $jwt = Jwt::sign('aa-agent+jwt', $this->agentPayload(), $k);
        $this->assertAAuthError('unknown_key', fn () => Jwt::verify($jwt, 'aa-agent+jwt', StaticResolver::single(self::AP, $this->apKey), self::NOW));
    }

    public function testMalformed(): void
    {
        $r = StaticResolver::single(self::AP, $this->apKey);
        foreach (['', 'a.b', 'a.b.c.d', '!!.e30.AA', B64::url('[1]') . '.' . B64::url('{}') . '.AA', B64::url('{"alg":"Ed25519"}') . '.' . B64::url('"str"') . '.AA', B64::url('{') . '.e30.AA'] as $bad) {
            $this->assertAAuthError('invalid_jwt', fn () => Jwt::verify($bad, 'aa-agent+jwt', $r, self::NOW));
        }
        $noIss = $this->agentPayload();
        unset($noIss['iss']);
        $this->assertAAuthError('invalid_jwt', fn () => Jwt::verify(Jwt::sign('aa-agent+jwt', $noIss, $this->apKey), 'aa-agent+jwt', $r, self::NOW));
    }
}
