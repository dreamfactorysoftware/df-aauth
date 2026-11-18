<?php

namespace DreamFactory\Core\AAuth\Tests\Protocol;

use DreamFactory\Core\AAuth\Protocol\HttpRequestParts;
use DreamFactory\Core\AAuth\Protocol\HttpSignature;
use DreamFactory\Core\AAuth\Protocol\Ids;
use DreamFactory\Core\AAuth\Protocol\Jwk;
use DreamFactory\Core\AAuth\Protocol\Jwt;
use DreamFactory\Core\AAuth\Protocol\Requirement;
use DreamFactory\Core\AAuth\Protocol\SignatureKey;
use DreamFactory\Core\AAuth\Tests\Protocol\Support\Assertions;
use DreamFactory\Core\AAuth\Tests\Protocol\Support\StaticResolver;
use PHPUnit\Framework\TestCase;

/** The library pieces composed the way the DreamFactory middleware / PS will use them. */
final class ThreePartyFlowTest extends TestCase
{
    use Assertions;

    private const AP = 'https://agent.example';
    private const PS = 'https://ps.example';
    private const RS = 'https://df.example';
    private const NOW = 1730217600;

    private array $apKey;
    private array $psKey;
    private array $rsKey;
    private array $agentKey;
    private StaticResolver $keys;

    protected function setUp(): void
    {
        $this->apKey = Jwk::generateEd25519();
        $this->psKey = Jwk::generateEd25519();
        $this->rsKey = Jwk::generateEs256(); // mix algorithms on purpose
        $this->agentKey = Jwk::generateEd25519();
        $this->keys = new StaticResolver([
            self::AP => ['keys' => [Jwk::publicOf($this->apKey)], 'meta' => ['issuer' => self::AP, 'name' => 'Acme Reports']],
            self::PS => ['keys' => [Jwk::publicOf($this->psKey)], 'meta' => ['issuer' => self::PS]],
            self::RS => ['keys' => [Jwk::publicOf($this->rsKey)], 'meta' => ['issuer' => self::RS]],
        ]);
    }

    /** What the resource middleware does with an incoming signed request. */
    private function resourceVerify(string $method, string $url, array $signed, string $body, array $acceptTyps): array
    {
        $req = HttpRequestParts::fromUrl($method, $url, array_change_key_case($signed, CASE_LOWER), $body);
        $sk = SignatureKey::parse($req->header('signature-key') ?? '');
        $typ = Jwt::decode($sk['jwt'])['header']['typ'] ?? '';
        if (!in_array($typ, $acceptTyps, true)) {
            throw \DreamFactory\Core\AAuth\Protocol\AAuthError::signature('invalid_jwt', "Unexpected token type {$typ}");
        }
        $tok = Jwt::verify($sk['jwt'], $typ, $this->keys, self::NOW);
        $sig = HttpSignature::verify($req, $tok['cnf_jwk'], self::NOW, 60, true);
        return ['typ' => $typ, 'token' => $tok, 'sig' => $sig, 'jkt' => Jwk::thumbprint($tok['cnf_jwk'])];
    }

    public function testFullFlow(): void
    {
        $agentJwk = Jwk::publicOf($this->agentKey);
        $agentToken = Jwt::sign('aa-agent+jwt', [
            'iss' => self::AP, 'dwk' => 'aauth-agent.json', 'sub' => 'aauth:reports@agent.example',
            'cnf' => ['jwk' => $agentJwk], 'ps' => self::PS, 'jti' => Ids::random(), 'iat' => self::NOW, 'exp' => self::NOW + 3600,
        ], $this->apKey);
        $url = self::RS . '/api/v2/sales/_table/orders?limit=5';

        // 1. agent token at the resource => person-token requirement
        $h = HttpSignature::sign('GET', $url, $agentToken, $this->agentKey, extra: ['@query'], now: self::NOW);
        $r = $this->resourceVerify('GET', $url, $h, '', Jwt::CNF_TYPES);
        $this->assertSame('aa-agent+jwt', $r['typ']);
        $this->assertSame('Acme Reports', $r['token']['meta']['name']);
        $this->assertSame('requirement=person-token', Requirement::header('person-token'));

        // 2. PS: request signed by the agent token, with a body
        $body = json_encode(['resource' => self::RS, 'capabilities' => ['interaction']], JSON_UNESCAPED_SLASHES);
        $h = HttpSignature::sign('POST', self::PS . '/person', $agentToken, $this->agentKey, [], $body, [], self::NOW);
        $atPs = $this->resourceVerify('POST', self::PS . '/person', $h, $body, ['aa-agent+jwt']);
        $personToken = Jwt::sign('aa-person+jwt', [
            'iss' => self::PS, 'dwk' => 'aauth-person.json', 'aud' => self::RS, 'sub' => 'pairwise-123',
            'cnf' => ['jwk' => $atPs['token']['cnf_jwk']], 'jti' => 'pt-1', 'iat' => self::NOW, 'exp' => self::NOW + 3600,
        ], $this->psKey);

        // 3. person token at the resource => resource token challenge
        $h = HttpSignature::sign('GET', $url, $personToken, $this->agentKey, extra: ['@query'], now: self::NOW);
        $r = $this->resourceVerify('GET', $url, $h, '', Jwt::CNF_TYPES);
        $this->assertSame('aa-person+jwt', $r['typ']);
        $this->assertSame(self::RS, $r['token']['payload']['aud']);
        $rt = Jwt::sign('aa-resource+jwt', [
            'iss' => self::RS, 'dwk' => 'aauth-resource.json', 'aud' => self::PS, 'ps' => self::PS,
            'sub' => $r['token']['payload']['sub'], 'presented_jti' => $r['token']['payload']['jti'],
            'agent_jkt' => $r['jkt'], 'scope' => 'sales.read', 'jti' => 'rt-1', 'iat' => self::NOW, 'exp' => self::NOW + 300,
        ], $this->rsKey);
        $challenge = Requirement::header('auth-token', ['resource-token' => $rt]);
        $this->assertSame($rt, Requirement::parse($challenge)['resource-token']);

        // 4. agent checks the resource token (§6.7.3)
        $vrt = Jwt::verify($rt, 'aa-resource+jwt', $this->keys, self::NOW);
        $this->assertSame(Jwk::thumbprint($agentJwk), $vrt['payload']['agent_jkt']);
        $this->assertNull($vrt['cnf_jwk']);

        // 5. PS checks resource token + presented token (§6.7.2) and issues the auth token
        $ptAtPs = Jwt::verify($personToken, 'aa-person+jwt', $this->keys, self::NOW);
        $this->assertSame($vrt['payload']['iss'], $ptAtPs['payload']['aud']);
        $this->assertSame($vrt['payload']['presented_jti'], $ptAtPs['payload']['jti']);
        $this->assertSame($vrt['payload']['agent_jkt'], Jwk::thumbprint($ptAtPs['cnf_jwk']));
        $authToken = Jwt::sign('aa-auth+jwt', [
            'iss' => self::PS, 'dwk' => 'aauth-person.json', 'aud' => self::RS, 'ps' => self::PS,
            'sub' => $vrt['payload']['sub'], 'cnf' => ['jwk' => $agentJwk], 'scope' => 'sales.read',
            'jti' => 'at-1', 'iat' => self::NOW, 'exp' => self::NOW + 3600,
        ], $this->psKey);

        // 6. auth token at the resource
        $h = HttpSignature::sign('GET', $url, $authToken, $this->agentKey, extra: ['@query'], now: self::NOW);
        $r = $this->resourceVerify('GET', $url, $h, '', ['aa-auth+jwt']);
        $this->assertSame('sales.read', $r['token']['payload']['scope']);

        // a person token never stands in for an auth token (typ checked first)
        $h = HttpSignature::sign('GET', $url, $personToken, $this->agentKey, extra: ['@query'], now: self::NOW);
        $this->assertAAuthError('invalid_jwt', fn () => $this->resourceVerify('GET', $url, $h, '', ['aa-auth+jwt']));
        $this->assertAAuthError('invalid_jwt', fn () => Jwt::verify($personToken, 'aa-auth+jwt', $this->keys, self::NOW));

        // a different agent key cannot use the stolen auth token
        $thief = Jwk::generateEd25519();
        $h = HttpSignature::sign('GET', $url, $authToken, $thief, extra: ['@query'], now: self::NOW);
        $this->assertAAuthError('invalid_signature', fn () => $this->resourceVerify('GET', $url, $h, '', ['aa-auth+jwt']));
    }
}
