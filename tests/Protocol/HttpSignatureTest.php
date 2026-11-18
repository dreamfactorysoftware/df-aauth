<?php

namespace DreamFactory\Core\AAuth\Tests\Protocol;

use DreamFactory\Core\AAuth\Protocol\B64;
use DreamFactory\Core\AAuth\Protocol\ContentDigest;
use DreamFactory\Core\AAuth\Protocol\HttpRequestParts;
use DreamFactory\Core\AAuth\Protocol\HttpSignature;
use DreamFactory\Core\AAuth\Protocol\Jwk;
use DreamFactory\Core\AAuth\Protocol\Jws;
use DreamFactory\Core\AAuth\Protocol\SignatureKey;
use DreamFactory\Core\AAuth\Protocol\StructuredFields;
use DreamFactory\Core\AAuth\Tests\Protocol\Support\Assertions;
use PHPUnit\Framework\TestCase;

final class HttpSignatureTest extends TestCase
{
    use Assertions;

    private const NOW = 1730217600;
    private const JWT = 'eyJhbGciOiJFZDI1NTE5IiwidHlwIjoiYWEtYWdlbnQrand0In0.eyJpc3MiOiJ4In0.c2ln';

    /** RFC 9421 Appendix B.1.4 test-key-ed25519 (alg added, as AAuth requires). */
    private const RFC_KEY = [
        'kty' => 'OKP', 'crv' => 'Ed25519', 'kid' => 'test-key-ed25519',
        'd' => 'n4Ni-HpISpVObnQMW0wOhCKROaIKqKtW_2ZYb2p9KcU',
        'x' => 'JrQLj5P_89iXES9-vFgrIy29clF9CC_oPPsw3c5D0bs',
        'alg' => 'Ed25519',
    ];

    private array $key;

    protected function setUp(): void
    {
        $this->key = Jwk::generateEd25519();
    }

    /** Request parts as the server would see them after the client sent $signed headers. */
    private function received(string $method, string $url, array $signed, string $body = '', array $other = []): HttpRequestParts
    {
        return HttpRequestParts::fromUrl($method, $url, array_change_key_case($signed + $other, CASE_LOWER), $body);
    }

    /** Sign with arbitrary components and parameter text (for negative cases). */
    private function signCustom(string $method, string $url, array $components, string $paramTail, array $headers = [], string $body = '', ?array $key = null): array
    {
        $h = array_change_key_case($headers, CASE_LOWER);
        $h['signature-key'] ??= SignatureKey::jwt('sig', self::JWT);
        $params = StructuredFields::serializeInnerList($components) . $paramTail;
        $parts = HttpRequestParts::fromUrl($method, $url, $h, $body);
        $sig = Jws::sign(HttpSignature::base($components, $params, $parts), $key ?? $this->key);
        return $h + ['signature-input' => 'sig=' . $params, 'signature' => 'sig=:' . base64_encode($sig) . ':'];
    }

    // ------------------------------------------------------------- RFC vectors

    public function testRfc9421B26Ed25519(): void
    {
        $sigInput = 'sig-b26=("date" "@method" "@path" "@authority" "content-type" "content-length");created=1618884473;keyid="test-key-ed25519"';
        $expectedSig = 'wqcAqbmYJ2ji2glfAMaRy4gruYYnx2nEFN2HN6jrnDnQCK1u02Gb04v9EDgwUPiu4A0w6vuQv5lIp5WPpBKRCw==';
        $req = new HttpRequestParts('POST', 'example.com', '/foo', 'param=Value&Pet=dog', [
            'Host' => 'example.com',
            'Date' => 'Tue, 20 Apr 2021 02:07:55 GMT',
            'Content-Type' => 'application/json',
            'Content-Digest' => 'sha-512=:WZDPaVn/7XgHaAy8pmojAkGWoRx2UFChF41A2svX+TaPm+AbwAgBWnrIiYllu7BNNyealdVLvRwEmTHWXvJwew==:',
            'Content-Length' => '18',
        ], '{"hello": "world"}');

        $member = StructuredFields::parseDictionary($sigInput)['sig-b26'];
        $params = StructuredFields::serializeMember($member);
        $this->assertSame(substr($sigInput, strlen('sig-b26=')), $params, 'canonical re-serialization');
        $components = array_column($member['items'], 'value');

        $base = HttpSignature::base($components, $params, $req);
        $this->assertSame(implode("\n", [
            '"date": Tue, 20 Apr 2021 02:07:55 GMT',
            '"@method": POST',
            '"@path": /foo',
            '"@authority": example.com',
            '"content-type": application/json',
            '"content-length": 18',
            '"@signature-params": ("date" "@method" "@path" "@authority" "content-type" "content-length");created=1618884473;keyid="test-key-ed25519"',
        ]), $base);

        $this->assertSame($expectedSig, base64_encode(Jws::sign($base, self::RFC_KEY)));
        $this->assertTrue(Jws::verify($base, base64_decode($expectedSig), Jwk::publicOf(self::RFC_KEY)));
        $this->assertTrue(ContentDigest::verify($req->header('content-digest'), $req->body));

        // The same message fails the AAuth profile: signature-key is not covered.
        $aauth = new HttpRequestParts($req->method, $req->authority, $req->path, $req->query, $req->headers + [
            'signature-input' => $sigInput,
            'signature' => 'sig-b26=:' . $expectedSig . ':',
            'signature-key' => SignatureKey::jwt('sig-b26', self::JWT),
        ], $req->body);
        $e = $this->assertAAuthError('invalid_input', fn () => HttpSignature::verify($aauth, Jwk::publicOf(self::RFC_KEY), 1618884473));
        $this->assertStringContainsString('required_input=("@method" "@authority" "@path" "signature-key" "content-type" "content-digest")', $e->headers['Signature-Error']);
    }

    // --------------------------------------------------------------- round trips

    public function testSignWireFormGet(): void
    {
        $h = HttpSignature::sign('get', 'https://Resource.Example/api/v2/x', self::JWT, $this->key, now: self::NOW);
        $this->assertSame(['Signature-Key', 'Signature-Input', 'Signature'], array_keys($h));
        $this->assertSame('sig=jwt;jwt="' . self::JWT . '"', $h['Signature-Key']);
        $this->assertSame('sig=("@method" "@authority" "@path" "signature-key");created=' . self::NOW, $h['Signature-Input']);
        $this->assertMatchesRegularExpression('/^sig=:[A-Za-z0-9+\/=]+:$/', $h['Signature']);

        $v = HttpSignature::verify($this->received('GET', 'https://resource.example/api/v2/x', $h), Jwk::publicOf($this->key), self::NOW + 5);
        $this->assertSame(['@method', '@authority', '@path', 'signature-key'], $v['components']);
        $this->assertSame(self::NOW, $v['created']);
        $this->assertSame('sig', $v['label']);
        $this->assertSame(64, strlen($v['signature']));
        $this->assertStringContainsString('"@authority": resource.example', $v['base']);
    }

    public function testSignWireFormPostMatchesDemoRegexes(): void
    {
        $body = '{"resource":"https://resource.example"}';
        $h = HttpSignature::sign('POST', 'https://ps.example/person', self::JWT, $this->key, [], $body, [], self::NOW);
        $this->assertSame(['Content-Type', 'Content-Digest', 'Signature-Key', 'Signature-Input', 'Signature'], array_keys($h));
        $this->assertSame('application/json', $h['Content-Type']);
        $this->assertSame(ContentDigest::sha256($body), $h['Content-Digest']);
        // the reference demo's verifier regexes (shared/aauth.mjs verifySignedRequest)
        $this->assertMatchesRegularExpression('/^sig=jwt;\s*jwt="([^"]+)"$/', $h['Signature-Key']);
        $this->assertMatchesRegularExpression('/^sig=(\(([^)]*)\)(.*))$/', $h['Signature-Input']);
        $this->assertDoesNotMatchRegularExpression('/;alg=/', $h['Signature-Input']);
        $this->assertSame('sig=("@method" "@authority" "@path" "signature-key" "content-type" "content-digest");created=' . self::NOW, $h['Signature-Input']);

        $v = HttpSignature::verify($this->received('POST', 'https://ps.example/person', $h, $body), Jwk::publicOf($this->key), self::NOW);
        $this->assertContains('content-digest', $v['components']);
    }

    public function testCallerContentTypeIsSignedVerbatim(): void
    {
        $body = 'a=1';
        $h = HttpSignature::sign('POST', 'https://r.example/x', self::JWT, $this->key, ['Content-Type' => 'application/x-www-form-urlencoded; charset=utf-8'], $body, [], self::NOW);
        $this->assertSame('application/x-www-form-urlencoded; charset=utf-8', $h['Content-Type']);
        HttpSignature::verify($this->received('POST', 'https://r.example/x', $h, $body), $this->key, self::NOW);
        $h['Content-Type'] = 'application/json';
        $this->assertAAuthError('invalid_signature', fn () => HttpSignature::verify($this->received('POST', 'https://r.example/x', $h, $body), $this->key, self::NOW));
    }

    public function testEs256RoundTrip(): void
    {
        $ec = Jwk::generateEs256();
        $h = HttpSignature::sign('DELETE', 'https://r.example/x/1', self::JWT, $ec, now: self::NOW);
        $v = HttpSignature::verify($this->received('DELETE', 'https://r.example/x/1', $h), Jwk::publicOf($ec), self::NOW);
        $this->assertSame(64, strlen($v['signature']));
        $this->assertAAuthError('invalid_signature', fn () => HttpSignature::verify($this->received('DELETE', 'https://r.example/x/2', $h), Jwk::publicOf($ec), self::NOW));
    }

    public function testPortAndPathEdgeCases(): void
    {
        $h = HttpSignature::sign('GET', 'http://localhost:8796', self::JWT, $this->key, now: self::NOW);
        $req = $this->received('GET', 'http://localhost:8796', $h);
        $this->assertSame('localhost:8796', $req->authority);
        $v = HttpSignature::verify($req, $this->key, self::NOW);
        $this->assertStringContainsString('"@path": /', $v['base']);
        $this->assertSame('df.example', HttpSignature::authorityOf(parse_url('https://DF.example:443/x')));
        $this->assertSame('df.example:8443', HttpSignature::authorityOf(parse_url('https://df.example:8443/x')));
        // percent-encoded path is signed raw
        $h = HttpSignature::sign('GET', 'https://r.example/a%20b/%C3%A9', self::JWT, $this->key, now: self::NOW);
        $v = HttpSignature::verify($this->received('GET', 'https://r.example/a%20b/%C3%A9', $h), $this->key, self::NOW);
        $this->assertStringContainsString('"@path": /a%20b/%C3%A9', $v['base']);
        $this->assertAAuthError('invalid_signature', fn () => HttpSignature::verify($this->received('GET', 'https://r.example/a b/%C3%A9', $h), $this->key, self::NOW));
    }

    // ----------------------------------------------------------- negative cases

    public function testTamperedBody(): void
    {
        $body = '{"status":"refunded"}';
        $h = HttpSignature::sign('PATCH', 'https://r.example/o/1', self::JWT, $this->key, [], $body, [], self::NOW);
        $e = $this->assertAAuthError('invalid_signature', fn () => HttpSignature::verify($this->received('PATCH', 'https://r.example/o/1', $h, '{"status":"paid"}'), $this->key, self::NOW), 401);
        $this->assertSame('error=invalid_signature', $e->headers['Signature-Error']);
        $this->assertStringContainsString('Content-Digest', $e->detail);

        // a recomputed digest without the key does not verify
        $h2 = $h;
        $h2['Content-Digest'] = ContentDigest::sha256('{"status":"paid"}');
        $e = $this->assertAAuthError('invalid_signature', fn () => HttpSignature::verify($this->received('PATCH', 'https://r.example/o/1', $h2, '{"status":"paid"}'), $this->key, self::NOW));
        $this->assertStringContainsString('message signature is invalid', $e->detail);
    }

    public function testMissingSignatureHeaders(): void
    {
        $h = HttpSignature::sign('GET', 'https://r.example/x', self::JWT, $this->key, now: self::NOW);
        foreach (['Signature', 'Signature-Input', 'Signature-Key'] as $drop) {
            $partial = $h;
            unset($partial[$drop]);
            $this->assertAAuthError('invalid_signature', fn () => HttpSignature::verify($this->received('GET', 'https://r.example/x', $partial), $this->key, self::NOW), 401);
        }
    }

    public function testMissingRequiredComponents(): void
    {
        $url = 'https://r.example/x';
        $h = $this->signCustom('GET', $url, ['@method', '@authority', '@path'], ';created=' . self::NOW);
        $e = $this->assertAAuthError('invalid_input', fn () => HttpSignature::verify($this->received('GET', $url, $h), $this->key, self::NOW), 401);
        $this->assertSame('error=invalid_input, required_input=("@method" "@authority" "@path" "signature-key")', $e->headers['Signature-Error']);

        // body present but content-digest / content-type not covered
        $body = '{}';
        $h = $this->signCustom('POST', $url, ['@method', '@authority', '@path', 'signature-key'], ';created=' . self::NOW,
            ['content-type' => 'application/json', 'content-digest' => ContentDigest::sha256($body)], $body);
        $e = $this->assertAAuthError('invalid_input', fn () => HttpSignature::verify($this->received('POST', $url, $h, $body), $this->key, self::NOW));
        $this->assertSame('error=invalid_input, required_input=("@method" "@authority" "@path" "signature-key" "content-type" "content-digest")', $e->headers['Signature-Error']);

        // extra required component
        $h = HttpSignature::sign('GET', $url, self::JWT, $this->key, now: self::NOW);
        $this->assertAAuthError('invalid_input', fn () => HttpSignature::verify($this->received('GET', $url, $h), $this->key, self::NOW, 60, false, ['authorization']));
        $h = HttpSignature::sign('GET', $url, self::JWT, $this->key, ['Authorization' => 'AAuth abc'], '', ['authorization'], self::NOW);
        $v = HttpSignature::verify($this->received('GET', $url, $h, '', ['authorization' => 'AAuth abc']), $this->key, self::NOW, 60, false, ['Authorization']);
        $this->assertContains('authorization', $v['components']);
    }

    public function testQueryRequiredWhenPresent(): void
    {
        $url = 'https://r.example/api/v2/sales/_table/orders?limit=5';
        $plain = HttpSignature::sign('GET', $url, self::JWT, $this->key, now: self::NOW);
        $e = $this->assertAAuthError('invalid_input', fn () => HttpSignature::verify($this->received('GET', $url, $plain), $this->key, self::NOW, 60, true));
        $this->assertStringContainsString('"@query"', $e->headers['Signature-Error']);
        // without requireQuery the query is not bound
        HttpSignature::verify($this->received('GET', $url, $plain), $this->key, self::NOW);

        $h = HttpSignature::sign('GET', $url, self::JWT, $this->key, extra: ['@query'], now: self::NOW);
        $this->assertStringContainsString('"signature-key" "@query");created=', $h['Signature-Input']);
        $v = HttpSignature::verify($this->received('GET', $url, $h), $this->key, self::NOW, 60, true);
        $this->assertStringContainsString('"@query": ?limit=5', $v['base']);
        // query changed after signing
        $this->assertAAuthError('invalid_signature', fn () => HttpSignature::verify($this->received('GET', str_replace('limit=5', 'limit=500', $url), $h), $this->key, self::NOW, 60, true));
        // query removed after signing: @query was covered as "?limit=5", now "?"
        $this->assertAAuthError('invalid_signature', fn () => HttpSignature::verify($this->received('GET', 'https://r.example/api/v2/sales/_table/orders', $h), $this->key, self::NOW, 60, true));
        // no query: @query not required, but "?" is accepted when covered
        $h = HttpSignature::sign('GET', 'https://r.example/a', self::JWT, $this->key, extra: ['@query'], now: self::NOW);
        $v = HttpSignature::verify($this->received('GET', 'https://r.example/a', $h), $this->key, self::NOW, 60, true);
        $this->assertStringContainsString('"@query": ?', $v['base']);
        HttpSignature::verify($this->received('GET', 'https://r.example/a', HttpSignature::sign('GET', 'https://r.example/a', self::JWT, $this->key, now: self::NOW)), $this->key, self::NOW, 60, true);
    }

    public function testCreatedWindow(): void
    {
        $url = 'https://r.example/x';
        $h = HttpSignature::sign('GET', $url, self::JWT, $this->key, now: self::NOW);
        HttpSignature::verify($this->received('GET', $url, $h), $this->key, self::NOW + 60);
        $this->assertAAuthError('invalid_signature', fn () => HttpSignature::verify($this->received('GET', $url, $h), $this->key, self::NOW + 61), 401);
        HttpSignature::verify($this->received('GET', $url, $h), $this->key, self::NOW - 60);
        $e = $this->assertAAuthError('clock_skew', fn () => HttpSignature::verify($this->received('GET', $url, $h), $this->key, self::NOW - 61), 401);
        $this->assertSame('error=clock_skew', $e->headers['Signature-Error']);
        // custom window
        $this->assertAAuthError('invalid_signature', fn () => HttpSignature::verify($this->received('GET', $url, $h), $this->key, self::NOW + 11, 10));

        $noCreated = $this->signCustom('GET', $url, HttpSignature::BASE, '');
        $this->assertAAuthError('invalid_signature', fn () => HttpSignature::verify($this->received('GET', $url, $noCreated), $this->key, self::NOW));
        $strCreated = $this->signCustom('GET', $url, HttpSignature::BASE, ';created="' . self::NOW . '"');
        $this->assertAAuthError('invalid_signature', fn () => HttpSignature::verify($this->received('GET', $url, $strCreated), $this->key, self::NOW));
    }

    public function testExpires(): void
    {
        $url = 'https://r.example/x';
        $h = $this->signCustom('GET', $url, HttpSignature::BASE, ';created=' . self::NOW . ';expires=' . (self::NOW + 10));
        HttpSignature::verify($this->received('GET', $url, $h), $this->key, self::NOW + 10);
        $this->assertAAuthError('invalid_signature', fn () => HttpSignature::verify($this->received('GET', $url, $h), $this->key, self::NOW + 11));
    }

    public function testAlgParameterIgnoredPerSpecOrRejectedWhenStrict(): void
    {
        $url = 'https://r.example/x';
        $h = $this->signCustom('GET', $url, HttpSignature::BASE, ';created=' . self::NOW . ';alg="ed25519"');
        // -11 §11.3.3.2: verifiers MUST ignore alg (the key decides); it is still part of @signature-params
        $v = HttpSignature::verify($this->received('GET', $url, $h), $this->key, self::NOW);
        $this->assertSame('ed25519', $v['params']['alg']);
        $this->assertStringEndsWith(';alg="ed25519"', $v['base']);
        // a lying alg does not change the algorithm used
        $h = $this->signCustom('GET', $url, HttpSignature::BASE, ';created=' . self::NOW . ';alg="hmac-sha256"');
        HttpSignature::verify($this->received('GET', $url, $h), $this->key, self::NOW);
        // strict mode (reference demo behaviour)
        $this->assertAAuthError('invalid_signature', fn () => HttpSignature::verify($this->received('GET', $url, $h), $this->key, self::NOW, 60, false, [], true));
    }

    public function testKeyidIgnored(): void
    {
        $url = 'https://r.example/x';
        $h = $this->signCustom('GET', $url, HttpSignature::BASE, ';created=' . self::NOW . ';keyid="whatever"');
        HttpSignature::verify($this->received('GET', $url, $h), $this->key, self::NOW);
        $this->addToAssertionCount(1);
    }

    public function testWrongAuthorityMethodPath(): void
    {
        $url = 'https://df.example/api/v2/x';
        $h = HttpSignature::sign('GET', $url, self::JWT, $this->key, now: self::NOW);
        $this->assertAAuthError('invalid_signature', fn () => HttpSignature::verify($this->received('GET', 'http://192.0.2.10:8796/api/v2/x', $h), $this->key, self::NOW));
        $this->assertAAuthError('invalid_signature', fn () => HttpSignature::verify($this->received('DELETE', $url, $h), $this->key, self::NOW));
        $this->assertAAuthError('invalid_signature', fn () => HttpSignature::verify($this->received('GET', 'https://df.example/api/v2/y', $h), $this->key, self::NOW));
        // host case is folded
        HttpSignature::verify($this->received('GET', 'https://DF.Example/api/v2/x', $h), $this->key, self::NOW);
    }

    public function testWrongKey(): void
    {
        $h = HttpSignature::sign('GET', 'https://r.example/x', self::JWT, $this->key, now: self::NOW);
        $this->assertAAuthError('invalid_signature', fn () => HttpSignature::verify($this->received('GET', 'https://r.example/x', $h), Jwk::publicOf(Jwk::generateEd25519()), self::NOW));
        $bad = Jwk::publicOf($this->key);
        unset($bad['alg']);
        $this->assertAAuthError('unsupported_algorithm', fn () => HttpSignature::verify($this->received('GET', 'https://r.example/x', $h), $bad, self::NOW));
        $this->assertAAuthError('unsupported_algorithm', fn () => HttpSignature::verify($this->received('GET', 'https://r.example/x', $h), ['alg' => 'EdDSA'] + $bad, self::NOW));
    }

    public function testSignatureKeyTamperingBreaksSignature(): void
    {
        $h = HttpSignature::sign('GET', 'https://r.example/x', self::JWT, $this->key, now: self::NOW);
        $h['Signature-Key'] = SignatureKey::jwt('sig', self::JWT . 'x');
        $this->assertAAuthError('invalid_signature', fn () => HttpSignature::verify($this->received('GET', 'https://r.example/x', $h), $this->key, self::NOW));
    }

    public function testMalformedSignatureHeaders(): void
    {
        $url = 'https://r.example/x';
        $h = HttpSignature::sign('GET', $url, self::JWT, $this->key, now: self::NOW);
        $b64url = $h;
        $b64url['Signature'] = 'sig=:' . B64::url(B64::stdDecode(substr($h['Signature'], 5, -1))) . ':';
        // RFC 8941 4.2.7: missing '=' padding alone must be tolerated, so only assert when the
        // base64url form actually contains '-' or '_' (not valid in sf-binary).
        if (strpbrk(substr($b64url['Signature'], 5, -1), '-_') !== false) {
            $this->assertAAuthError('invalid_signature', fn () => HttpSignature::verify($this->received('GET', $url, $b64url), $this->key, self::NOW));
        }
        foreach ([
            ['Signature', 'sig="abc"'],
            ['Signature', 'other=:AAAA:'],
            ['Signature', 'sig=:AAAA'],
            ['Signature-Input', 'sig="@method"'],
            ['Signature-Input', 'other=("@method");created=1'],
            ['Signature-Input', 'sig=(@method)'],
            ['Signature-Input', 'sig=("@method" "@method" "@authority" "@path" "signature-key");created=' . self::NOW],
            ['Signature-Input', 'sig=("@method";req "@authority" "@path" "signature-key");created=' . self::NOW],
            ['Signature-Input', 'sig=(1 "@authority" "@path" "signature-key");created=' . self::NOW],
            ['Signature-Key', 'sig=jwt'],
        ] as [$name, $value]) {
            $bad = $h;
            $bad[$name] = $value;
            $code = $name === 'Signature-Key' ? 'invalid_key' : 'invalid_signature';
            $this->assertAAuthError($code, fn () => HttpSignature::verify($this->received('GET', $url, $bad), $this->key, self::NOW));
        }
    }

    public function testUnsupportedComponents(): void
    {
        $url = 'https://r.example/x';
        $h = $this->signCustom('GET', $url, HttpSignature::BASE, ';created=' . self::NOW);
        $h['signature-input'] = 'sig=("@method" "@authority" "@path" "signature-key" "@target-uri");created=' . self::NOW;
        $this->assertAAuthError('invalid_signature', fn () => HttpSignature::verify($this->received('GET', $url, $h), $this->key, self::NOW));
        $h = $this->signCustom('GET', $url, [...HttpSignature::BASE, 'x-custom'], ';created=' . self::NOW, ['x-custom' => ' v ']);
        $v = HttpSignature::verify($this->received('GET', $url, $h), $this->key, self::NOW);
        $this->assertStringContainsString('"x-custom": v', $v['base']);
        unset($h['x-custom']);
        $this->assertAAuthError('invalid_signature', fn () => HttpSignature::verify($this->received('GET', $url, $h), $this->key, self::NOW));
    }

    public function testOtherLabelAndMultipleMembers(): void
    {
        $url = 'https://r.example/x';
        $h = $this->signCustom('GET', $url, HttpSignature::BASE, ';created=' . self::NOW, ['signature-key' => SignatureKey::jwt('agent', self::JWT)]);
        $h['signature-input'] = str_replace('sig=', 'agent=', $h['signature-input']);
        $h['signature'] = str_replace('sig=', 'agent=', $h['signature']);
        $v = HttpSignature::verify($this->received('GET', $url, $h), $this->key, self::NOW);
        $this->assertSame('agent', $v['label']);

        // "sig" is selected when several members exist; the other members are ignored
        $h2 = HttpSignature::sign('GET', $url, self::JWT, $this->key, now: self::NOW);
        $h2['Signature-Input'] = 'other=("@method");created=1, ' . $h2['Signature-Input'];
        $h2['Signature'] = 'other=:AAAA:, ' . $h2['Signature'];
        HttpSignature::verify($this->received('GET', $url, $h2), $this->key, self::NOW);
    }

    public function testDigestCoveredOnEmptyBody(): void
    {
        $url = 'https://r.example/x';
        $h = $this->signCustom('GET', $url, [...HttpSignature::BASE, 'content-digest'], ';created=' . self::NOW, ['content-digest' => ContentDigest::sha256('')]);
        HttpSignature::verify($this->received('GET', $url, $h), $this->key, self::NOW);
        $h = $this->signCustom('GET', $url, [...HttpSignature::BASE, 'content-digest'], ';created=' . self::NOW, ['content-digest' => ContentDigest::sha256('x')]);
        $this->assertAAuthError('invalid_signature', fn () => HttpSignature::verify($this->received('GET', $url, $h), $this->key, self::NOW));
    }

    public function testHeaderListsAreJoined(): void
    {
        $parts = new HttpRequestParts('GET', 'a', '/', null, ['X-A' => ['1', ' 2 ']], '');
        $this->assertSame('1, 2', $parts->header('x-a'));
        $this->assertNull($parts->header('x-b'));
    }
}
