<?php

namespace DreamFactory\Core\AAuth\Tests\Platform;

use DreamFactory\Core\AAuth\Playground\Client;
use DreamFactory\Core\AAuth\Playground\Playground;
use DreamFactory\Core\AAuth\Protocol\Jwk;
use DreamFactory\Core\AAuth\Support\Store;
use Illuminate\Support\Facades\Crypt;

/**
 * Try it with cached tokens: a cached person or auth token the API refuses with a signature error
 * and no requirement (no record of it, a revoked key) is forgotten, and the run starts over once with
 * the agent token instead of ending on that 401 until the token expires.
 */
final class PlaygroundTest extends TestCase
{
    private const USER = 7;

    /** A Client that answers from a script and records what it was sent. */
    private function client(array $script): Client
    {
        return new class($script) extends Client {
            public array $sent = [];

            public function __construct(private array $script)
            {
            }

            public function send(string $method, string $url, ?string $body = null, ?string $jwt = null, ?array $privateJwk = null): array
            {
                $this->sent[] = [$method, $url, $jwt];
                $response = array_shift($this->script) ?? ['status' => 500, 'headers' => [], 'body' => 'script ended'];

                return ['request' => ['method' => $method, 'url' => $url, 'headers' => [], 'body' => $body], 'response' => $response];
            }
        };
    }

    private function cacheTokens(array $tokens): void
    {
        Store::cache()->put('aauth:pg:key:' . self::USER, Crypt::encryptString(json_encode(Jwk::generateEd25519())), 3600);
        Store::cache()->put('aauth:pg:tok:' . self::USER, Crypt::encryptString(json_encode($tokens)), 3600);
    }

    private function cachedTokens(): array
    {
        return json_decode(Crypt::decryptString(Store::cache()->get('aauth:pg:tok:' . self::USER)), true);
    }

    private static function noRecord(): array
    {
        return ['status' => 401, 'headers' => [['Signature-Error', 'error=invalid_jwt']],
            'body' => '{"error":"invalid_jwt","detail":"This DreamFactory has no record of issuing this token. Get a new one."}'];
    }

    public function testACachedTokenTheApiNoLongerAcceptsIsForgottenAndTheRunStartsOver(): void
    {
        $this->cacheTokens(['auth_token' => 'cached-auth-token', 'auth_exp' => time() + 3000, 'person_token' => 'cached-person-token', 'person_exp' => time() + 3000]);
        $client = $this->client([
            self::noRecord(),
            ['status' => 401, 'headers' => [['AAuth-Requirement', 'requirement=person-token']], 'body' => '{"error":"person_token_required"}'],
            ['status' => 200, 'headers' => [], 'body' => json_encode(['issuer' => self::ISSUER, 'person_token_endpoint' => self::ISSUER . '/aauth/person',
                'auth_token_endpoint' => self::ISSUER . '/aauth/token'])],
            ['status' => 202, 'headers' => [['Location', '/aauth/pending/p1']], 'body' => '{"status":"pending","code":"7KQM-4D2P"}'],
        ]);
        $run = (new Playground(self::USER, $client))->send('GET', '/api/v2/sales/_table/orders', null);

        $this->assertSame('waiting', $run['status'], json_encode($run['error']));
        $this->assertSame('7KQM-4D2P', $run['pending']['code']);
        $this->assertSame('cached-auth-token', $client->sent[0][2]);
        $this->assertNotSame('cached-auth-token', $client->sent[1][2], 'the second call presents the agent token');
        $this->assertSame(['GET', self::ISSUER . '/api/v2/sales/_table/orders'], array_slice($client->sent[1], 0, 2));
        $this->assertSame(['POST', self::ISSUER . '/aauth/person'], array_slice($client->sent[3], 0, 2));
        $tokens = $this->cachedTokens();
        $this->assertArrayNotHasKey('auth_token', $tokens);
        $this->assertArrayNotHasKey('person_token', $tokens);
    }

    public function testItStartsOverOnlyOnce(): void
    {
        $this->cacheTokens(['person_token' => 'cached-person-token', 'person_exp' => time() + 3000]);
        $client = $this->client([self::noRecord(), self::noRecord()]);
        $run = (new Playground(self::USER, $client))->send('GET', '/api/v2/sales/_table/orders', null);

        $this->assertSame('done', $run['status']);
        $this->assertSame(401, $run['result']['status'], 'the agent token\'s own 401 is the result');
        $this->assertCount(2, $client->sent);
    }

    public function testA401WithoutASignatureErrorEndsTheRunAsBefore(): void
    {
        $this->cacheTokens(['auth_token' => 'cached-auth-token', 'auth_exp' => time() + 3000]);
        $client = $this->client([['status' => 401, 'headers' => [], 'body' => '{"error":"unauthorized"}']]);
        $run = (new Playground(self::USER, $client))->send('GET', '/api/v2/sales/_table/orders', null);

        $this->assertSame(['done', 401], [$run['status'], $run['result']['status']]);
        $this->assertCount(1, $client->sent);
        $this->assertSame('cached-auth-token', $this->cachedTokens()['auth_token'], 'kept');
    }
}
