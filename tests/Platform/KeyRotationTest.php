<?php

namespace DreamFactory\Core\AAuth\Tests\Platform;

use DreamFactory\Core\AAuth\Protocol\AAuthError;
use DreamFactory\Core\AAuth\Protocol\Jwt;
use DreamFactory\Core\AAuth\Resource\ResourceTokens;
use DreamFactory\Core\AAuth\Support\AAuth;
use DreamFactory\Core\AAuth\Support\Keys;
use Illuminate\Support\Facades\Crypt;
use Illuminate\Support\Facades\Schema;

/** Signing key rotation: overlap window, revocation, pruning, and pre-migration behaviour. */
final class KeyRotationTest extends TestCase
{
    private function token(): string
    {
        return ResourceTokens::mint(['sub' => 'pairwise-sub', 'jti' => 'presented-jti'], 'https://ps.example.test', 'JKT', 'sales.read');
    }

    private function verify(string $jwt): array
    {
        $this->forget();

        return Jwt::verify($jwt, 'aa-resource+jwt', AAuth::discovery(), time());
    }

    private function kids(string $purpose): array
    {
        $this->forget();

        return array_column(Keys::jwks($purpose)['keys'], 'kid');
    }

    private function retireAgo(string $kid, int $seconds): void
    {
        $this->db()->table(Keys::TABLE)->where('kid', $kid)->update(['retired_at' => now()->subSeconds($seconds)]);
    }

    public function testRotationKeepsOldTokensVerifyingDuringTheOverlap(): void
    {
        $old = Keys::publicJwk('resource')['kid'];
        $before = $this->token();
        $this->assertSame([$old], $this->kids('resource'));

        $r = Keys::rotate('resource');
        $this->assertSame([$old], $r['retired']);
        $this->assertSame([], $r['revoked']);
        $this->assertNotSame($old, $r['kid']);
        $this->forget();
        $this->assertSame($r['kid'], Keys::privateJwk('resource')['kid'], 'the new key signs at once');
        $this->assertSame([$old, $r['kid']], $this->kids('resource'), 'both published during the overlap');
        $this->assertSame($r['kid'], Jwt::decode($this->token())['header']['kid']);
        $this->assertSame('pairwise-sub', $this->verify($before)['payload']['sub'], 'a token signed before the rotation still verifies');
        $this->assertNotNull(Keys::find('resource', $old));

        // other purposes are untouched
        $person = Keys::publicJwk('person')['kid'];
        Keys::rotate('resource');
        $this->forget();
        $this->assertSame($person, Keys::publicJwk('person')['kid']);
    }

    public function testRetiredKeysLeaveAfterTheOverlapAndArePruned(): void
    {
        $old = Keys::publicJwk('agent')['kid'];
        $new = Keys::rotate('agent')['kid'];
        $this->retireAgo($old, Keys::overlap() + 5);
        $this->assertSame([$new], $this->kids('agent'), 'gone from the JWKS once the overlap ends, even before pruning');
        $this->assertNull(Keys::find('agent', $old));
        $this->assertSame(1, Keys::prune(true), 'dry run counts');
        $this->assertSame(2, $this->db()->table(Keys::TABLE)->where('purpose', 'agent')->count());
        $this->assertSame(1, Keys::prune());
        $this->assertSame([$new], $this->db()->table(Keys::TABLE)->where('purpose', 'agent')->pluck('kid')->all(), 'private key deleted too');
        $this->assertSame(0, Keys::prune());
    }

    public function testRevokeDropsPreviousKeysAtOnce(): void
    {
        $before = $this->token();
        $old = Keys::publicJwk('resource')['kid'];
        $retiring = Keys::rotate('resource')['kid'];
        $r = Keys::rotate('resource', true);
        $this->assertEqualsCanonicalizing([$old, $retiring], $r['revoked']);
        $this->assertSame([$r['kid']], $this->kids('resource'));
        try {
            $this->verify($before);
            $this->fail('a token signed with a revoked key verified');
        } catch (AAuthError $e) {
            $this->assertSame('unknown_key', $e->error);
        }
    }

    public function testOverlapNeverShorterThanTheLongestTokenLifetime(): void
    {
        $this->app['config']->set('df-aauth.key_overlap', 60);
        $this->assertSame(3600 + 300, Keys::overlap());
        $this->app['config']->set('df-aauth.auth_token_ttl', 7200);
        $this->assertSame(7200 + 300, Keys::overlap());
        $this->app['config']->set('df-aauth.key_overlap', 172800);
        $this->assertSame(172800, Keys::overlap());
    }

    public function testInventoryShowsStatesWithoutPrivateMaterial(): void
    {
        Keys::publicJwk('person');
        $old = Keys::publicJwk('resource')['kid'];
        Keys::rotate('resource');
        $rows = Keys::inventory();
        $states = array_map(fn ($r) => $r['purpose'] . ':' . $r['state'], $rows);
        $this->assertEqualsCanonicalizing(['person:signing', 'resource:retiring', 'resource:signing'], $states);
        $retiring = array_values(array_filter($rows, fn ($r) => $r['kid'] === $old))[0];
        $this->assertMatchesRegularExpression('/^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ$/', $retiring['published_until']);
        $this->assertStringNotContainsString('"d"', json_encode($rows));
        $this->assertNotNull(Keys::signingKeyCreatedAt('resource'));
        $this->assertNull(Keys::signingKeyCreatedAt('agent'), 'no agent key yet');
    }

    public function testPrivateKeysAreEncryptedWithTheAppKey(): void
    {
        Keys::publicJwk('person');
        $row = $this->db()->table(Keys::TABLE)->where('purpose', 'person')->first();
        $this->assertStringNotContainsString('"d"', $row->private_jwk);
        $this->assertArrayHasKey('d', json_decode(Crypt::decryptString($row->private_jwk), true));
    }

    public function testBeforeTheMigrationKeysBehaveAsBefore(): void
    {
        $a = Keys::publicJwk('resource')['kid'];
        Schema::table(Keys::TABLE, fn ($t) => $t->dropColumn('retired_at'));
        $this->app['cache']->store()->flush();
        $this->forget();
        $this->assertFalse(Keys::rotationReady());
        $this->assertSame($a, Keys::privateJwk('resource')['kid']);
        $this->assertSame([$a], $this->kids('resource'));
        $this->assertSame(0, Keys::prune());
        $this->expectException(\RuntimeException::class);
        Keys::rotate('resource');
    }
}
