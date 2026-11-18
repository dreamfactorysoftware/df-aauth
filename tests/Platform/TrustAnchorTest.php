<?php

namespace DreamFactory\Core\AAuth\Tests\Platform;

use DreamFactory\Core\AAuth\Protocol\AAuthError;
use DreamFactory\Core\AAuth\Resource\PersonServers;
use DreamFactory\Core\AAuth\Resource\ScopeResolver;

/**
 * Trust is anchored on the verified signer (iss), never on the self-declared `ps` claim, and auth
 * tokens issued by access servers are refused.
 */
final class TrustAnchorTest extends TestCase
{
    private const EVIL = 'https://evil.example';

    private function err(\Closure $fn): AAuthError
    {
        try {
            $fn();
        } catch (AAuthError $e) {
            return $e;
        }
        $this->fail('no AAuthError');
    }

    public function testForgedAccessServerTokenNamingTheLocalPsIsRefused(): void
    {
        $forged = ['iss' => self::EVIL, 'dwk' => 'aauth-access.json', 'ps' => self::ISSUER, 'aud' => self::ISSUER, 'sub' => 'x', 'scope' => 'sales.refund'];
        $e = $this->err(fn () => PersonServers::preCheck('aa-auth+jwt', $forged));
        $this->assertSame(401, $e->status);
        $this->assertSame('invalid_jwt', $e->error);
        $this->assertArrayHasKey('Signature-Error', $e->headers);
        $this->assertSame('invalid_jwt', $this->err(fn () => PersonServers::anchor('aa-auth+jwt', $forged))->error);
    }

    public function testPersonDwkAuthTokenMustNameItselfInPs(): void
    {
        $t = ['iss' => self::EVIL, 'dwk' => 'aauth-person.json', 'ps' => self::ISSUER, 'sub' => 'x'];
        $this->assertSame(401, $this->err(fn () => PersonServers::anchor('aa-auth+jwt', $t))->status);
        $this->assertSame(401, $this->err(fn () => PersonServers::preCheck('aa-auth+jwt', $t))->status);
        unset($t['ps']);
        $this->assertSame('invalid_jwt', $this->err(fn () => PersonServers::anchor('aa-auth+jwt', $t))->error);
    }

    public function testTrustIsDecidedOnIss(): void
    {
        $local = ['iss' => self::ISSUER, 'dwk' => 'aauth-person.json', 'ps' => self::ISSUER, 'sub' => 'x'];
        $this->assertSame(self::ISSUER, PersonServers::anchor('aa-auth+jwt', $local));
        PersonServers::preCheck('aa-auth+jwt', $local); // trusted: no exception
        PersonServers::preCheck('aa-person+jwt', ['iss' => self::ISSUER]);
        PersonServers::preCheck('aa-agent+jwt', ['iss' => self::EVIL]); // agent tokens: no PS policy

        // an untrusted person server is refused early as a credential problem (nothing verified yet)
        $e = $this->err(fn () => PersonServers::preCheck('aa-person+jwt', ['iss' => self::EVIL, 'ps' => self::ISSUER]));
        $this->assertSame(401, $e->status);
        $this->assertSame('invalid_jwt', $e->error);
    }

    public function testExternalPersonServerStartsWithNoScopesAndEmptyMeansNone(): void
    {
        $this->role(1, 'Sales read');
        $this->role(2, 'Sales refund');
        $this->scope(1, 'sales.read');
        $this->scope(2, 'sales.refund');
        // what PersonServers::add() inserts for a new external PS
        $id = $this->db()->table('aauth_person_servers')->insertGetId(['issuer' => self::EVIL, 'name' => 'Partner', 'is_local' => false, 'enabled' => true, 'scopes' => '[]']);
        $resolver = new ScopeResolver(fn () => true, fn () => [1, 1]);

        $row = PersonServers::trusted(self::EVIL);
        $this->assertSame([], $row['scopes']);
        $this->assertSame([], $resolver->candidates($row), 'a new external PS vouches for nothing');
        $wire = PersonServers::get($id);
        $this->assertSame([], $wire['scopes']);
        $this->assertFalse($wire['all_scopes']);

        PersonServers::patch($id, ['scopes' => ['sales.read']]);
        $this->assertSame(['sales.read'], array_keys($resolver->candidates(PersonServers::trusted(self::EVIL))));

        // clearing the last scope leaves none (not "all")
        $wire = PersonServers::patch($id, ['scopes' => []]);
        $this->assertSame([], $wire['scopes']);
        $this->assertFalse($wire['all_scopes']);
        $this->assertSame([], $resolver->candidates(PersonServers::trusted(self::EVIL)));

        // "all scopes" is an explicit opt-in
        $wire = PersonServers::patch($id, ['all_scopes' => true]);
        $this->assertTrue($wire['all_scopes']);
        $this->assertSame(['sales.read', 'sales.refund'], array_keys($resolver->candidates(PersonServers::trusted(self::EVIL))));
        $wire = PersonServers::patch($id, ['all_scopes' => false]);
        $this->assertFalse($wire['all_scopes']);
        $this->assertSame([], $wire['scopes']);

        // the local row still trusts every scope by default
        $this->assertTrue(PersonServers::ensureLocal()['scopes'] === null);
    }
}
