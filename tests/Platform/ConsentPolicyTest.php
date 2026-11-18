<?php

namespace DreamFactory\Core\AAuth\Tests\Platform;

use DreamFactory\Core\AAuth\PersonServer\ConsentPolicy;
use DreamFactory\Core\AAuth\PersonServer\Grants;

/** "Grant only roles you have." */
final class ConsentPolicyTest extends TestCase
{
    protected function setUp(): void
    {
        parent::setUp();
        $this->role(1, 'Sales read');
        $this->role(2, 'Sales refunds');
        $this->role(3, 'Hidden');
        $this->scope(1, 'sales.read');
        $this->scope(2, 'sales.refund');
        $this->scope(3, 'hidden', false);
    }

    public function testAdminCanGrantEveryEnabledScope(): void
    {
        $admin = $this->user(1, 'admin@x.test', true);
        $this->assertSame(['sales.read' => true, 'sales.refund' => true, 'hidden' => false, 'profile' => true],
            ConsentPolicy::grantable($admin, ['sales.read', 'sales.refund', 'hidden', 'profile'], self::ISSUER));
    }

    public function testUserCanGrantOnlyAssignedRoles(): void
    {
        $jordan = $this->user(2, 'jordan@x.test', false, [1]);
        $this->assertSame(['sales.read' => true, 'sales.refund' => false, 'email' => true, 'nope' => false],
            ConsentPolicy::grantable($jordan, ['sales.read', 'sales.refund', 'email', 'nope'], self::ISSUER));
        $nobody = $this->user(3, 'nobody@x.test');
        $this->assertSame(['sales.read' => false], ConsentPolicy::grantable($nobody, ['sales.read'], self::ISSUER));
    }

    public function testExternalResourceScopesAreThePersonsToGive(): void
    {
        $nobody = $this->user(3, 'nobody@x.test');
        $this->assertSame(['board.write' => true, 'profile' => true],
            ConsentPolicy::grantable($nobody, ['board.write', 'profile'], 'https://board.example'));
    }

    public function testStandingGrantsCoverAndMerge(): void
    {
        $this->user(2, 'jordan@x.test', false, [1]);
        Grants::save(2, self::ISSUER, 'DF', 'https://agent.example', 'aauth:a@agent.example', 'Acme', ['sales.read']);
        $g = Grants::find(2, self::ISSUER, 'https://agent.example', 'aauth:a@agent.example');
        $this->assertTrue(Grants::covers($g, ['sales.read']));
        $this->assertFalse(Grants::covers($g, ['sales.read', 'sales.refund']));
        $this->assertFalse(Grants::covers($g, []));
        Grants::save(2, self::ISSUER, 'DF', 'https://agent.example', 'aauth:a@agent.example', 'Acme', ['sales.refund']);
        $g = Grants::find(2, self::ISSUER, 'https://agent.example', 'aauth:a@agent.example');
        $this->assertTrue(Grants::covers($g, ['sales.read', 'sales.refund']));
        $this->assertNull(Grants::find(2, self::ISSUER, 'https://agent.example', 'aauth:other@agent.example'));
        $this->assertCount(1, Grants::list());
        Grants::delete($g['id']);
        $this->assertSame([], Grants::list());
    }
}
