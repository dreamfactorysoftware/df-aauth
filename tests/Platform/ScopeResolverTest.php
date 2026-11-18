<?php

namespace DreamFactory\Core\AAuth\Tests\Platform;

use DreamFactory\Core\AAuth\Resource\ScopeResolver;

final class ScopeResolverTest extends TestCase
{
    /** role id => [rows, bits]; allows: role id => list of "service/component VERB" it allows */
    private function resolver(array $stats, array $allow): ScopeResolver
    {
        return new ScopeResolver(
            fn (int $r, string $s, ?string $c, string $v) => in_array("$s/$c $v", $allow[$r] ?? [], true),
            fn (int $r) => $stats[$r] ?? [0, 0]
        );
    }

    protected function setUp(): void
    {
        parent::setUp();
        $this->role(1, 'Sales read');
        $this->role(2, 'Sales refunds');
        $this->role(3, 'Everything');
        $this->role(4, 'Disabled one');
        $this->scope(1, 'sales.read');
        $this->scope(2, 'sales.refund');
        $this->scope(3, 'all');
        $this->scope(4, 'off', false);
    }

    public function testLeastPrivilegedCoveringScopeWins(): void
    {
        $r = $this->resolver([1 => [2, 2], 2 => [4, 6], 3 => [1, 31]], [
            1 => ['sales/_table/orders GET'],
            2 => ['sales/_table/orders GET', 'sales/_table/orders/5 PATCH'],
            3 => ['sales/_table/orders GET', 'sales/_table/orders/5 PATCH'],
        ]);
        // GET: role 3 has fewer rows (1) than role 1 (2) -> rows first
        $this->assertSame('all', $r->covering('sales', '_table/orders', 'GET', null)['scope']);
        // without role 3 the read role wins over refunds (2 rows < 4 rows)
        $ps = ['scopes' => ['sales.read', 'sales.refund']];
        $this->assertSame('sales.read', $r->covering('sales', '_table/orders', 'GET', $ps)['scope']);
        $this->assertSame('sales.refund', $r->covering('sales', '_table/orders/5', 'PATCH', $ps)['scope']);
        $this->assertNull($r->covering('sales', '_table/orders/5', 'DELETE', $ps));
    }

    public function testTieBreaksOnVerbBitsThenRoleId(): void
    {
        $r = $this->resolver([1 => [2, 5], 2 => [2, 3], 3 => [2, 3]], [
            1 => ['db/x GET'], 2 => ['db/x GET'], 3 => ['db/x GET'],
        ]);
        $this->assertSame('sales.refund', $r->covering('db', 'x', 'GET', null)['scope']);   // 3 bits < 5, role 2 < role 3
    }

    public function testDisabledScopesAndPersonServerAllowListAreHonoured(): void
    {
        $r = $this->resolver([4 => [0, 0], 1 => [9, 9]], [4 => ['db/x GET'], 1 => ['db/x GET']]);
        $this->assertSame('sales.read', $r->covering('db', 'x', 'GET', null)['scope']);   // 'off' is disabled
        $this->assertNull($r->covering('db', 'x', 'GET', ['scopes' => []]));                // PS allowed nothing
        $this->assertSame('sales.read', $r->covering('db', 'x', 'GET', ['scopes' => null])['scope']); // null = all
        $this->assertSame([], array_keys($r->candidates(['scopes' => ['nope']])));
    }

    public function testApiRootIsCoveredByAnyScope(): void
    {
        $r = $this->resolver([1 => [2, 2], 2 => [4, 6], 3 => [7, 31]], []);
        $this->assertSame('sales.read', $r->covering('', '', 'GET', null)['scope']);
        $this->assertSame('sales.refund', $r->covering(null, null, 'GET', null, ['sales.refund'])['scope']);
    }
}
