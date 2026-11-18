<?php

namespace DreamFactory\Core\AAuth\Tests\Platform;

use DreamFactory\Core\AAuth\PersonServer\Pending;

final class PendingTest extends TestCase
{
    private function create(string $kind = 'person'): array
    {
        return Pending::create($kind, ['sub' => 'aauth:a@agent.example', 'iss' => 'https://agent.example', 'jkt' => 'JKT1'],
            self::ISSUER, 'DreamFactory', ['justification' => str_repeat('x', 1500)]);
    }

    public function testCreateAndFindByCodeIsForgiving(): void
    {
        $p = $this->create();
        $this->assertSame('pending', $p['status']);
        $this->assertMatchesRegularExpression('/^[0-9A-HJKMNP-TV-Z]{8}$/', $p['code']);
        $this->assertSame(1000, mb_strlen($p['justification']));
        $display = Pending::displayCode($p['code']);
        $this->assertMatchesRegularExpression('/^.{4}-.{4}$/', $display);
        $this->assertSame($p['id'], Pending::findLiveByCode(strtolower($display))['id']);
        $this->assertSame($p['id'], Pending::findLiveByCode($p['code'])['id']);
        $this->assertNull(Pending::findLiveByCode('ZZZZ-ZZZZ' === $display ? 'YYYY-YYYY' : 'ZZZZ-ZZZZ'));
        $this->assertNull(Pending::findLiveByCode('not a code!'));
        $this->assertSame('JKT1', $p['agent']['jkt']);
    }

    public function testApprovedIsDeliveredOnceThenGone(): void
    {
        $p = $this->create();
        Pending::markInteracting($p['id']);
        $this->assertSame([202, ['status' => 'interacting']], Pending::poll(Pending::find($p['id'])));
        $this->assertTrue(Pending::approve($p['id'], 'TOKEN', time() + 600, 7, 'SUB'));
        $this->assertFalse(Pending::approve($p['id'], 'OTHER', time() + 600), 'approve only once');
        $this->assertNull(Pending::findLiveByCode($p['code']), 'code is single use');
        [$status, $body] = Pending::poll(Pending::find($p['id']));
        $this->assertSame(200, $status);
        $this->assertSame('TOKEN', $body['token']);
        $this->assertSame(7, Pending::find($p['id'])['user_id']);
        $this->assertSame(410, Pending::poll(Pending::find($p['id']))[0]);
    }

    public function testDeniedAnswersForbiddenOnceThenGone(): void
    {
        $p = $this->create('auth');
        Pending::deny($p['id']);
        $this->assertSame(403, Pending::poll(Pending::find($p['id']))[0]);
        $this->assertSame(410, Pending::poll(Pending::find($p['id']))[0]);
    }

    public function testExpiredAnswersTimeoutOnceThenGone(): void
    {
        $p = $this->create();
        $this->db()->table('aauth_ps_pending')->where('id', $p['id'])->update(['expires_at' => now()->subSecond()]);
        $this->assertNull(Pending::findLiveByCode($p['code']));
        $this->assertFalse(Pending::isLive(Pending::find($p['id'])));
        $this->assertSame(408, Pending::poll(Pending::find($p['id']))[0]);
        $this->assertSame(410, Pending::poll(Pending::find($p['id']))[0]);
    }

    public function testCancelled(): void
    {
        $p = $this->create();
        Pending::setStatus($p['id'], 'cancelled');
        $this->assertSame(410, Pending::poll(Pending::find($p['id']))[0]);
    }
}
