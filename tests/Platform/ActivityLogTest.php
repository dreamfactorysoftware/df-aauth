<?php

namespace DreamFactory\Core\AAuth\Tests\Platform;

use DreamFactory\Core\AAuth\Admin\ActivityLog;
use DreamFactory\Core\Exceptions\BadRequestException;

/** The admin activity list: newest first, paging, and the optional outcome filter. */
final class ActivityLogTest extends TestCase
{
    /** Rows 1..8, oldest first, with these outcomes. */
    private const OUTCOMES = ['allowed', 'error', 'person_required', 'denied', 'auth_required', 'blocked', 'allowed', 'error'];

    protected function setUp(): void
    {
        parent::setUp();
        foreach (self::OUTCOMES as $i => $outcome) {
            $this->db()->table('aauth_activity')->insert([
                'id' => $i + 1,
                'created_at' => '2026-11-10 00:00:0' . $i,
                'agent_id' => 'aauth:a@agent.example',
                'method' => 'GET',
                'path' => '/api/v2/db/_table/t',
                'status' => $outcome === 'allowed' ? 200 : 401,
                'outcome' => $outcome,
                'detail' => $outcome === 'error' ? 'invalid_signature: Missing signature header.' : null,
            ]);
        }
    }

    private static function ids(array $page): array
    {
        return array_column($page['resource'], 'id');
    }

    public function testWithoutAFilterEveryOutcomeIsListedNewestFirst(): void
    {
        $page = ActivityLog::list();
        $this->assertSame([8, 7, 6, 5, 4, 3, 2, 1], self::ids($page));
        $this->assertFalse($page['has_more']);
        $this->assertSame(self::ids($page), self::ids(ActivityLog::list(null, null, '')), 'an empty filter is no filter');
        $this->assertSame('invalid_signature: Missing signature header.', $page['resource'][0]['detail']);
    }

    public function testTheFilterKeepsOnlyTheNamedOutcomes(): void
    {
        $this->assertSame([7, 1], self::ids(ActivityLog::list(null, null, 'allowed')));
        $this->assertSame([5, 3], self::ids(ActivityLog::list(null, null, 'person_required,auth_required')));
        $this->assertSame([8, 6, 4, 2], self::ids(ActivityLog::list(null, null, ' Denied , blocked,error,')), 'trimmed, case-insensitive');
        $this->assertSame([7, 1], self::ids(ActivityLog::list(null, null, ['allowed', 'allowed'])), 'a list works too');
    }

    public function testPagingFollowsTheFilter(): void
    {
        $first = ActivityLog::list(2, null, 'denied,blocked,error');
        $this->assertSame([8, 6], self::ids($first));
        $this->assertTrue($first['has_more']);
        $next = ActivityLog::list(2, 6, 'denied,blocked,error');
        $this->assertSame([4, 2], self::ids($next));
        $this->assertFalse($next['has_more']);
    }

    public function testAnUnknownOutcomeIsABadRequest(): void
    {
        $this->expectException(BadRequestException::class);
        ActivityLog::list(null, null, 'allowed,rejected');
    }
}
