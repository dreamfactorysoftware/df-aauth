<?php

namespace DreamFactory\Core\AAuth\Tests\Platform;

use DreamFactory\Core\AAuth\PersonServer\Subjects;

final class SubjectsTest extends TestCase
{
    public function testPairwiseSubjectsAreStablePerResourceAndRecorded(): void
    {
        $a = Subjects::pairwise(1, self::ISSUER);
        $this->assertSame($a, Subjects::pairwise(1, self::ISSUER));
        $this->assertSame(22, strlen($a));
        $this->assertMatchesRegularExpression('/^[A-Za-z0-9_-]+$/', $a);
        $this->assertNotSame($a, Subjects::pairwise(1, 'https://board.example'));
        $this->assertNotSame($a, Subjects::pairwise(2, self::ISSUER));
        $this->assertNull(Subjects::userFor($a));
        $this->assertSame($a, Subjects::record(1, self::ISSUER));
        Subjects::record(1, self::ISSUER);
        $this->assertSame(1, Subjects::userFor($a));
        $this->assertSame(['user_id' => 1, 'resource' => self::ISSUER], Subjects::find($a));
    }
}
