<?php

namespace DreamFactory\Core\AAuth\Tests\Protocol\Support;

use DreamFactory\Core\AAuth\Protocol\AAuthError;

trait Assertions
{
    /** Run $fn and assert it throws AAuthError with $code (and optionally $status). Returns the error. */
    protected function assertAAuthError(string $code, callable $fn, ?int $status = null): AAuthError
    {
        try {
            $fn();
        } catch (AAuthError $e) {
            $this->assertSame($code, $e->error, "Expected {$code}, got {$e->error}: {$e->detail}");
            if ($status !== null) {
                $this->assertSame($status, $e->status);
            }
            return $e;
        }
        $this->fail("Expected AAuthError {$code}, nothing thrown");
    }
}
