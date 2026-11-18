<?php

namespace DreamFactory\Core\AAuth\Protocol;

/**
 * Optional: a resolver that can skip its cache. Jwt::verify() calls resolveFresh() once when a JWT
 * signature fails with a (possibly stale) cached key (§11.4), before reporting invalid_jwt.
 */
interface RefreshableKeyResolver extends KeyResolver
{
    public function resolveFresh(string $iss, string $dwk, ?string $kid): array;
}
