<?php

namespace DreamFactory\Core\AAuth\Tests\Protocol\Support;

use DreamFactory\Core\AAuth\Protocol\AAuthError;
use DreamFactory\Core\AAuth\Protocol\Jwk;
use DreamFactory\Core\AAuth\Protocol\RefreshableKeyResolver;

/** KeyResolver over a fixed set of issuer keys: [iss => ['keys' => [jwk...], 'meta' => [...]]]. */
final class StaticResolver implements RefreshableKeyResolver
{
    public int $calls = 0;
    public int $freshCalls = 0;
    /** @var array|null keys returned by resolveFresh() (simulates rotation) */
    public ?array $freshIssuers = null;

    public function __construct(public array $issuers)
    {
    }

    public static function single(string $iss, array $jwk, array $meta = []): self
    {
        return new self([$iss => ['keys' => [Jwk::publicOf($jwk)], 'meta' => $meta + ['issuer' => $iss]]]);
    }

    public function resolve(string $iss, string $dwk, ?string $kid): array
    {
        $this->calls++;
        return $this->find($this->issuers, $iss, $kid);
    }

    public function resolveFresh(string $iss, string $dwk, ?string $kid): array
    {
        $this->freshCalls++;
        return $this->find($this->freshIssuers ?? $this->issuers, $iss, $kid);
    }

    private function find(array $issuers, string $iss, ?string $kid): array
    {
        foreach ($issuers[$iss]['keys'] ?? [] as $k) {
            if ($kid === null || ($k['kid'] ?? null) === $kid) {
                return ['jwk' => $k, 'meta' => $issuers[$iss]['meta'] ?? []];
            }
        }
        throw AAuthError::signature('unknown_key', "No key {$kid} for {$iss}");
    }
}
