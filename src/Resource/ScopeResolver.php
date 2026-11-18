<?php

namespace DreamFactory\Core\AAuth\Resource;

use DreamFactory\Core\AAuth\Support\RoleGate;

/**
 * Chooses the scope (= role) that covers a request.
 *
 * covering(): among the candidate scopes, those whose role allows (service, component, verb) the way
 * AccessCheck would decide; the least privileged wins: fewest role_service_access rows, then the
 * lowest total verb bits, then the lowest role id. A request with no service (GET /api/v2) is
 * covered by any candidate.
 */
class ScopeResolver
{
    /** @var \Closure(int, string, ?string, string): bool */
    private \Closure $allows;
    /** @var \Closure(int): array{0:int,1:int} */
    private \Closure $stats;

    public function __construct(?\Closure $allows = null, ?\Closure $stats = null)
    {
        $this->allows = $allows ?? fn (int $roleId, string $service, ?string $component, string $verb) => RoleGate::allows($roleId, $service, $component, $verb);
        $this->stats = $stats ?? fn (int $roleId) => RoleGate::stats($roleId);
    }

    /**
     * Enabled scopes the person server may hand out: all of them for a PS row whose `scopes` is null,
     * otherwise the intersection with its allow-list.
     *
     * @param array|null $psRow aauth_person_servers row (decoded) or null (no filter)
     * @return array<string, array> scope => row
     */
    public function candidates(?array $psRow, ?array $only = null): array
    {
        $enabled = Scopes::enabledByName();
        if ($psRow !== null && is_array($psRow['scopes'] ?? null)) {
            $enabled = array_intersect_key($enabled, array_flip($psRow['scopes']));
        }
        if ($only !== null) {
            $enabled = array_intersect_key($enabled, array_flip($only));
        }

        return $enabled;
    }

    public function covering(?string $service, ?string $component, string $verb, ?array $psRow, ?array $only = null): ?array
    {
        return $this->pick($this->candidates($psRow, $only), $service, $component, $verb);
    }

    /** @param array<string, array> $candidates */
    public function pick(array $candidates, ?string $service, ?string $component, string $verb): ?array
    {
        $service = strtolower((string)$service);
        $matching = [];
        foreach ($candidates as $row) {
            $roleId = (int)$row['role_id'];
            if ($service === '' || ($this->allows)($roleId, $service, $component, strtoupper($verb))) {
                [$count, $bits] = ($this->stats)($roleId);
                $matching[] = [$count, $bits, $roleId, $row];
            }
        }
        if (!$matching) {
            return null;
        }
        usort($matching, fn ($a, $b) => [$a[0], $a[1], $a[2]] <=> [$b[0], $b[1], $b[2]]);

        return $matching[0][3];
    }
}
