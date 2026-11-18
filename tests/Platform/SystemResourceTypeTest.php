<?php

namespace DreamFactory\Core\AAuth\Tests\Platform;

use DreamFactory\Core\AAuth\Resources\AAuth;
use DreamFactory\Core\AAuth\ServiceProvider;
use DreamFactory\Core\Enums\LicenseLevel;
use DreamFactory\Core\System\Components\SystemResourceManager;

/**
 * The `aauth` system resource is registered as a Gold resource, like the other commercial
 * packages' resources (df-limits, df-compliance, df-masking), so `GET /api/v2/system` and the admin
 * app label it Gold.
 */
final class SystemResourceTypeTest extends TestCase
{
    public function testAauthResourceIsRegisteredAsGold(): void
    {
        $df = new SystemResourceManager($this->app);
        $this->assertNull($df->getResourceType(ServiceProvider::RESOURCE));

        ServiceProvider::addSystemResourceTypes($df);

        $type = $df->getResourceType(ServiceProvider::RESOURCE);
        $this->assertNotNull($type);
        $this->assertSame('aauth', $type->getName());
        $this->assertSame(AAuth::class, $type->getClassName());
        $this->assertSame(LicenseLevel::GOLD, $type->subscriptionRequired());
        $this->assertSame(LicenseLevel::GOLD, $type->toArray()['subscription_required']);
        $this->assertFalse($type->isSingleton());
        $this->assertFalse($type->isReadOnly());
    }

    public function testRegisteringTwiceKeepsOneResource(): void
    {
        $df = new SystemResourceManager($this->app);
        ServiceProvider::addSystemResourceTypes($df);
        $first = $df->getResourceType(ServiceProvider::RESOURCE);
        ServiceProvider::addSystemResourceTypes($df);

        $this->assertSame($first, $df->getResourceType(ServiceProvider::RESOURCE));
        $this->assertSame(1, count(array_filter($df->getResourceTypeNames(), fn ($n) => $n === 'aauth')));
    }
}
