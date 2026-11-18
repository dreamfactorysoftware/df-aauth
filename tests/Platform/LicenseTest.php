<?php

namespace DreamFactory\Core\AAuth\Tests\Platform;

use DreamFactory\Core\AAuth\AgentProvider\AgentProvider;
use DreamFactory\Core\AAuth\Http\Controllers\MetadataController;
use DreamFactory\Core\AAuth\Http\Middleware\AAuthMiddleware;
use DreamFactory\Core\AAuth\Protocol\HttpSignature;
use DreamFactory\Core\AAuth\Protocol\Jwk;
use DreamFactory\Core\AAuth\Resources\AAuth;
use DreamFactory\Core\AAuth\Support\License;
use DreamFactory\Core\AAuth\Support\Settings;
use DreamFactory\Core\Components\InternalServiceRequest;
use DreamFactory\Core\Enums\LicenseLevel;
use Illuminate\Http\Request;
use Illuminate\Session\ArraySessionHandler;
use Illuminate\Session\Store as SessionStore;
use Illuminate\Support\Facades\Facade;
use PHPUnit\Framework\Attributes\DataProvider;
use Symfony\Component\HttpFoundation\Response;

/**
 * AAuth needs a Gold license level, as df-compliance's service reports and restricted admins do:
 * the level comes from DreamFactory's Environment (the highest subscription_required of the
 * installed service types). On other levels the admin API answers 403 and AAuth behaves as off.
 */
final class LicenseTest extends TestCase
{
    protected function setUp(): void
    {
        parent::setUp();
        if (!class_exists(\DreamFactory\Core\Utility\Session::class)) {
            $this->markTestSkipped('needs df-core (the DreamFactory image vendor/)');
        }
        foreach (['Session' => \Illuminate\Support\Facades\Session::class, 'Event' => \Illuminate\Support\Facades\Event::class] as $alias => $facade) {
            if (!class_exists($alias, false)) {
                class_alias($facade, $alias); // df-core's Session helper and RestHandler use the global aliases
            }
        }
        $session = new SessionStore('aauth_test', new ArraySessionHandler(10));
        $session->start();
        $session->put('user', ['id' => 1, 'is_sys_admin' => true, 'name' => 'Admin']);
        $session->put('has_role', false);
        $this->app->instance('session', $session);
        Facade::clearResolvedInstance('session');
        Settings::set('enabled', true);
    }

    protected function tearDown(): void
    {
        License::resolveUsing(static fn () => LicenseLevel::GOLD);
        parent::tearDown();
    }

    /** @param list<string|null> $levels subscription_required of the installed service types */
    private function installServiceTypes(array $levels): void
    {
        if (!class_exists('ServiceManager', false)) {
            class_alias(\DreamFactory\Core\Facades\ServiceManager::class, 'ServiceManager');
        }
        $types = array_map(static fn (?string $level) => new class ($level) {
            public function __construct(private ?string $level)
            {
            }

            public function subscriptionRequired(): ?string
            {
                return $this->level;
            }
        }, $levels);
        $this->app->instance('df.service', new class ($types) {
            public function __construct(private array $types)
            {
            }

            public function getServiceTypes(): array
            {
                return $this->types;
            }
        });
        Facade::clearResolvedInstance('df.service');
        License::resolveUsing(null);
    }

    public static function installs(): array
    {
        return [
            'open source' => [[null, null], false],
            'silver' => [[null, LicenseLevel::SILVER], false],
            'gold' => [[null, LicenseLevel::SILVER, LicenseLevel::GOLD], true],
        ];
    }

    #[DataProvider('installs')]
    public function testTheLicenseLevelComesFromTheInstalledServiceTypes(array $levels, bool $gold): void
    {
        $this->installServiceTypes($levels);
        $this->assertSame($gold, License::isGold());
        $this->assertSame($gold, Settings::enabled(), 'switched on, valid issuer: active only on Gold');
    }

    public function testALevelThatCannotBeReadIsNotGold(): void
    {
        License::resolveUsing(static fn () => throw new \RuntimeException('no service manager'));
        $this->assertFalse(License::isGold());
        $this->assertFalse(Settings::enabled());
    }

    public function testTheAdminApiNeedsGold(): void
    {
        $this->installServiceTypes([LicenseLevel::SILVER]);
        foreach ([['GET', ''], ['GET', 'agents'], ['PATCH', ''], ['POST', 'keys']] as [$verb, $path]) {
            [$status, $body] = $this->call($verb, $path, $verb === 'PATCH' ? ['enabled' => false] : []);
            $this->assertSame(403, $status, "$verb $path");
            $this->assertSame(License::MESSAGE, $body['error']['message'], "$verb $path");
        }
        $this->assertTrue((bool)Settings::get('enabled'), 'nothing changed');

        $this->installServiceTypes([LicenseLevel::GOLD]);
        $this->assertSame(200, $this->call('GET', '')[0]);
    }

    public function testSignedRequestsAndAAuthEndpointsAnswerAsWhenOffWithoutGold(): void
    {
        $key = Jwk::generateEd25519();
        $url = self::ISSUER . '/api/v2/sales/_table/orders';
        $token = AgentProvider::agentToken(Jwk::publicOf($key), 'aauth:reports@df.example.test');
        $send = fn () => (new AAuthMiddleware())->handle($this->request('GET', $url, HttpSignature::sign('GET', $url, $token, $key)), fn () => new Response('next'));

        $this->assertSame(401, $send()->getStatusCode(), 'Gold: AAuth answers (an agent token alone is not enough)');
        $this->assertSame(200, (new MetadataController())->resource($this->request('GET', self::ISSUER . '/.well-known/aauth-resource.json', []))->getStatusCode());
        $rows = $this->db()->table('aauth_activity')->count();

        License::resolveUsing(static fn () => LicenseLevel::OPEN_SOURCE);
        $r = $send();
        $this->assertSame('next', $r->getContent(), 'not Gold: the request goes on to DreamFactory\'s own authentication');
        $this->assertSame($rows, $this->db()->table('aauth_activity')->count(), 'and AAuth records nothing');
        $this->assertSame(404, (new MetadataController())->resource($this->request('GET', self::ISSUER . '/.well-known/aauth-resource.json', []))->getStatusCode());
    }

    /** @return array{0:int,1:mixed} */
    private function call(string $verb, string $path, array $payload = []): array
    {
        $request = new InternalServiceRequest();
        $request->setMethod($verb);
        $request->setPayloadData($payload);
        $response = (new AAuth(['name' => 'aauth']))->handleRequest($request, $path);

        return [$response->getStatusCode(), $response->getContent()];
    }

    private function request(string $method, string $url, array $headers): Request
    {
        $server = ['REMOTE_ADDR' => '198.51.100.7'];
        foreach ($headers as $name => $value) {
            $server['HTTP_' . strtoupper(str_replace('-', '_', $name))] = $value;
        }

        return Request::create($url, $method, [], [], [], $server);
    }
}
