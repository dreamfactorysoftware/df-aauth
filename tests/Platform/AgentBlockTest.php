<?php

namespace DreamFactory\Core\AAuth\Tests\Platform;

use DreamFactory\Core\AAuth\AgentProvider\AgentProvider;
use DreamFactory\Core\AAuth\Http\Controllers\AuthorizeController;
use DreamFactory\Core\AAuth\Http\Middleware\AAuthMiddleware;
use DreamFactory\Core\AAuth\PersonServer\Grants;
use DreamFactory\Core\AAuth\PersonServer\IssuedTokens;
use DreamFactory\Core\AAuth\PersonServer\Minter;
use DreamFactory\Core\AAuth\PersonServer\PsController;
use DreamFactory\Core\AAuth\PersonServer\Subjects;
use DreamFactory\Core\AAuth\Protocol\Discovery;
use DreamFactory\Core\AAuth\Protocol\HttpSignature;
use DreamFactory\Core\AAuth\Protocol\Ids;
use DreamFactory\Core\AAuth\Protocol\Jwk;
use DreamFactory\Core\AAuth\Protocol\Jwt;
use DreamFactory\Core\AAuth\Resource\Agents;
use DreamFactory\Core\AAuth\Resource\PersonServers;
use DreamFactory\Core\AAuth\Resource\ResourceTokens;
use DreamFactory\Core\AAuth\Resource\ScopeResolver;
use DreamFactory\Core\AAuth\Support\AAuth;
use DreamFactory\Core\AAuth\Support\Maintenance;
use DreamFactory\Core\AAuth\Support\Settings;
use DreamFactory\Core\AAuth\Tests\Protocol\Support\FakeFetcher;
use Illuminate\Http\Request;
use Illuminate\Session\ArraySessionHandler;
use Illuminate\Session\Store as SessionStore;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Schema;
use Symfony\Component\HttpFoundation\Response;

/**
 * Who a request belongs to and how blocks follow it. Person and auth tokens from this DreamFactory's
 * person server belong to the agent they were issued for; tokens from an external person server to
 * the signing key's newest agent token. A key bound to ANY blocked agent (every agent id it ever
 * presented an agent token for, or its "jkt:" stand-in) is refused, whatever agent id a new agent
 * token claims and whether the key moved before or after the block, at the resource
 * (AAuthMiddleware), at the person server and at the authorization endpoint, and the admin API names
 * the agents that share a key. An unknown block state (system database unreadable) is refused with
 * 503, never treated as allowed.
 */
final class AgentBlockTest extends TestCase
{
    private const A = 'aauth:reports@df.example.test';
    private const B = 'aauth:fresh-start@df.example.test';
    private const EXT = 'https://ps1.example';

    private array $key;

    protected function setUp(): void
    {
        parent::setUp();
        if (!class_exists(\DreamFactory\Core\Utility\Session::class)) {
            $this->markTestSkipped('needs df-core (the DreamFactory image vendor/)');
        }
        $session = new SessionStore('aauth_test', new ArraySessionHandler(10));
        $session->start();
        $this->app->instance('session', $session);
        if (!class_exists('Session', false)) {
            class_alias(\Illuminate\Support\Facades\Session::class, 'Session');
        }
        Settings::set('enabled', true);
        $this->key = Jwk::generateEd25519();
    }

    /** Sends a signed request through the df.aauth middleware; the API behind it answers 200. */
    private function api(string $jwt, ?array $key = null, string $path = '/api/v2/sales/_table/orders'): Response
    {
        $url = self::ISSUER . $path;
        $h = HttpSignature::sign('GET', $url, $jwt, $key ?? $this->key);

        return (new AAuthMiddleware())->handle($this->request('GET', $url, $h), fn () => new Response('ok'));
    }

    /**
     * GET /api/v2 with a resolver that lets every role through, so an auth token that passes the
     * block check is served ("SERVED"); needs servedSetup().
     */
    private function served(string $jwt): Response
    {
        $url = self::ISSUER . '/api/v2';
        $h = HttpSignature::sign('GET', $url, $jwt, $this->key);
        $mw = new AAuthMiddleware(new ScopeResolver(fn () => true, fn () => [0, 0]));

        return $mw->handle($this->request('GET', $url, $h), fn () => new Response('SERVED', 200));
    }

    /** A role and scope (sales.read) Jordan holds, the session lookups df-core reads, a quiet log. */
    private function servedSetup(): array
    {
        $this->role(1, 'Sales read');
        $this->scope(1, 'sales.read');
        Cache::forever('role:1', ['id' => 1, 'name' => 'Sales read', 'is_active' => true, 'role_service_access_by_role_id' => []]);
        foreach (['lookup', 'app_lookup', 'role_lookup', 'user_lookup'] as $t) {
            Schema::create($t, function ($b) {
                $b->increments('id');
                $b->unsignedInteger('app_id')->nullable();
                $b->unsignedInteger('role_id')->nullable();
                $b->unsignedInteger('user_id')->nullable();
                $b->string('name')->nullable();
                $b->text('value')->nullable();
                $b->boolean('private')->default(false);
                $b->text('description')->nullable();
            });
        }

        return $this->user(5, 'jordan@corp.test', false, [1]);
    }

    /** The pending request's agent record for $sub on the current key (what the person server stores). */
    private function agent(string $sub): array
    {
        return ['jwk' => Jwk::publicOf($this->key), 'sub' => $sub, 'iss' => self::ISSUER, 'name' => null];
    }

    /** An auth token from this DreamFactory's person server, issued for $for. */
    private function authToken(array $user, string $for = self::A): string
    {
        $sub = Subjects::record((int)$user['id'], self::ISSUER);

        return Minter::authToken(['agent' => $this->agent($for), 'resource' => self::ISSUER, 'sub' => $sub], $user, ['sales.read'])['token'];
    }

    /** A signed person server call (POST /aauth/token, GET /aauth/pending/{id}) with an agent token for $sub. */
    private function ps(string $method, string $path, string $sub, string $body = ''): Response
    {
        $url = self::ISSUER . $path;
        $h = HttpSignature::sign($method, $url, $this->agentToken($sub), $this->key, [], $body);
        $req = $this->request($method, $url, $h, $body);
        $ps = new PsController();

        return $path === '/aauth/token' ? $ps->token($req) : $ps->poll($req, substr($path, strlen('/aauth/pending/')));
    }

    private function authorize(string $jwt, string $body): Response
    {
        $url = self::ISSUER . '/aauth/authorize';
        $h = HttpSignature::sign('POST', $url, $jwt, $this->key, [], $body);

        return (new AuthorizeController())->authorize($this->request('POST', $url, $h + ['Content-Type' => 'application/json'], $body));
    }

    private function request(string $method, string $url, array $headers, string $body = ''): Request
    {
        $server = ['REMOTE_ADDR' => '198.51.100.7'];
        foreach ($headers as $name => $value) {
            $name = strtoupper(str_replace('-', '_', $name));
            $server[$name === 'CONTENT_TYPE' ? $name : 'HTTP_' . $name] = $value;
        }

        return Request::create($url, $method, [], [], [], $server, $body);
    }

    private function agentToken(string $sub, ?array $key = null): string
    {
        return AgentProvider::agentToken(Jwk::publicOf($key ?? $this->key), $sub);
    }

    /** A person token from this DreamFactory's person server, issued for $for (the person's "Continue"). */
    private function personToken(string $for = self::A): string
    {
        $row = $this->db()->table('user')->where('id', 5)->first();
        $user = $row ? (array)$row : $this->user(5, 'jordan@corp.test');

        return Minter::personToken(['agent' => $this->agent($for), 'resource' => self::ISSUER], $user)['token'];
    }

    /** Trusts an external person server (sales.read) whose metadata and JWKS discovery serves; returns its key. */
    private function externalPersonServer(): array
    {
        $psKey = Jwk::generateEd25519();
        $this->db()->table(PersonServers::TABLE)->insert(['issuer' => self::EXT, 'name' => 'External', 'is_local' => false, 'enabled' => true,
            'scopes' => json_encode(['sales.read'])]);
        $fetcher = new FakeFetcher([
            self::EXT . '/.well-known/aauth-person.json' => ['issuer' => self::EXT, 'jwks_uri' => self::EXT . '/jwks.json'],
            self::EXT . '/jwks.json' => ['keys' => [Jwk::publicOf($psKey)]],
        ]);
        (new \ReflectionProperty(AAuth::class, 'discovery'))->setValue(null, new Discovery($fetcher, \Closure::fromCallable([AAuth::class, 'resolveLocal'])));

        return $psKey;
    }

    /** A person token from the external person server, bound to the current key (it names no agent). */
    private function externalPersonToken(array $psKey): string
    {
        return Jwt::sign('aa-person+jwt', [
            'iss' => self::EXT, 'dwk' => 'aauth-person.json', 'aud' => self::ISSUER, 'sub' => 'ext-person-1',
            'cnf' => ['jwk' => Jwk::publicOf($this->key)], 'jti' => Ids::random(), 'iat' => time(), 'exp' => time() + 600,
        ], $psKey);
    }

    private function agentRow(string $agentId): array
    {
        return Agents::get((int)$this->db()->table(Agents::TABLE)->where('agent_id', $agentId)->value('id'));
    }

    private function block(string $sub): void
    {
        $id = (int)$this->db()->table(Agents::TABLE)->where('agent_id', $sub)->value('id');
        Agents::patch($id, ['status' => 'blocked']);
    }

    /** [agent_id, outcome, status] of the newest activity row. */
    private function lastActivity(): array
    {
        $a = $this->db()->table('aauth_activity')->orderByDesc('id')->first();

        return [$a->agent_id, $a->outcome, (int)$a->status];
    }

    private static function problem(Response $r): array
    {
        return json_decode((string)$r->getContent(), true) ?: [];
    }

    public function testAKeyBoundToABlockedAgentCannotBeRebound(): void
    {
        $jkt = Jwk::thumbprint(Jwk::publicOf($this->key));
        $this->assertSame(401, $this->api($this->agentToken(self::A))->getStatusCode(), 'agent token: person token required');
        $person = $this->personToken();
        $this->block(self::A);

        // the agent provider mints an agent token with a new sub for the same key
        $r = $this->api($this->agentToken(self::B));
        $this->assertSame(403, $r->getStatusCode());
        $this->assertSame('agent_blocked', self::problem($r)['error']);
        $this->assertSame([self::A, 'blocked', 403], $this->lastActivity());
        $this->assertSame(0, $this->db()->table(Agents::TABLE)->where('agent_id', self::B)->count(), 'the new sub is not recorded as an agent');

        // ... so the person token issued to that key while it was the blocked agent stays refused
        Cache::flush();
        $this->assertSame(self::A, Agents::identityForKey($jkt)['agent_id'], 'the binding is durable');
        $r = $this->api($person);
        $this->assertSame(403, $r->getStatusCode());
        $this->assertSame('agent_blocked', self::problem($r)['error']);
        $this->assertSame([self::A, 'blocked', 403], $this->lastActivity());

        // the honest limit: a genuinely new key under a new id is a new agent (no grants, fresh approval)
        $other = Jwk::generateEd25519();
        $this->assertSame(401, $this->api($this->agentToken(self::B, $other), $other)->getStatusCode());

        // unblocked, the key may move again
        Agents::patch((int)$this->db()->table(Agents::TABLE)->where('agent_id', self::A)->value('id'), ['status' => 'allowed']);
        $this->assertSame(401, $this->api($this->agentToken(self::B))->getStatusCode());
        $this->assertSame(self::B, Agents::identityForKey($jkt)['agent_id']);
    }

    public function testRememberKeyNeverMovesAKeyAwayFromABlockedAgent(): void
    {
        $this->assertSame(self::A, Agents::rememberKey('JKT-1', self::A, self::ISSUER, 'Reports')['agent_id']);
        Agents::seen(self::A, self::ISSUER, 'Reports');
        $this->assertSame(self::B, Agents::rememberKey('JKT-1', self::B, self::ISSUER, 'Fresh')['agent_id'], 'an allowed agent\'s key may move');
        $this->assertSame(self::A, Agents::rememberKey('JKT-1', self::A, self::ISSUER, 'Reports')['agent_id']);
        $this->block(self::A);
        foreach ([true, false] as $cached) {
            if (!$cached) {
                Cache::flush();
            }
            foreach ([self::B, 'aauth:third@df.example.test'] as $sub) {
                $bound = Agents::rememberKey('JKT-1', $sub, self::ISSUER, 'Fresh');
                $this->assertSame(['agent_id' => self::A, 'issuer' => self::ISSUER, 'name' => 'Reports'], $bound);
            }
            $this->assertSame(self::A, Agents::identityForKey('JKT-1')['agent_id']);
            $this->assertSame([self::A, self::B], $this->db()->table(Agents::KEYS)->where('jkt', 'JKT-1')->orderBy('id')->pluck('agent_id')->all(),
                'no new binding while the key is blocked');
        }
        $this->assertSame(self::A, Agents::rememberKey('JKT-1', self::A, self::ISSUER, 'Reports v2')['agent_id'], 'its own agent may rename itself');
        $this->assertSame('Reports v2', Agents::identityForKey('JKT-1')['name']);

        // pruning never releases a blocked agent's key, however long it has been idle
        $this->app['config']->set('df-aauth.activity_retention_days', 30);
        Agents::rememberKey('JKT-2', 'aauth:idle@df.example.test', self::ISSUER, null);
        $this->db()->table(Agents::KEYS)->update(['last_seen_at' => now()->subDays(40)]);
        $this->assertSame(2, Maintenance::agentKeys(true), 'the idle key, and JKT-1\'s older binding to the allowed B');
        $this->assertSame(2, Agents::pruneKeys());
        $this->assertSame([['JKT-1', self::A]], $this->db()->table(Agents::KEYS)->get(['jkt', 'agent_id'])->map(fn ($r) => [$r->jkt, $r->agent_id])->all());
    }

    public function testUnknownBlockStateFailsClosedAtTheResource(): void
    {
        $person = $this->personToken();
        $this->assertSame(401, $this->api($this->agentToken(self::A))->getStatusCode());
        Schema::drop(Agents::TABLE);

        foreach ([$this->agentToken(self::A), $person] as $jwt) {
            $r = $this->api($jwt);
            $this->assertSame(503, $r->getStatusCode());
            $this->assertSame('temporarily_unavailable', self::problem($r)['error']);
            $this->assertSame('30', $r->headers->get('Retry-After'));
            $this->assertSame(['error', 503], array_slice($this->lastActivity(), 1));
        }

        // the key binding itself unreadable: no "jkt:..." stand-in that nobody can have blocked
        Cache::flush();
        Schema::drop(Agents::KEYS);
        $this->assertSame(503, $this->api($person)->getStatusCode());
    }

    public function testThePersonServerRefusesBlockedAndUnknownAgents(): void
    {
        $ps = new PsController();
        $send = function (string $sub) use ($ps): Response {
            $url = self::ISSUER . '/aauth/person';
            $body = json_encode(['resource' => self::ISSUER, 'capabilities' => ['interaction']]);
            $h = HttpSignature::sign('POST', $url, $this->agentToken($sub), $this->key, [], $body);

            return $ps->person($this->request('POST', $url, $h, $body));
        };
        $this->assertSame(202, $send(self::A)->getStatusCode());
        Agents::seen(self::A, self::ISSUER, null);
        $this->block(self::A);

        $r = $send(self::B);
        $this->assertSame(403, $r->getStatusCode(), 'a new sub for a blocked agent\'s key');
        $this->assertSame('agent_blocked', self::problem($r)['error']);
        $this->assertSame(self::A, Agents::identityForKey(Jwk::thumbprint(Jwk::publicOf($this->key)))['agent_id']);

        Schema::drop(Agents::TABLE);
        $r = $send(self::A);
        $this->assertSame(503, $r->getStatusCode());
        $this->assertSame('temporarily_unavailable', self::problem($r)['error']);
        $this->assertSame('30', $r->headers->get('Retry-After'));
    }

    public function testAKeyThatMovedBeforeTheBlockStaysBlocked(): void
    {
        $user = $this->servedSetup();
        $this->assertSame(401, $this->api($this->agentToken(self::A))->getStatusCode());
        $auth = $this->authToken($user); // issued while the key was A's
        $this->assertSame('SERVED', $this->served($auth)->getContent());

        // the agent moves its key to another sub with one agent token, then the admin blocks A
        $this->assertSame(401, $this->api($this->agentToken(self::B))->getStatusCode());
        $this->assertSame([self::B, 'person_required', 401], $this->lastActivity());
        $this->block(self::A);

        $r = $this->served($auth);
        $this->assertSame(403, $r->getStatusCode(), 'A\'s token is refused although the key now names B');
        $this->assertSame('agent_blocked', self::problem($r)['error']);
        $this->assertSame([self::A, 'blocked', 403], $this->lastActivity());
        $r = $this->api($this->agentToken(self::B));
        $this->assertSame(403, $r->getStatusCode(), 'and so is B on that key');
        $this->assertSame([self::A, 'blocked', 403], $this->lastActivity());
    }

    /**
     * The agent holds an "Always allow" grant under A, takes auth tokens from DreamFactory's person
     * server as A, and moves its key to throwaway subs (through the person server, which logs no
     * activity) before and after every API request. The API requests are A's, the agent the tokens
     * were issued for; every id the key used is listed and names the others it shares the key with,
     * and blocking any of them stops the key.
     */
    public function testARotatingKeyIsStoppedByBlockingTheAgentsItUsed(): void
    {
        $user = $this->servedSetup();
        $jkt = Jwk::thumbprint(Jwk::publicOf($this->key));
        Grants::save(5, self::ISSUER, 'DF', self::ISSUER, self::A, 'Reports', ['sales.read']);
        $person = $this->personToken(self::A);
        $pc = Jwt::decode($person)['payload'];
        $rt = ResourceTokens::mint($pc, self::ISSUER, $jkt, 'sales.read');

        $r = $this->ps('POST', '/aauth/token', self::A, json_encode(['resource_token' => $rt, 'presented_token' => $person]));
        $this->assertSame(200, $r->getStatusCode(), (string)$r->getContent());
        $auth = json_decode((string)$r->getContent(), true)['auth_token'];
        $this->assertSame(404, $this->ps('GET', '/aauth/pending/nopenope', 'aauth:w1@df.example.test')->getStatusCode());
        $this->assertSame('SERVED', $this->served($auth)->getContent());
        $this->assertSame([self::A, 'allowed', 200], $this->lastActivity(), 'the agent the auth token was issued for, not the latest sub');
        $this->assertSame(404, $this->ps('GET', '/aauth/pending/nopenope', 'aauth:v1@df.example.test')->getStatusCode());

        $listed = array_column(Agents::list(), 'request_count', 'agent_id');
        ksort($listed);
        $this->assertSame([self::A => 1, 'aauth:v1@df.example.test' => 0, 'aauth:w1@df.example.test' => 0], $listed,
            'every id the key used is listed; person server calls are not counted as requests');
        $this->assertSame(['aauth:v1@df.example.test', 'aauth:w1@df.example.test'], array_column($this->agentRow(self::A)['shares_key_with'], 'agent_id'));

        // the admin blocks another id that shares the key: every id the key used is refused
        $this->block('aauth:w1@df.example.test');
        $r = $this->served($auth);
        $this->assertSame(403, $r->getStatusCode(), (string)$r->getContent());
        $this->assertSame(['aauth:w1@df.example.test', 'blocked', 403], $this->lastActivity(), 'logged under the blocked id');
        $this->assertSame(403, $this->ps('GET', '/aauth/pending/nopenope', 'aauth:u1@df.example.test')->getStatusCode());
        $this->assertSame(403, $this->ps('POST', '/aauth/token', self::A, json_encode(['resource_token' => $rt, 'presented_token' => $person]))->getStatusCode());

        // a fresh key under A (which holds the grant) is a new key, but A is listed and can be blocked
        $this->block(self::A);
        $this->key = Jwk::generateEd25519();
        $r = $this->ps('GET', '/aauth/pending/nopenope', self::A);
        $this->assertSame(403, $r->getStatusCode());
        $this->assertSame('agent_blocked', self::problem($r)['error']);
    }

    /**
     * The grant holder A also binds its key to a second sub at the person server, so the key's
     * newest binding is W1. Activity names A (the auth token was issued for A), so the admin blocks
     * A, and a new key under A gets nothing from A's standing grant, whichever sub it is bound to.
     */
    public function testBlockingTheAgentInActivityStopsTheGrantHolderOnEveryKey(): void
    {
        $user = $this->servedSetup();
        Grants::save(5, self::ISSUER, 'DF', self::ISSUER, self::A, 'Reports', ['sales.read']);

        // one round: the identity step (asked for by a throwaway id), an auth token from A's grant,
        // the key moved to W1, the API call
        $jkt = Jwk::thumbprint(Jwk::publicOf($this->key));
        $this->assertSame(404, $this->ps('GET', '/aauth/pending/nopenope', 'aauth:w0@df.example.test')->getStatusCode(), 'its POST /aauth/person');
        $person = $this->personToken('aauth:w0@df.example.test');
        $rt = ResourceTokens::mint(Jwt::decode($person)['payload'], self::ISSUER, $jkt, 'sales.read');
        $r = $this->ps('POST', '/aauth/token', self::A, json_encode(['resource_token' => $rt, 'presented_token' => $person]));
        $this->assertSame(200, $r->getStatusCode(), 'the standing grant answers at once: ' . $r->getContent());
        $auth = json_decode((string)$r->getContent(), true)['auth_token'];
        $this->assertSame(404, $this->ps('GET', '/aauth/pending/nopenope', 'aauth:w1@df.example.test')->getStatusCode());
        $this->assertSame('SERVED', $this->served($auth)->getContent());

        $this->assertSame([self::A, 'allowed', 200], $this->lastActivity(), 'Activity names the grant holder, not the throwaway id');
        $wire = $this->agentRow(self::A);
        $this->assertSame(1, $wire['request_count']);
        $this->assertSame(['aauth:w0@df.example.test', 'aauth:w1@df.example.test'], array_column($wire['shares_key_with'], 'agent_id'),
            'and lists the ids that share its key');
        $this->assertSame([self::A, 'aauth:w0@df.example.test'], array_column($this->agentRow('aauth:w1@df.example.test')['shares_key_with'], 'agent_id'));

        // the admin blocks the agent its Activity shows
        $this->block(self::A);
        $r = $this->served($auth);
        $this->assertSame(403, $r->getStatusCode());
        $this->assertSame([self::A, 'blocked', 403], $this->lastActivity());

        // a new key under the grant holder, bound to W2 first: the grant serves nothing
        $this->key = Jwk::generateEd25519();
        $jkt = Jwk::thumbprint(Jwk::publicOf($this->key));
        $person = $this->personToken('aauth:w2@df.example.test');
        $rt = ResourceTokens::mint(Jwt::decode($person)['payload'], self::ISSUER, $jkt, 'sales.read');
        $this->assertSame(404, $this->ps('GET', '/aauth/pending/nopenope', 'aauth:w2@df.example.test')->getStatusCode());
        $r = $this->ps('POST', '/aauth/token', self::A, json_encode(['resource_token' => $rt, 'presented_token' => $person]));
        $this->assertSame(403, $r->getStatusCode(), (string)$r->getContent());
        $this->assertSame('agent_blocked', self::problem($r)['error']);
        $r = $this->ps('POST', '/aauth/token', 'aauth:w2@df.example.test', json_encode(['resource_token' => $rt, 'presented_token' => $person]));
        $this->assertSame(403, $r->getStatusCode(), 'presenting A\'s agent token tied this key to A: refused under any id now');

        // the honest limit: a new key under a new id is a new agent, and it holds no grant
        $this->key = Jwk::generateEd25519();
        $person = $this->personToken('aauth:w3@df.example.test');
        $rt = ResourceTokens::mint(Jwt::decode($person)['payload'], self::ISSUER, Jwk::thumbprint(Jwk::publicOf($this->key)), 'sales.read');
        $r = $this->ps('POST', '/aauth/token', 'aauth:w3@df.example.test', json_encode(['resource_token' => $rt, 'presented_token' => $person]));
        $this->assertSame(202, $r->getStatusCode(), 'the person is asked: ' . $r->getContent());
        $this->assertSame(0, $this->db()->table('aauth_activity')->where('outcome', 'allowed')->where('agent_id', '<>', self::A)->count(),
            'no request was ever served under another id');
    }

    /** A token that claims to be ours but was never recorded is refused (401); an unreadable record fails closed (503). */
    public function testATokenOfThisPersonServerWithoutARecordIsRefused(): void
    {
        $user = $this->servedSetup();
        $this->assertSame(401, $this->api($this->agentToken(self::A))->getStatusCode());
        $auth = $this->authToken($user);
        $this->assertSame('SERVED', $this->served($auth)->getContent());
        $this->db()->table(IssuedTokens::TABLE)->where('jti', Jwt::decode($auth)['payload']['jti'])->delete();

        $r = $this->served($auth);
        $this->assertSame(401, $r->getStatusCode());
        $this->assertSame('invalid_jwt', self::problem($r)['error']);
        $this->assertStringContainsString('invalid_jwt', (string)$r->headers->get('Signature-Error'));
        $this->assertSame([null, 'error', 401], $this->lastActivity());

        $person = $this->personToken();
        $this->db()->table(IssuedTokens::TABLE)->where('jti', Jwt::decode($person)['payload']['jti'])->delete();
        $r = $this->authorize($person, json_encode(['scope' => 'sales.read']));
        $this->assertSame(401, $r->getStatusCode(), 'the authorization endpoint too');
        $this->assertSame('/aauth/authorize', $this->db()->table('aauth_activity')->orderByDesc('id')->value('path'));

        $auth = $this->authToken($user);
        Schema::drop(IssuedTokens::TABLE);
        $r = $this->served($auth);
        $this->assertSame(503, $r->getStatusCode());
        $this->assertSame('temporarily_unavailable', self::problem($r)['error']);
    }

    /** Tokens from an external person server name no agent: their requests follow the key's newest agent token. */
    public function testExternalPersonServerTokensAreAttributedThroughTheKey(): void
    {
        $this->servedSetup();
        $person = $this->externalPersonToken($this->externalPersonServer());
        $standIn = 'jkt:' . substr(Jwk::thumbprint(Jwk::publicOf($this->key)), 0, 12);

        $this->assertSame(401, $this->served($person)->getStatusCode());
        $this->assertSame([$standIn, 'auth_required', 401], $this->lastActivity(), 'a key never seen with an agent token');
        $this->assertSame(401, $this->api($this->agentToken(self::A))->getStatusCode());
        $this->served($person);
        $this->assertSame([self::A, 'auth_required', 401], $this->lastActivity());
        $this->assertSame(401, $this->api($this->agentToken(self::B))->getStatusCode());
        $this->served($person);
        $this->assertSame([self::B, 'auth_required', 401], $this->lastActivity(), 'the newest binding');
        $this->assertSame([self::B, $standIn], array_column($this->agentRow(self::A)['shares_key_with'], 'agent_id'));
    }

    /** The admin API's agent records name the other agents that share a signing key, so all of them can be blocked. */
    public function testTheAdminApiListsTheAgentsThatShareAKey(): void
    {
        [$k1, $k2, $k3] = array_map(fn () => Jwk::thumbprint(Jwk::publicOf(Jwk::generateEd25519())), [1, 2, 3]);
        $c = 'aauth:third@df.example.test';
        $other = 'aauth:other@df.example.test';
        $standIn = 'jkt:' . substr($k3, 0, 12);
        foreach ([[$k1, self::A, 'Reports'], [$k1, self::B, 'Fresh'], [$k2, $other, null], [$k3, $c, null]] as [$jkt, $id, $name]) {
            Agents::rememberKey($jkt, $id, self::ISSUER, $name);
            Agents::seen($id, self::ISSUER, $name);
        }
        Agents::seen($standIn, '', null); // the key presented an external person server's token before its agent token

        $byId = array_column(Agents::list(), null, 'agent_id');
        $this->assertSame([self::B], array_column($byId[self::A]['shares_key_with'], 'agent_id'));
        $this->assertSame([self::A], array_column($byId[self::B]['shares_key_with'], 'agent_id'));
        $this->assertSame([], $byId[$other]['shares_key_with']);
        $this->assertSame([$standIn], array_column($byId[$c]['shares_key_with'], 'agent_id'));
        $this->assertSame([$c], array_column($byId[$standIn]['shares_key_with'], 'agent_id'));
        $this->assertSame(['id' => $byId[self::B]['id'], 'agent_id' => self::B, 'issuer' => self::ISSUER, 'name' => 'Fresh', 'status' => 'allowed'],
            $byId[self::A]['shares_key_with'][0], 'what blocking it takes: the row id');

        $this->assertSame($byId[self::A]['shares_key_with'], Agents::get($byId[self::A]['id'])['shares_key_with']);
        $this->assertSame([$c], array_column(Agents::get($byId[$standIn]['id'])['shares_key_with'], 'agent_id'));
        $this->assertSame([self::A], array_column(Agents::patch($byId[self::B]['id'], ['status' => 'blocked'])['shares_key_with'], 'agent_id'));
        $this->assertSame('blocked', Agents::get($byId[self::A]['id'])['shares_key_with'][0]['status']);
    }

    /**
     * A signing key presents agent tokens for at most MAX_AGENTS_PER_KEY agent ids: one more is refused
     * (403 too_many_agents) at the resource, the person server and the authorization endpoint, without
     * a binding or an agent row; the ids it already used keep working.
     */
    public function testAKeyPresentsAgentTokensForAtMostTwentyAgentIds(): void
    {
        $jkt = Jwk::thumbprint(Jwk::publicOf($this->key));
        for ($i = 0; $i < Agents::MAX_AGENTS_PER_KEY; $i++) {
            $this->assertSame(401, $this->api($this->agentToken("aauth:w$i@df.example.test"))->getStatusCode());
        }
        $this->assertSame(Agents::MAX_AGENTS_PER_KEY, $this->db()->table(Agents::KEYS)->where('jkt', $jkt)->count());

        $r = $this->api($this->agentToken('aauth:one-more@df.example.test'));
        $this->assertSame(403, $r->getStatusCode());
        $this->assertSame('too_many_agents', self::problem($r)['error']);
        $row = $this->db()->table('aauth_activity')->orderByDesc('id')->first();
        $this->assertSame([null, 'error', 403], [$row->agent_id, $row->outcome, (int)$row->status]);
        $this->assertStringStartsWith('too_many_agents: This signing key has already presented agent tokens for 20 agent ids', (string)$row->detail);
        $this->assertSame(0, $this->db()->table(Agents::TABLE)->where('agent_id', 'aauth:one-more@df.example.test')->count());
        $this->assertSame(Agents::MAX_AGENTS_PER_KEY, $this->db()->table(Agents::KEYS)->where('jkt', $jkt)->count());

        $r = $this->ps('GET', '/aauth/pending/nopenope', 'aauth:one-more@df.example.test');
        $this->assertSame(403, $r->getStatusCode(), 'a refusal at the person server, not 503');
        $this->assertSame('too_many_agents', self::problem($r)['error']);
        $r = $this->authorize($this->agentToken('aauth:one-more@df.example.test'), json_encode(['scope' => 'sales.read']));
        $this->assertSame(403, $r->getStatusCode());
        $this->assertSame('too_many_agents', self::problem($r)['error']);

        $this->assertSame(401, $this->api($this->agentToken('aauth:w3@df.example.test'))->getStatusCode(), 'an id it used still works');
        $this->key = Jwk::generateEd25519();
        $this->assertSame(401, $this->api($this->agentToken('aauth:one-more@df.example.test'))->getStatusCode(), 'and so does a new key');
    }

    /**
     * One key bound to 500 agent ids (as before the per-key limit): the list names at most LIST_SHARES
     * per agent and says it is cut, in bounded time and memory, and one agent's record names them all.
     */
    public function testTheAgentListStaysSmallWhenOneKeyIsBoundToManyAgents(): void
    {
        $jkt = Jwk::thumbprint(Jwk::publicOf(Jwk::generateEd25519()));
        $n = 500;
        $now = now();
        foreach (array_chunk(range(0, $n - 1), 100) as $chunk) {
            $this->db()->table(Agents::KEYS)->insert(array_map(fn ($i) => ['jkt' => $jkt, 'agent_id' => sprintf('aauth:x%03d@df.example.test', $i),
                'issuer' => self::ISSUER, 'name' => null, 'last_seen_at' => $now], $chunk));
            $this->db()->table(Agents::TABLE)->insert(array_map(fn ($i) => ['agent_id' => sprintf('aauth:x%03d@df.example.test', $i),
                'issuer' => self::ISSUER, 'status' => 'allowed', 'first_seen_at' => $now, 'last_seen_at' => $now, 'request_count' => 1], $chunk));
        }
        $this->db()->table(Agents::TABLE)->insert(['agent_id' => 'aauth:alone@df.example.test', 'issuer' => self::ISSUER, 'status' => 'allowed',
            'first_seen_at' => $now, 'last_seen_at' => $now, 'request_count' => 1]);

        gc_collect_cycles();
        $before = memory_get_usage();
        memory_reset_peak_usage();
        $t = microtime(true);
        $list = Agents::list();
        $seconds = microtime(true) - $t;
        $grew = memory_get_peak_usage() - $before;
        $this->assertCount($n + 1, $list);
        $entries = 0;
        foreach ($list as $a) {
            $entries += count($a['shares_key_with']);
            if ($a['agent_id'] === 'aauth:alone@df.example.test') {
                $this->assertSame([[], false], [$a['shares_key_with'], $a['shares_key_with_truncated']]);
                continue;
            }
            $this->assertCount(Agents::LIST_SHARES, $a['shares_key_with']);
            $this->assertTrue($a['shares_key_with_truncated']);
            $this->assertNotContains($a['agent_id'], array_column($a['shares_key_with'], 'agent_id'));
        }
        $this->assertSame($n * Agents::LIST_SHARES, $entries, 'linear: 249,500 entries without the limit');
        $this->assertLessThan(48 * 1048576, $grew, 'about 100 MB without the limit');
        $this->assertLessThan(10.0, $seconds);
        $this->assertLessThan(4 * 1048576, strlen(json_encode(['resource' => $list])), 'about 28 MB without the limit');

        $one = Agents::get((int)$this->db()->table(Agents::TABLE)->where('agent_id', 'aauth:x007@df.example.test')->value('id'));
        $this->assertCount($n - 1, $one['shares_key_with'], 'one agent\'s record names every agent on its keys');
        $this->assertFalse($one['shares_key_with_truncated']);
        $this->assertSame('aauth:x000@df.example.test', $one['shares_key_with'][0]['agent_id'], 'sorted by agent id');
    }

    /** MySQL's utf8mb4_unicode_ci (and SQL Server's default) emulated with SQLite NOCASE columns. */
    private function caseInsensitiveAgentTables(): void
    {
        Schema::drop(Agents::TABLE);
        Schema::drop(Agents::KEYS);
        Schema::create(Agents::TABLE, function ($t) {
            $t->increments('id');
            $t->string('agent_id', 255)->collation('NOCASE');
            $t->string('issuer', 255)->default('')->collation('NOCASE');
            $t->string('name', 255)->nullable();
            $t->string('status', 16)->default('allowed');
            $t->timestamp('first_seen_at')->nullable();
            $t->timestamp('last_seen_at')->nullable();
            $t->unsignedInteger('request_count')->default(0);
            $t->unique(['agent_id', 'issuer']);
        });
        Schema::create(Agents::KEYS, function ($t) {
            $t->increments('id');
            $t->string('jkt', 64)->collation('NOCASE');
            $t->string('agent_id', 255)->collation('NOCASE');
            $t->string('issuer', 255)->default('')->collation('NOCASE');
            $t->string('name', 255)->nullable();
            $t->timestamp('last_seen_at')->nullable();
            $t->unique(['jkt', 'agent_id', 'issuer']);
        });
    }

    /**
     * On a case-insensitive collation an agent id that differs only in case is the same agent to the
     * database (its row, its grants, its block), so shares_key_with links it the same way.
     */
    public function testSharesKeyWithMatchesAgentIdsAsTheDatabaseDoes(): void
    {
        $this->caseInsensitiveAgentTables();
        [$k0, $k1] = array_map(fn () => Jwk::thumbprint(Jwk::publicOf(Jwk::generateEd25519())), [0, 1]);
        $variant = 'aauth:Reports@df.example.test';
        $w1 = 'aauth:w1@df.example.test';
        foreach ([[$k0, self::A], [$k1, $variant], [$k1, $w1]] as [$jkt, $id]) {
            Agents::rememberKey($jkt, $id, self::ISSUER, null);
            Agents::seen($id, self::ISSUER, null);
        }
        $this->assertSame(2, $this->db()->table(Agents::TABLE)->count(), 'the variant is A\'s row');
        $this->assertSame($variant, $this->db()->table(Agents::KEYS)->where('jkt', $k1)->where('agent_id', '<>', $w1)->value('agent_id'), 'stored as presented');

        $byId = array_column(Agents::list(), null, 'agent_id');
        $this->assertSame([$w1], array_column($byId[self::A]['shares_key_with'], 'agent_id'));
        $this->assertSame([self::A], array_column($byId[$w1]['shares_key_with'], 'agent_id'));
        $this->assertSame([$w1], array_column(Agents::get($byId[self::A]['id'])['shares_key_with'], 'agent_id'));
        $this->assertSame([self::A], array_column(Agents::get($byId[$w1]['id'])['shares_key_with'], 'agent_id'));
        $this->block(self::A);
        $this->assertSame(self::A, strtolower(Agents::identityForKey($k1)['agent_id']), 'and the block reaches the key');
    }

    /** Requests the key made only with an external person server's tokens are the "jkt:" stand-in's; its block holds. */
    public function testAStandInBlockIsNotLiftedByAnAgentToken(): void
    {
        $this->servedSetup();
        $jkt = Jwk::thumbprint(Jwk::publicOf($this->key));
        $standIn = 'jkt:' . substr($jkt, 0, 12);
        $person = $this->externalPersonToken($this->externalPersonServer());
        $this->assertSame(401, $this->served($person)->getStatusCode());
        $this->assertSame([$standIn, 'auth_required', 401], $this->lastActivity());
        $this->block($standIn);

        $r = $this->api($this->agentToken(self::B));
        $this->assertSame(403, $r->getStatusCode(), 'an agent token with a new sub does not lift it');
        $this->assertSame([$standIn, 'blocked', 403], $this->lastActivity());
        $this->assertSame(403, $this->served($person)->getStatusCode());
        $this->assertSame(403, $this->ps('GET', '/aauth/pending/nopenope', self::B)->getStatusCode(), 'nor at the person server');
        $this->assertSame(0, $this->db()->table(Agents::KEYS)->where('jkt', $jkt)->count(), 'no binding to B was recorded');
        $this->assertSame(0, $this->db()->table(Agents::TABLE)->where('agent_id', self::B)->count());
    }

    /** Every binding the key ever had counts, whichever is the newest, at the resource and the person server. */
    public function testEveryBindingOfAKeyIsChecked(): void
    {
        $jkt = Jwk::thumbprint(Jwk::publicOf($this->key));
        Agents::rememberKey($jkt, self::A, self::ISSUER, null);
        Agents::seen(self::A, self::ISSUER, null);
        Agents::rememberKey($jkt, self::B, self::ISSUER, null);
        Agents::rememberKey($jkt, self::A, self::ISSUER, 'Reports'); // A is the newest binding again
        $this->assertSame(2, $this->db()->table(Agents::KEYS)->where('jkt', $jkt)->count());
        Agents::seen(self::B, self::ISSUER, null);
        $this->block(self::B); // an older binding

        $this->assertSame(self::B, Agents::identityForKey($jkt)['agent_id']);
        $r = $this->api($this->agentToken('aauth:third@df.example.test'));
        $this->assertSame(403, $r->getStatusCode());
        $this->assertSame([self::B, 'blocked', 403], $this->lastActivity());
        $this->assertSame(403, $this->api($this->agentToken(self::A))->getStatusCode(), 'A on that key too');
        $this->assertSame(403, $this->ps('GET', '/aauth/pending/nopenope', 'aauth:third@df.example.test')->getStatusCode());
        $this->assertSame(0, $this->db()->table(Agents::KEYS)->where('agent_id', 'aauth:third@df.example.test')->count());
        // a stale cache entry from an older release decides nothing
        Cache::put('aauth:jkt:' . $jkt, ['agent_id' => 'aauth:third@df.example.test', 'issuer' => self::ISSUER, 'name' => null], 3600);
        $this->assertSame(403, $this->api($this->personToken())->getStatusCode());
    }

    public function testTheAuthorizationEndpointRefusesBlockedAndUnknownAgents(): void
    {
        $this->servedSetup();
        $this->assertSame(401, $this->api($this->agentToken(self::A))->getStatusCode());
        $person = $this->personToken();
        $r = $this->authorize($person, json_encode(['scope' => 'sales.read']));
        $this->assertSame(200, $r->getStatusCode(), (string)$r->getContent());
        $this->assertArrayHasKey('resource_token', self::problem($r));

        $this->block(self::A);
        $r = $this->authorize($person, json_encode(['scope' => 'sales.read', 'n' => 2]));
        $this->assertSame(403, $r->getStatusCode());
        $this->assertSame('agent_blocked', self::problem($r)['error']);
        $this->assertSame([self::A, 'blocked', 403], $this->lastActivity());
        $this->assertSame('/aauth/authorize', $this->db()->table('aauth_activity')->orderByDesc('id')->value('path'));
        $r = $this->authorize($this->agentToken(self::B), json_encode(['scope' => 'sales.read', 'n' => 3]));
        $this->assertSame(403, $r->getStatusCode(), 'an agent token with a new sub too');

        Schema::drop(Agents::TABLE);
        $r = $this->authorize($person, json_encode(['scope' => 'sales.read', 'n' => 4]));
        $this->assertSame(503, $r->getStatusCode());
        $this->assertSame('temporarily_unavailable', self::problem($r)['error']);
        $this->assertSame('30', $r->headers->get('Retry-After'));
    }
}
