<?php

namespace DreamFactory\Core\AAuth\Tests\Platform;

use DreamFactory\Core\AAuth\PersonServer\InteractController;
use DreamFactory\Core\AAuth\PersonServer\Pending;
use DreamFactory\Core\AAuth\Support\ClientIp;
use DreamFactory\Core\AAuth\Support\Settings;
use DreamFactory\Core\AAuth\Support\Store;
use DreamFactory\Core\AAuth\Support\Throttle;
use Illuminate\Http\Request;
use Illuminate\Session\ArraySessionHandler;
use Illuminate\Session\Store as SessionStore;
use Symfony\Component\HttpFoundation\Response;

/**
 * Single-use interaction codes are claimed by the first browser that acts on the request (a POST, or
 * the "next" card), never by opening the link: chat link previews and mail scanners fetch links
 * before the person does and must not take the code. The claimant owns the request and its outcome:
 * a browser that only opened the link is told the code was used, also after the request was decided.
 */
final class ConsentClaimTest extends TestCase
{
    private const USED = 'This code was already used in another browser. Ask the agent for a new code.';

    private InteractController $c;

    protected function setUp(): void
    {
        parent::setUp();
        $this->app->instance('session', $this->browser());
        $this->user(5, 'jordan@corp.test');
        Settings::set('enabled', true);
        $this->c = new InteractController();
    }

    private function browser(?int $uid = null): SessionStore
    {
        $s = new SessionStore('aauth_test', new ArraySessionHandler(10));
        $s->start();
        if ($uid !== null) {
            $s->put('aauth_ps.uid', $uid);
        }

        return $s;
    }

    private function request(SessionStore $browser, string $method, string $uri, array $params = []): Request
    {
        $r = Request::create('https://df.example.test' . $uri, $method, $params, [], [], ['REMOTE_ADDR' => '198.51.100.7']);
        $r->setLaravelSession($browser);

        return $r;
    }

    private function pending(string $kind = 'person', array $extra = []): array
    {
        return Pending::create($kind, ['sub' => 'aauth:reports@agent.example', 'iss' => 'https://agent.example', 'jkt' => 'J',
            'jwk' => ['kty' => 'OKP', 'crv' => 'Ed25519', 'x' => 'AAAA'], 'name' => 'Reports agent',
            'callback_endpoint' => 'https://agent.example/callback'], self::ISSUER, 'DF', $extra);
    }

    private function open(SessionStore $browser, array $p, string $query = ''): Response
    {
        return $this->c->show($this->request($browser, 'GET', '/aauth/interact?code=' . Pending::displayCode($p['code']) . $query));
    }

    private static function state(Response $r): string
    {
        preg_match('/data-aauth-state="([a-z]+)"/', (string)$r->getContent(), $m);

        return $m[1] ?? '';
    }

    public function testOpeningTheLinkNeverClaimsTheCode(): void
    {
        $p = $this->pending();
        $preview = $this->browser();
        $person = $this->browser();

        foreach ([$preview, $preview, $person] as $who) {
            $r = $this->open($who, $p, '&callback=' . rawurlencode('https://agent.example/callback'));
            $this->assertSame(200, $r->getStatusCode());
            $this->assertSame('signin', self::state($r), 'the same sign-in card as before');
            $this->assertStringNotContainsString(self::USED, (string)$r->getContent());
        }
        $this->assertSame('pending', Pending::find($p['id'])['status'], 'a GET never changes the request');
        $this->assertSame([202, ['status' => 'pending']], Pending::poll(Pending::find($p['id'])));

        // the person's first POST (here: signed in already, Continue as ...) claims it
        $person->put('aauth_ps.uid', 5);
        $this->assertSame('identity', self::state($this->open($person, $p)));
        $this->assertSame('pending', Pending::find($p['id'])['status']);
        $r = $this->c->submit($this->request($person, 'POST', '/aauth/interact', ['pid' => $p['id'], 'decision' => 'show']));
        $this->assertSame('identity', self::state($r));
        $this->assertSame('interacting', Pending::find($p['id'])['status']);

        // the previewer's session cannot act on it any more, and now sees the code as used
        $r = $this->c->submit($this->request($preview, 'POST', '/aauth/interact', ['pid' => $p['id'], 'decision' => 'deny']));
        $this->assertStringContainsString(self::USED, (string)$r->getContent());
        $this->assertSame('interacting', Pending::find($p['id'])['status'], 'not denied by the other browser');
        $this->assertStringContainsString(self::USED, (string)$this->open($preview, $p)->getContent());

        // and the person approves; the callback remembered from the link still applies
        $r = $this->c->submit($this->request($person, 'POST', '/aauth/interact', ['pid' => $p['id'], 'decision' => 'allow']));
        $this->assertSame('done', self::state($r));
        $this->assertStringContainsString('https://agent.example/callback', (string)$r->getContent());
        $this->assertSame('approved', Pending::find($p['id'])['status']);
    }

    public function testDenyWithoutSigningInAndTypedCodesClaim(): void
    {
        $p = $this->pending();
        $first = $this->browser();
        $this->open($first, $p);
        $other = $this->browser();
        $this->open($other, $p);
        $r = $this->c->submit($this->request($first, 'POST', '/aauth/interact', ['pid' => $p['id'], 'decision' => 'deny']));
        $this->assertSame('done', self::state($r));
        $this->assertSame('denied', Pending::find($p['id'])['status']);

        // a code typed into the code card is a POST: it claims at once
        $q = $this->pending();
        $typist = $this->browser();
        $r = $this->c->submit($this->request($typist, 'POST', '/aauth/interact', ['code' => strtolower(Pending::displayCode($q['code']))]));
        $this->assertSame('signin', self::state($r));
        $this->assertSame('interacting', Pending::find($q['id'])['status']);
        $late = $this->c->submit($this->request($this->browser(), 'POST', '/aauth/interact', ['code' => Pending::displayCode($q['code'])]));
        $this->assertStringContainsString(self::USED, (string)$late->getContent());
    }

    public function testTheNextCardClaimsTheAuthRequest(): void
    {
        $person = $this->browser(5);
        $person->put('aauth_ps.next', ['sub' => 'pairwise', 'jkt' => 'J', 'since' => time()]);
        $p = $this->pending('auth', ['sub' => 'pairwise', 'scope' => 'sales.read', 'user_id' => 5]);
        $json = json_decode((string)$this->c->next($this->request($person, 'GET', '/aauth/interact/next'))->getContent(), true);
        $this->assertSame('consent', $json['state']);
        $this->assertSame('interacting', Pending::find($p['id'])['status']);
        $this->assertStringContainsString(self::USED, (string)$this->open($this->browser(), $p)->getContent());
        $this->assertSame('consent', self::state($this->open($person, $p)));
    }

    public function testABrowserThatOnlyOpenedTheLinkIsToldTheCodeWasUsedAfterAnotherDecided(): void
    {
        $this->user(7, 'casey@corp.test');
        $p = $this->pending();
        $person = $this->browser(5);
        $this->assertSame('identity', self::state($this->open($person, $p)), 'the person reads "Continue as Jordan"');
        $other = $this->browser(7);
        $this->open($other, $p);
        $this->assertSame('next', self::state($this->c->submit($this->request($other, 'POST', '/aauth/interact', ['pid' => $p['id'], 'decision' => 'allow']))));
        $this->assertSame(7, Pending::find($p['id'])['user_id']);

        // the person's click on the page already open: not "Approved", but the code card
        $ip = ClientIp::of($this->request($person, 'POST', '/aauth/interact'));
        $failures = Throttle::count('code-ip', $ip);
        $r = $this->c->submit($this->request($person, 'POST', '/aauth/interact', ['pid' => $p['id'], 'decision' => 'allow']));
        $this->assertSame('code', self::state($r));
        $this->assertStringContainsString(self::USED, (string)$r->getContent());
        $this->assertStringNotContainsString('data-aauth-result', (string)$r->getContent());
        $this->assertSame($failures + 1, Throttle::count('code-ip', $ip), 'counted as a failed code attempt');
        $this->assertSame(7, Pending::find($p['id'])['user_id']);
    }

    public function testANonClaimantGetsNoOutcomeAndNoCallbackEvenAfterTheClaimRecordExpired(): void
    {
        $p = $this->pending();
        $person = $this->browser(5);
        $other = $this->browser();
        $this->open($person, $p);
        $this->open($other, $p, '&callback=' . rawurlencode('https://agent.example/callback?from=other'));
        $this->assertSame('next', self::state($this->c->submit($this->request($person, 'POST', '/aauth/interact', ['pid' => $p['id'], 'decision' => 'allow']))));

        foreach ([false, true] as $expired) {
            if ($expired) {
                Store::cache()->forget('aauth:pid-owner:' . $p['id']); // the shared claim record lasts the pending TTL + 60 s
            }
            $r = $this->c->submit($this->request($other, 'POST', '/aauth/interact', ['pid' => $p['id'], 'decision' => 'deny']));
            $this->assertStringContainsString(self::USED, (string)$r->getContent());
            $this->assertStringNotContainsString('from=other', (string)$r->getContent(), 'its callback is not sent a result');
            $this->assertSame('approved', Pending::find($p['id'])['status']);
        }
        // the claimant still sees its own outcome
        $r = $this->c->submit($this->request($person, 'POST', '/aauth/interact', ['pid' => $p['id'], 'decision' => 'allow']));
        $this->assertSame('done', self::state($r));
        $this->assertStringContainsString('data-aauth-result="approved"', (string)$r->getContent());
    }

    public function testTheNextCardIgnoresAnotherBrowsersRequestButReportsAStandingGrant(): void
    {
        $person = $this->browser(5);
        $person->put('aauth_ps.next', ['sub' => 'pairwise', 'jkt' => 'J', 'since' => time()]);
        $a = $this->pending('auth', ['sub' => 'pairwise', 'scope' => 'sales.read', 'user_id' => 5]);
        $other = $this->browser();
        $this->open($other, $a);
        $this->c->submit($this->request($other, 'POST', '/aauth/interact', ['pid' => $a['id'], 'decision' => 'deny']));
        $this->assertSame('denied', Pending::find($a['id'])['status']);
        $next = fn () => json_decode((string)$this->c->next($this->request($person, 'GET', '/aauth/interact/next'))->getContent(), true);
        $this->assertSame(['state' => 'waiting'], $next(), 'not "done, denied": that was another browser\'s request');

        // a standing grant answers the agent at once: no browser owns that request, and the person sees it
        $g = $this->pending('auth', ['sub' => 'pairwise', 'scope' => 'sales.read', 'user_id' => 5, 'status' => 'interacting']);
        Pending::approve($g['id'], 'token', time() + 600, 5);
        Pending::setStatus($g['id'], 'delivered');
        $this->assertSame(['state' => 'done', 'result' => 'approved'], $next());
    }
}
