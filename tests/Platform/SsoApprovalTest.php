<?php

namespace DreamFactory\Core\AAuth\Tests\Platform;

use DreamFactory\Core\AAuth\PersonServer\Accounts;
use DreamFactory\Core\AAuth\PersonServer\InteractController;
use DreamFactory\Core\AAuth\PersonServer\Pending;
use DreamFactory\Core\AAuth\PersonServer\SignIn;
use DreamFactory\Core\AAuth\PersonServer\SsoLogin;
use DreamFactory\Core\AAuth\PersonServer\View;
use DreamFactory\Core\AAuth\Support\Settings;
use Illuminate\Http\Request;
use Illuminate\Session\ArraySessionHandler;
use Illuminate\Session\Store as SessionStore;

/**
 * Approving with a directory account (LDAP / AD through DreamFactory's mapping) and with single
 * sign-on through DreamFactory's login page (docs/sso-approval.md). DreamFactory's services are
 * replaced by FakeAccounts.
 */
final class SsoApprovalTest extends TestCase
{
    private FakeAccounts $accounts;
    private SessionStore $session;

    protected function setUp(): void
    {
        parent::setUp();
        $this->accounts = new FakeAccounts();
        $this->app->instance(Accounts::class, $this->accounts);
        $this->session = new SessionStore('aauth_test', new ArraySessionHandler(10));
        $this->session->start();
        $this->app->instance('session', $this->session);
        $this->user(5, 'jordan@corp.test', false, []);
        $this->user(6, 'casey@corp.test', false, []);
        $this->db()->table('user')->where('id', 6)->update(['is_active' => false]);
        Settings::set('enabled', true);
    }

    private function request(string $method, string $uri, array $params = [], string $ip = '198.51.100.7'): Request
    {
        $r = Request::create('https://df.example.test' . $uri, $method, $params, [], [], ['REMOTE_ADDR' => $ip]);
        $r->setLaravelSession($this->session);

        return $r;
    }

    private function pending(): array
    {
        $p = Pending::create('person', ['sub' => 'aauth:reports@agent.example', 'iss' => 'https://agent.example', 'jkt' => 'J', 'name' => 'Acme Reports'], self::ISSUER, 'DF');
        $this->session->put('aauth_ps.pids', [$p['id']]);

        return $p;
    }

    /** What the admin app does after login (df-admin-interface url.ts handleRedirectIfPresent). */
    private static function adminAppReturn(string $loginUrl, string $jwt): string
    {
        $hash = (string)parse_url($loginUrl, PHP_URL_FRAGMENT);
        parse_str((string)substr($hash, strpos($hash, '?') + 1), $q);
        $redirect = $q['redirect'];
        $separator = str_contains($redirect, '?') ? '&' : '?';

        return $redirect . $separator . 'session_token=' . $jwt;
    }

    public function testDirectorySignInUsesTheServiceAndItsOwnLockoutBucket(): void
    {
        $r = $this->request('POST', '/aauth/interact');
        $this->assertSame(['status' => 'ok', 'user_id' => 5], SignIn::attempt($r, 'jdoe', 'right', 'corp-ldap'));
        $this->assertSame([['corp-ldap', 'jdoe', 'right']], $this->accounts->logins);
        $this->assertSame('wrong', SignIn::attempt($r, 'jdoe', 'nope', 'corp-ldap')['status']);
        $this->assertSame('wrong', SignIn::attempt($r, 'jdoe', 'right', 'other-ldap')['status'], 'only listed directory services');
        $this->assertSame('wrong', SignIn::attempt($r, 'jdoe', '', 'corp-ldap')['status'], 'never an empty password (anonymous bind)');
        for ($i = 0; $i < SignIn::ACCOUNT_LIMIT; $i++) {
            SignIn::attempt($this->request('POST', '/', [], "203.0.113.$i"), 'jdoe', 'guess', 'corp-ldap');
        }
        $this->assertSame('throttled', SignIn::attempt($this->request('POST', '/', [], '192.0.2.200'), 'jdoe', 'right', 'corp-ldap')['status']);
        $this->assertFalse(SignIn::locked('192.0.2.201', 'jdoe'), 'the local account jdoe is a different bucket');
        // df-adldap names shadow users with the first character of cn
        $this->assertSame('Philip Fry', \DreamFactory\Core\AAuth\Support\Users::displayName(['name' => 'P', 'first_name' => 'Philip', 'last_name' => 'Fry', 'email' => 'fry+ldap@x']));
        $this->assertSame('Jo', \DreamFactory\Core\AAuth\Support\Users::displayName(['name' => 'Jo', 'first_name' => 'Joanna', 'last_name' => 'Lee']));
    }

    public function testSignInCardOffersDirectoriesAndSsoOnlyWhenTheyExist(): void
    {
        $vars = ['csrf' => 'tok', 'title' => 'DreamFactory', 'heading' => 'Agent access', 'pid' => 'p1', 'attrs' => ' data-aauth-state="signin"'];
        $plain = View::render('signin', $vars + ['directories' => [], 'sso' => false]);
        $this->assertStringContainsString('<input type="email" name="email"', $plain);
        $this->assertStringNotContainsString('name="service"', $plain);
        $this->assertStringNotContainsString('value="sso"', $plain);
        $this->assertSame(View::render('signin', $vars), $plain, 'no new options: the page is unchanged');

        $both = View::render('signin', $vars + ['directories' => [['name' => 'corp-ldap', 'label' => 'Corp <AD>']], 'service' => 'corp-ldap', 'sso' => true]);
        $this->assertMatchesRegularExpression('/<select name="service"><option value="">DreamFactory account<\/option><option value="corp-ldap" selected>Corp &lt;AD&gt;<\/option><\/select>/', $both);
        $this->assertStringContainsString('<input type="text" name="email"', $both, 'directory usernames are not emails');
        $this->assertMatchesRegularExpression('/<form method="post" action="\/aauth\/interact" class="sso-row">\s*<input type="hidden" name="_token" value="tok">\s*<input type="hidden" name="pid" value="p1">\s*<button class="full" type="submit" name="decision" value="sso">/', $both);
        $this->assertStringContainsString('<input type="text" name="email"', View::render('signin', $vars + ['loginAttribute' => 'username']));
    }

    public function testSsoIsOfferedPerConfig(): void
    {
        $this->assertFalse(SsoLogin::offered(), 'auto, no SSO service');
        $this->accounts->sso = true;
        $this->assertTrue(SsoLogin::offered(), 'auto, an OAuth/OIDC/SAML service is active');
        $this->app['config']->set('df-aauth.sso', 'off');
        $this->assertFalse(SsoLogin::offered());
        $this->accounts->sso = false;
        $this->app['config']->set('df-aauth.sso', 'on');
        $this->assertTrue(SsoLogin::offered());
    }

    public function testTheTokenComesBackInTheFragmentNeverTheQuery(): void
    {
        $url = SsoLogin::start($this->request('POST', '/aauth/interact'), 'pid1');
        $this->assertStringStartsWith('https://df.example.test/dreamfactory/dist/#/auth/login?redirect=https%3A%2F%2Fdf.example.test%2Faauth%2Finteract%2Fsso%23state%3D', $url);
        $back = self::adminAppReturn($url, 'a.b.c');
        $this->assertSame('https', parse_url($back, PHP_URL_SCHEME));
        $this->assertSame('df.example.test', parse_url($back, PHP_URL_HOST), 'same origin: the admin app only redirects there');
        $this->assertSame('/aauth/interact/sso', parse_url($back, PHP_URL_PATH));
        $this->assertNull(parse_url($back, PHP_URL_QUERY), 'nothing for access logs or Referer');
        $this->assertMatchesRegularExpression('/^state=[A-Za-z0-9_-]{20,}\?session_token=a\.b\.c$/', parse_url($back, PHP_URL_FRAGMENT));
        $this->app['config']->set('df-aauth.sso_login_path', 'login.html?x=1');
        $this->assertStringStartsWith('https://df.example.test/login.html?x=1&redirect=', SsoLogin::start($this->request('POST', '/'), null));
    }

    public function testStateIsSingleUseBoundToThisBrowserAndFresh(): void
    {
        $r = $this->request('POST', '/aauth/interact/sso');
        $state = self::stateOf(SsoLogin::start($r, 'pid1'));
        $this->assertSame(['user_id' => null, 'pid' => null, 'matched' => false], SsoLogin::complete($r, 'forged', 'good.jwt.5'));
        $this->assertSame(['user_id' => null, 'pid' => null, 'matched' => false], SsoLogin::complete($r, '', 'good.jwt.5'));
        $this->assertSame(['user_id' => null, 'pid' => 'pid1', 'matched' => true], SsoLogin::complete($r, $state, 'bad.jwt.x'), 'a bad token burns its state');
        $this->assertNull(SsoLogin::complete($r, $state, 'good.jwt.5')['user_id'], 'so a good token cannot follow on it');

        $state = self::stateOf(SsoLogin::start($r, 'pid1'));
        $this->assertSame(['user_id' => 5, 'pid' => 'pid1', 'matched' => true], SsoLogin::complete($r, $state, 'good.jwt.5'));
        $this->assertNull(SsoLogin::complete($r, $state, 'good.jwt.5')['user_id'], 'replay');

        $state = self::stateOf(SsoLogin::start($r, null));
        $states = $this->session->get(SsoLogin::STATE);
        $states[$state]['at'] = time() - SsoLogin::MAX_AGE - 1;
        $this->session->put(SsoLogin::STATE, $states);
        $this->assertNull(SsoLogin::complete($r, $state, 'good.jwt.5')['user_id'], 'stale state');

        // two consent tabs in one browser: both states stay valid, each once
        $a = self::stateOf(SsoLogin::start($r, 'tab-a'));
        $b = self::stateOf(SsoLogin::start($r, 'tab-b'));
        $this->assertSame('tab-b', SsoLogin::complete($r, $b, 'good.jwt.5')['pid']);
        $this->assertSame(['user_id' => 5, 'pid' => 'tab-a', 'matched' => true], SsoLogin::complete($r, $a, 'good.jwt.5'));
        for ($i = 0; $i < 8; $i++) {
            SsoLogin::start($r, "p$i");
        }
        $this->assertCount(SsoLogin::MAX_STATES, $this->session->get(SsoLogin::STATE), 'bounded');
    }

    public function testConsentFlowSignsInThroughSso(): void
    {
        $this->accounts->sso = true;
        $p = $this->pending();
        $c = new InteractController();
        $this->assertSame('pending', Pending::find($p['id'])['status']);

        $start = $c->submit($this->request('POST', '/aauth/interact', ['pid' => $p['id'], 'decision' => 'sso']));
        $this->assertSame(303, $start->getStatusCode());
        $login = $start->headers->get('Location');
        $this->assertStringStartsWith('https://df.example.test/dreamfactory/dist/#/auth/login?redirect=', $login);
        $this->assertStringContainsString('no-store', (string)$start->headers->get('Cache-Control'));
        // the claim is held before the browser leaves for the login page
        $this->assertSame('interacting', Pending::find($p['id'])['status']);
        $this->assertFalse(Pending::claim(Pending::find($p['id']), 'another-browser'));

        $landing = $c->ssoLanding($this->request('GET', '/aauth/interact/sso'));
        $this->assertStringContainsString('data-aauth-state="sso"', $landing->getContent());
        $this->assertMatchesRegularExpression('/<form method="post" action="\/aauth\/interact\/sso" data-aauth-sso>/', $landing->getContent());
        $this->assertStringContainsString('src="/aauth/assets/interact.js"', $landing->getContent());
        $this->assertSame('no-referrer', $landing->headers->get('Referrer-Policy'));

        $done = $c->ssoComplete($this->request('POST', '/aauth/interact/sso', ['state' => self::stateOf($login), 'session_token' => 'good.jwt.5']));
        $this->assertSame(303, $done->getStatusCode());
        $this->assertSame('/aauth/interact?code=' . rawurlencode(Pending::displayCode($p['code'])), $done->headers->get('Location'));
        $this->assertSame(5, $this->session->get('aauth_ps.uid'), 'signed in to the consent session only');

        $card = $c->show($this->request('GET', '/aauth/interact', ['code' => Pending::displayCode($p['code'])]));
        $this->assertStringContainsString('data-aauth-state="identity"', $card->getContent(), 'signing in is not consent: Continue as ...');
        $this->assertSame('interacting', Pending::find($p['id'])['status']);
    }

    public function testFailedSsoReturnsToTheSignInCard(): void
    {
        $this->accounts->sso = true;
        $p = $this->pending();
        $c = new InteractController();
        $login = $c->submit($this->request('POST', '/aauth/interact', ['pid' => $p['id'], 'decision' => 'sso']))->headers->get('Location');
        $inactive = $c->ssoComplete($this->request('POST', '/aauth/interact/sso', ['state' => self::stateOf($login), 'session_token' => 'good.jwt.6']));
        $this->assertSame(303, $inactive->getStatusCode());
        $this->assertStringEndsWith('&sso=failed', $inactive->headers->get('Location'));
        $this->assertNull($this->session->get('aauth_ps.uid'));
        $card = $c->show($this->request('GET', '/aauth/interact', ['code' => Pending::displayCode($p['code']), 'sso' => 'failed']));
        $this->assertStringContainsString('data-aauth-state="signin"', $card->getContent());
        $this->assertStringContainsString('Single sign-on did not complete', $card->getContent());

        $forged = $c->ssoComplete($this->request('POST', '/aauth/interact/sso', ['state' => 'nope', 'session_token' => 'good.jwt.5']));
        $this->assertStringContainsString('data-aauth-state="code"', $forged->getContent());
        $this->assertNull($this->session->get('aauth_ps.uid'), 'a token without this browser\'s state signs nobody in');

        $this->accounts->sso = false;
        $off = $c->submit($this->request('POST', '/aauth/interact', ['pid' => $p['id'], 'decision' => 'sso']));
        $this->assertSame(200, $off->getStatusCode());
        $this->assertStringContainsString('Single sign-on is not available', $off->getContent());
    }

    private static function stateOf(string $loginUrl): string
    {
        preg_match('/%23state%3D([A-Za-z0-9_-]+)/', $loginUrl, $m);

        return $m[1] ?? '';
    }
}

final class FakeAccounts implements Accounts
{
    public bool $sso = false;
    public array $logins = [];

    public function directories(): array
    {
        return [['name' => 'corp-ldap', 'label' => 'Corp LDAP']];
    }

    public function directoryLogin(string $service, string $username, string $password): ?int
    {
        $this->logins[] = [$service, $username, $password];

        return $service === 'corp-ldap' && $username === 'jdoe' && $password === 'right' ? 5 : null;
    }

    public function hasSso(): bool
    {
        return $this->sso;
    }

    public function sessionUser(string $jwt): ?int
    {
        // like DreamFactoryAccounts: valid token AND an active user
        if (!preg_match('/^good\.jwt\.(\d+)$/', $jwt, $m)) {
            return null;
        }
        $row = \Illuminate\Support\Facades\DB::table('user')->where('id', (int)$m[1])->first();

        return $row && $row->is_active ? (int)$m[1] : null;
    }
}
