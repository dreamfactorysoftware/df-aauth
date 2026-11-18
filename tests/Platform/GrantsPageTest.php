<?php

namespace DreamFactory\Core\AAuth\Tests\Platform;

use DreamFactory\Core\AAuth\PersonServer\GrantsController;
use DreamFactory\Core\AAuth\Support\Settings;
use Illuminate\Http\Request;
use Illuminate\Session\ArraySessionHandler;
use Illuminate\Session\Store as SessionStore;

/** /aauth/grants, a person's own standing grants. */
final class GrantsPageTest extends TestCase
{
    public function testUnavailablePageSaysWhy(): void
    {
        $session = new SessionStore('aauth_test', new ArraySessionHandler(10));
        $session->start();
        $this->app->instance('session', $session);
        $c = new GrantsController();
        foreach ([[false, true], [true, false]] as [$enabled, $localPs]) {
            Settings::set('enabled', $enabled);
            Settings::set('ps_local_enabled', $localPs);
            foreach (['GET' => [], 'POST' => ['decision' => 'signout']] as $method => $params) {
                $r = Request::create('https://df.example.test/aauth/grants', $method, $params);
                $r->setLaravelSession($session);
                $page = $method === 'GET' ? $c->show($r) : $c->submit($r);
                $this->assertSame(404, $page->getStatusCode());
                $this->assertMatchesRegularExpression('/data-aauth-error>.*?<\/svg>Agent sign-in is not available\.<\/p>/s', (string)$page->getContent());
            }
        }
    }
}
