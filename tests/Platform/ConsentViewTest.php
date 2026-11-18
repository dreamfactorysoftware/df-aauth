<?php

namespace DreamFactory\Core\AAuth\Tests\Platform;

use DreamFactory\Core\AAuth\AgentProvider\AgentProvider;
use DreamFactory\Core\AAuth\PersonServer\View;
use DreamFactory\Core\AAuth\Support\Users;

/**
 * The consent pages: the DOM contract agent/person.mjs and the e2e rely on (agent/README.md), the
 * brand (gear wordmark, never an agent-supplied logo) and escaping of agent-supplied text.
 */
final class ConsentViewTest extends TestCase
{
    private const PLAYGROUND = 'aauth:playground@df.example.test';

    private function base(array $vars = []): array
    {
        return $vars + [
            'csrf' => 'tok', 'title' => 'DreamFactory', 'code' => 'K7QP-3M9X', 'pid' => 'p1', 'error' => null,
            'heading' => 'Acme Reports', 'agentSub' => 'aauth:reports@agent.example.test', 'agentNamed' => true, 'agentPlayground' => false,
            'resourceName' => 'DreamFactory', 'resourceHost' => 'df.example.test', 'justification' => null,
            'userName' => 'Jordan Lee', 'userEmail' => 'jordan@x.test',
        ];
    }

    /** The same scan agent/person.mjs does. */
    private function scan(string $html): array
    {
        preg_match_all('/<[^>]*\sdata-aauth-state\s*=\s*["\']?([\w-]+)/i', $html, $states);
        preg_match('/<([\w-]+)\b[^>]*\sdata-aauth-error\b[^>]*>([\s\S]*?)<\/\1>/i', $html, $err);
        preg_match_all('/<[^>]*\sdata-aauth-scope="([^"]*)"[^>]*\sdata-aauth-grantable="([01])"/i', $html, $scopes, PREG_SET_ORDER);

        return [
            'states' => $states[1],
            'error' => $err ? html_entity_decode(trim(strip_tags($err[2])), ENT_QUOTES) : null,
            'scopes' => array_map(fn ($m) => [$m[1], $m[2] === '1'], $scopes),
        ];
    }

    public function testConsentKeepsTheFormContract(): void
    {
        $html = View::render('consent', $this->base([
            'attrs' => ' data-aauth-state="consent"', 'anyGrantable' => true,
            'error' => "You don't have a role that allows this.",
            'scopes' => [
                ['scope' => 'sales.read', 'description' => 'Read customers and orders', 'grantable' => true],
                ['scope' => 'sales.refund', 'description' => 'Update order status', 'grantable' => false],
            ],
        ]));
        $s = $this->scan($html);
        $this->assertSame(['consent'], $s['states']);
        $this->assertSame("You don't have a role that allows this.", $s['error']);
        $this->assertSame([['sales.read', true], ['sales.refund', false]], $s['scopes']);
        $this->assertSame(1, preg_match_all('/<form\b[^>]*method="post"[^>]*>/', $html));
        foreach (['name="_token" value="tok"', 'name="pid" value="p1"', 'name="scopes_shown" value="1"', 'name="always" value="1"',
            'name="scopes[]" value="sales.read" checked', 'name="scopes[]" value="sales.refund" disabled',
            'name="decision" value="deny"', 'name="decision" value="switch"'] as $needle) {
            $this->assertStringContainsString($needle, $html);
        }
        // Allow is the primary action but never preselected: Enter must not grant access unread.
        $this->assertMatchesRegularExpression('/<button class="primary" type="submit" name="decision" value="allow">/', $html);
        $this->assertStringNotContainsString('autofocus', $html);

        // Nothing grantable: Allow is a plain disabled button and Deny becomes the primary action.
        $blocked = View::render('consent', $this->base(['attrs' => ' data-aauth-state="consent"', 'anyGrantable' => false,
            'scopes' => [['scope' => 'sales.refund', 'description' => 'Update order status', 'grantable' => false]]]));
        $this->assertMatchesRegularExpression('/<button type="submit" name="decision" value="allow" disabled>/', $blocked);
        $this->assertMatchesRegularExpression('/<button class="primary" type="submit" name="decision" value="deny">/', $blocked);
        $this->assertStringNotContainsString('name="always"', $blocked);
    }

    public function testEveryStateRendersOneCardWithTheGearWordmark(): void
    {
        $pages = [
            'code' => ['attrs' => ' data-aauth-state="code"', 'code' => null],
            'signin' => ['attrs' => ' data-aauth-state="signin"', 'canDeny' => true],
            'identity' => ['attrs' => ' data-aauth-state="identity"'],
            'next' => ['attrs' => ' data-aauth-state="next" data-next-url="/aauth/interact/next"', 'script' => true],
            'done' => ['attrs' => ' data-aauth-state="done" data-aauth-result="approved"', 'approved' => true],
            'grants' => ['attrs' => ' data-aauth-state="grants"', 'grants' => [], 'wide' => true],
        ];
        foreach ($pages as $template => $vars) {
            $html = View::render($template, $this->base($vars));
            $this->assertSame([$template], $this->scan($html)['states'], $template);
            $this->assertStringContainsString('src="/dreamfactory/dist/assets/img/logo.png"', $html, $template);
            $this->assertStringContainsString('href="/dreamfactory/dist/favicon.ico"', $html, $template);
            $this->assertStringNotContainsString('Logo-dreamfactory-purple-grey', $html, $template);
            $this->assertSame(1, preg_match_all('/<img\b/i', $html), "$template: the wordmark is the only image");
        }
        $signin = View::render('signin', $this->base(['attrs' => ' data-aauth-state="signin"', 'canDeny' => true]));
        foreach (['name="email"', 'name="password"', 'name="decision" value="deny"'] as $needle) {
            $this->assertStringContainsString($needle, $signin);
        }
        $identity = View::render('identity', $this->base(['attrs' => ' data-aauth-state="identity"']));
        foreach (['value="allow"', 'value="deny"', 'value="switch"'] as $needle) {
            $this->assertStringContainsString('name="decision" ' . $needle, $identity);
        }
        $this->assertStringContainsString('value="allow">Continue</button>', $identity);
        $this->assertStringNotContainsString('autofocus', $identity);
        $named = View::render('identity', $this->base(['attrs' => ' data-aauth-state="identity"', 'userFirst' => '<Jo>']));
        $this->assertStringContainsString('value="allow">Continue as &lt;Jo&gt;</button>', $named);
        $done = View::render('done', $this->base(['attrs' => ' data-aauth-state="done"', 'approved' => true]));
        $this->assertStringNotContainsString('close this tab', $done);
        $this->assertStringContainsString('<span class="code"', $done);
        $next = View::render('next', $this->base(['attrs' => ' data-aauth-state="next"', 'script' => true]));
        foreach (['data-aauth-wait', 'data-aauth-closed', 'data-aauth-closed-text', 'data-aauth-badge', '/aauth/assets/interact.js'] as $needle) {
            $this->assertStringContainsString($needle, $next);
        }
    }

    public function testOnlyThePlaygroundGetsTheGear(): void
    {
        $this->assertTrue(AgentProvider::isPlayground(self::ISSUER, self::PLAYGROUND));
        $this->assertFalse(AgentProvider::isPlayground('https://evil.example', self::PLAYGROUND));
        $this->assertFalse(AgentProvider::isPlayground(self::ISSUER, 'aauth:other@df.example.test'));
        $this->assertFalse(AgentProvider::isPlayground(null, null));

        $own = View::render('signin', $this->base(['heading' => 'DreamFactory Playground', 'agentSub' => self::PLAYGROUND, 'agentPlayground' => true]));
        $this->assertStringContainsString('class="tile tile-df"', $own);
        // the brand mark (gear + database: two paths), not the hollow spinner cog
        $this->assertSame(2, substr_count($own, '<path fill="#ff8c5a"'));
        $this->assertStringNotContainsString('M35.2618', $own);

        // a third-party agent calling itself "DreamFactory Playground" gets a plain monogram
        $impostor = View::render('signin', $this->base(['heading' => 'DreamFactory Playground', 'agentSub' => 'aauth:pg@evil.example']));
        $this->assertStringNotContainsString('tile-df', $impostor);
        $this->assertMatchesRegularExpression('/<span class="tile" aria-hidden="true">D<\/span>/', $impostor);
        $this->assertStringContainsString('aauth:pg@<span class="host">evil.example</span>', $impostor);
    }

    public function testAgentTextIsEscaped(): void
    {
        $html = View::render('consent', $this->base([
            'attrs' => ' data-aauth-state="consent"', 'anyGrantable' => true,
            'heading' => '<b>Acme</b>', 'justification' => '<script>alert(1)</script>',
            'scopes' => [['scope' => 'x"><i>', 'description' => '<img src=x>', 'grantable' => true]],
        ]));
        $this->assertStringNotContainsString('<script>alert', $html);
        $this->assertStringNotContainsString('<b>Acme</b>', $html);
        $this->assertStringNotContainsString('<img src=x>', $html);
        $this->assertStringContainsString('&lt;script&gt;alert(1)&lt;/script&gt;', $html);
        $this->assertSame([['x&quot;&gt;&lt;i&gt;', true]], $this->scan($html)['scopes']);
    }

    public function testContinueAsFirstName(): void
    {
        $this->assertSame('Jordan', Users::firstName(['first_name' => 'Jordan', 'name' => 'Jordan Lee']));
        $this->assertSame('Test', Users::firstName(['first_name' => '', 'name' => 'Test Admin']));
        $this->assertSame('', Users::firstName(['name' => 'pat@example.com', 'email' => 'pat@example.com']));
        $this->assertSame('', Users::firstName(['first_name' => 'Maximilianabcdefgh']));
        $this->assertSame('', Users::firstName([]));
    }

    public function testMonogram(): void
    {
        $this->assertSame('A', View::monogram('Acme Reports'));
        $this->assertSame('R', View::monogram('aauth:reports@agent.example'));
        $this->assertSame('É', View::monogram(' élan'));
        $this->assertSame('?', View::monogram('***'));
    }
}
