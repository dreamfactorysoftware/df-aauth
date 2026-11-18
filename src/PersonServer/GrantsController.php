<?php

namespace DreamFactory\Core\AAuth\PersonServer;

use DreamFactory\Core\AAuth\AgentProvider\AgentProvider;
use DreamFactory\Core\AAuth\Support\Settings;
use DreamFactory\Core\AAuth\Support\Users;
use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\Response;

/** /aauth/grants: the signed-in person's standing grants ("Always allow"), with revoke. */
class GrantsController
{
    private const UID = 'aauth_ps.uid';

    public function show(Request $request): Response
    {
        return $this->render($request);
    }

    public function submit(Request $request): Response
    {
        if (!Settings::enabled() || !Settings::localPersonServerEnabled()) {
            return $this->render($request);
        }
        $decision = (string)$request->input('decision', '');
        if ($request->filled('email')) {
            $service = trim((string)$request->input('service', ''));
            $result = SignIn::attempt($request, trim((string)$request->input('email')), (string)$request->input('password'), $service);
            if ($result['status'] === 'throttled') {
                return $this->render($request, 'Too many attempts. Try again in a few minutes.', 429);
            }
            if ($result['status'] !== 'ok') {
                return $this->render($request, $service !== '' ? 'Wrong username or password.' : 'Wrong email or password.');
            }
            $request->session()->regenerate();
            $request->session()->put(self::UID, $result['user_id']);

            return $this->render($request);
        }
        $uid = (int)$request->session()->get(self::UID, 0);
        if ($decision === 'sso' && !$uid) {
            return SsoLogin::offered() ? InteractController::redirect(SsoLogin::start($request, null))
                : $this->render($request, 'Single sign-on is not available here.');
        }
        if ($decision === 'signout') {
            $request->session()->forget(self::UID);

            return $this->render($request);
        }
        if ($uid && $decision === 'revoke') {
            try {
                Grants::delete((int)$request->input('grant_id'), $uid);
            } catch (\Throwable $e) {
                return $this->render($request, 'That grant no longer exists.');
            }
        }

        return $this->render($request);
    }

    private function render(Request $request, ?string $error = null, int $status = 200): Response
    {
        $base = ['csrf' => csrf_token(), 'title' => 'DreamFactory', 'error' => $error];
        if (!Settings::enabled() || !Settings::localPersonServerEnabled()) {
            // the message must replace $base['error'] (null here): with `+` the left operand wins
            return View::page('code', ['error' => 'Agent sign-in is not available.', 'attrs' => ' data-aauth-state="code"'] + $base, 404);
        }
        $uid = (int)$request->session()->get(self::UID, 0);
        $user = $uid ? Users::find($uid) : null;
        if ($user && empty($user['is_active'])) {
            $request->session()->forget(self::UID);
            $user = null;
        }
        if (!$user) {
            return View::page('signin', $base + InteractController::signInOptions($request)
                + ['heading' => 'Agent access', 'action' => '/aauth/grants', 'attrs' => ' data-aauth-state="signin"'], $status);
        }

        $grants = array_map(fn (array $g) => $g + [
            'playground' => AgentProvider::isPlayground($g['agent_iss'] ?? null, $g['agent_sub'] ?? null),
            'resource_host' => (string)parse_url((string)$g['resource'], PHP_URL_HOST),
        ], Grants::forUser($uid));

        return View::page('grants', $base + [
            'grants' => $grants,
            'userName' => Users::displayName($user),
            'userEmail' => (string)$user['email'],
            'wide' => true,
            'attrs' => ' data-aauth-state="grants"',
        ]);
    }
}
