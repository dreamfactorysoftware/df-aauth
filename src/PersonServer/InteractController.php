<?php

namespace DreamFactory\Core\AAuth\PersonServer;

use DreamFactory\Core\AAuth\AgentProvider\AgentProvider;
use DreamFactory\Core\AAuth\Protocol\Ids;
use DreamFactory\Core\AAuth\Support\ClientIp;
use DreamFactory\Core\AAuth\Support\Settings;
use DreamFactory\Core\AAuth\Support\Throttle;
use DreamFactory\Core\AAuth\Support\Users;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\RedirectResponse;
use Symfony\Component\HttpFoundation\Response;

/**
 * The Person Server consent UI at /aauth/interact (web middleware group: session + CSRF).
 *
 * Card states (data-aauth-state, see agent/README.md "Consent page contract"):
 *   code -> signin -> identity (person request) | consent (auth request) -> next | done
 *
 * The code is only a correlation id: every decision is a CSRF-protected POST by a person signed in
 * with their DreamFactory account: email/username + password, an LDAP / Active Directory service
 * (SignIn; no DF session side effects, failure limits per client address and account), or single
 * sign-on through DreamFactory's login page (SsoLogin: OAuth, OIDC, SAML). The signed-in DF user
 * id lives in the Laravel session under aauth_ps.uid. A code is single-use: the first browser
 * that POSTs for the request (sign-in, single sign-on, deny, allow, switch, a typed code) or reaches
 * it from the "next" card owns it, and its outcome: any other browser gets "already used", also after
 * the request was decided. Opening the link (GET) never claims it and never changes the request,
 * because chat link previews and mail scanners fetch links before the person does.
 */
class InteractController
{
    private const UID = 'aauth_ps.uid';
    private const PIDS = 'aauth_ps.pids';
    private const NEXT = 'aauth_ps.next';
    private const BROWSER = 'aauth_ps.browser';
    /** Requests this browser claimed (outlives the shared claim record, which expires with the request). */
    private const CLAIMED = 'aauth_ps.claimed';
    private const MAX_FAILURES = 10;
    private const FAILURE_WINDOW = 600;
    /** Wrong passwords on one request before it fails for good. */
    private const MAX_REQUEST_FAILURES = 5;

    public function show(Request $request): Response
    {
        if (!$this->available()) {
            return View::page('code', $this->base($request) + ['error' => 'Agent sign-in is not available.', 'attrs' => ' data-aauth-state="code"'], 404);
        }
        $code = trim((string)$request->query('code', ''));
        if ($code !== '') {
            return $this->openCode($request, $code, false);
        }

        return $this->codeCard($request);
    }

    public function submit(Request $request): Response
    {
        if (!$this->available()) {
            return View::page('code', $this->base($request) + ['error' => 'Agent sign-in is not available.', 'attrs' => ' data-aauth-state="code"'], 404);
        }
        $pid = (string)$request->input('pid', '');
        if ($pid === '') {
            $code = trim((string)$request->input('code', ''));

            return $code === '' ? $this->codeCard($request, 'Enter the code shown by the agent.') : $this->openCode($request, $code, true);
        }
        if (!in_array($pid, (array)$request->session()->get(self::PIDS, []), true)) {
            return $this->codeCard($request, 'Enter the code shown by the agent.');
        }
        $p = Pending::find($pid);
        // opening the link put the request in this session; acting on it, or seeing how it ended,
        // belongs to the browser that claimed it
        if ($p && $this->ownedElsewhere($request, $p)) {
            return $this->alreadyUsed($request);
        }
        if (!$p || !Pending::isLive($p)) {
            return $this->finished($request, $p);
        }
        // every POST acts on the request, so the first one claims it (before single sign-on leaves)
        if (!$this->claim($request, $p)) {
            return $this->alreadyUsed($request);
        }
        $user = $this->user($request);

        if ($request->filled('email')) {
            return $this->signIn($request, $p);
        }
        $decision = (string)$request->input('decision', '');
        if ($decision === 'sso' && !$user) {
            return SsoLogin::offered() ? self::redirect(SsoLogin::start($request, $p['id']))
                : $this->state($request, $p, null, 'Single sign-on is not available here.');
        }
        if ($decision === 'deny' && !$user) {
            // "Deny" on the sign-in card: the person holding the code refuses without signing in.
            Pending::deny($p['id']);

            return $this->done($request, $p, false);
        }
        if ($decision === 'switch') {
            $request->session()->forget(self::UID);

            return $this->state($request, $p, null);
        }
        if (!$user) {
            return $this->state($request, $p, null, 'Sign in first.');
        }
        if ($p['kind'] === 'auth' && $p['user_id'] !== null && $p['user_id'] !== (int)$user['id']) {
            return $this->state($request, $p, $user);
        }
        if ($decision === 'deny') {
            Pending::deny($p['id'], (int)$user['id']);

            return $this->done($request, $p, false);
        }
        if ($decision !== 'allow') {
            return $this->state($request, $p, $user);
        }

        return $p['kind'] === 'person' ? $this->approvePerson($request, $p, $user) : $this->approveAuth($request, $p, $user);
    }

    /** JSON for the "next" card: has the agent come back with its auth request yet? */
    public function next(Request $request): JsonResponse
    {
        $next = $request->session()->get(self::NEXT);
        $user = $this->user($request);
        if (!is_array($next) || !$user || !$this->available()) {
            return $this->json(['state' => 'timeout']);
        }
        $rows = \DB::table(Pending::TABLE)->where('kind', 'auth')->where('sub', $next['sub'])
            ->where('created_at', '>=', now()->setTimestamp((int)$next['since'] - 5))
            ->orderByDesc('created_at')->limit(10)->get(['id']);
        foreach ($rows as $row) {
            $p = Pending::find($row->id);
            if (!$p || ($p['agent']['jkt'] ?? null) !== $next['jkt'] || Pending::claimedElsewhere($p, $this->browser($request))) {
                continue; // another browser's request (and outcome); a standing grant's answer has no owner
            }
            if (Pending::isLive($p)) {
                if (!$this->claim($request, $p)) {
                    continue;
                }
                $this->allowPid($request, $p['id']);

                return $this->json(['state' => 'consent', 'url' => '/aauth/interact?code=' . Pending::displayCode($p['code'])]);
            }
            if (in_array($p['status'], ['approved', 'delivered'], true)) {
                return $this->json(['state' => 'done', 'result' => 'approved']);
            }
            if (in_array($p['status'], ['denied', 'closed', 'cancelled'], true)) {
                return $this->json(['state' => 'done', 'result' => 'denied']);
            }
        }
        if (time() - (int)$next['since'] > 120) {
            return $this->json(['state' => 'timeout']);
        }

        return $this->json(['state' => 'waiting']);
    }

    /** GET /aauth/interact/sso: the page DreamFactory's login returns to (the token is in the URL fragment). */
    public function ssoLanding(Request $request): Response
    {
        if (!$this->available()) {
            return View::page('code', $this->base($request) + ['error' => 'Agent sign-in is not available.', 'attrs' => ' data-aauth-state="code"'], 404);
        }

        return View::page('sso', $this->base($request) + ['ssoPath' => SsoLogin::PATH, 'script' => true, 'attrs' => ' data-aauth-state="sso"']);
    }

    /** POST /aauth/interact/sso {state, session_token}: signs the person in to this consent session. */
    public function ssoComplete(Request $request): Response
    {
        if (!$this->available()) {
            return View::page('code', $this->base($request) + ['error' => 'Agent sign-in is not available.', 'attrs' => ' data-aauth-state="code"'], 404);
        }

        return self::finishSso($request);
    }

    /**
     * Validates state + token, signs the person in, and redirects (303) to the request's consent
     * card, or to the grants page when single sign-on was started there.
     */
    public static function finishSso(Request $request): Response
    {
        $base = ['csrf' => csrf_token(), 'title' => 'DreamFactory'];
        if (Throttle::exceeded('sso-ip', ClientIp::of($request), self::MAX_FAILURES * 3, self::FAILURE_WINDOW)) {
            return View::page('code', $base + ['error' => 'Too many attempts. Try again in a few minutes.', 'attrs' => ' data-aauth-state="code"'], 429);
        }
        $done = SsoLogin::complete($request, (string)$request->input('state', ''), (string)$request->input('session_token', ''));
        $p = $done['pid'] !== null ? Pending::find($done['pid']) : null;
        if ($done['user_id'] === null) {
            Throttle::hit('code-ip', ClientIp::of($request), self::FAILURE_WINDOW);
            $why = $done['matched'] ? 'Single sign-on did not complete. Try again.' : 'This sign-in link has expired. Try again.';
            if ($p && Pending::isLive($p)) {
                return self::redirect('/aauth/interact?code=' . rawurlencode(Pending::displayCode($p['code'])) . '&sso=failed');
            }

            return View::page('code', $base + ['error' => $why, 'attrs' => ' data-aauth-state="code"'], 200);
        }
        $request->session()->regenerate();
        $request->session()->put(self::UID, $done['user_id']);
        if ($done['pid'] === null) {
            return self::redirect('/aauth/grants');
        }
        if (!$p) {
            return View::page('code', $base + ['error' => 'This request has expired. Ask the agent for a new code.', 'attrs' => ' data-aauth-state="code"'], 200);
        }

        return self::redirect('/aauth/interact?code=' . rawurlencode(Pending::displayCode($p['code'])));
    }

    public function script(): Response
    {
        $js = (string)file_get_contents(dirname(__DIR__, 2) . '/resources/assets/interact.js');

        return new Response($js, 200, ['Content-Type' => 'application/javascript; charset=UTF-8', 'Cache-Control' => 'public, max-age=300', 'X-Content-Type-Options' => 'nosniff']);
    }

    // --------------------------------------------------------------------------------------------

    private function available(): bool
    {
        return Settings::enabled() && Settings::localPersonServerEnabled();
    }

    /**
     * A code from the link (GET, $claim false) or typed into the code card (POST, $claim true).
     * Opening a link only remembers the request in this browser's session and shows its card: link
     * previews and mail scanners fetch links first, and must not take the code from the person.
     */
    private function openCode(Request $request, string $code, bool $claim): Response
    {
        if ($this->failures($request) >= self::MAX_FAILURES) {
            return $this->codeCard($request, 'Too many attempts. Try again in a few minutes.', $code, 429);
        }
        $p = Pending::findLiveByCode($code);
        if (!$p) {
            $this->fail($request);
            $old = Pending::findByCode($code);
            $callback = $old ? $this->validCallback((string)$request->query('callback', ''), $old) : null;
            if ($old && $callback !== null && !in_array($old['status'], ['approved', 'delivered'], true)) {
                // §7.3.1: send a browser-based agent back with the reason instead of leaving it waiting
                $error = $old['status'] === 'denied' ? 'access_denied' : 'interaction_expired';

                return $this->codeCard($request, 'This request has expired. Ask the agent for a new code.', '', 200, $this->withQuery($callback, 'error', $error));
            }

            return $this->codeCard($request, 'Unknown or expired code.', $code);
        }
        if ($claim ? !$this->claim($request, $p) : Pending::claimedElsewhere($p, $this->browser($request))) {
            return $this->alreadyUsed($request);
        }
        $this->allowPid($request, $p['id']);
        $callback = $this->validCallback((string)$request->query('callback', ''), $p);
        if ($callback !== null) {
            $request->session()->put('aauth_ps.cb.' . $p['id'], $callback);
        }

        return $this->state($request, $p, $this->user($request));
    }

    /** Claims a live request for this browser (single-use code) and marks it interacting. */
    private function claim(Request $request, array $p): bool
    {
        if (!Pending::claim($p, $this->browser($request))) {
            return false;
        }
        Pending::markInteracting($p['id']);
        $claimed = array_slice(array_values(array_unique(array_merge((array)$request->session()->get(self::CLAIMED, []), [$p['id']]))), -20);
        $request->session()->put(self::CLAIMED, $claimed);

        return true;
    }

    /**
     * Another browser owns this request: it holds the claim, or (once the shared claim record has
     * expired) the request was decided and this browser never claimed it. Decisions need a claim.
     */
    private function ownedElsewhere(Request $request, array $p): bool
    {
        if (Pending::claimedElsewhere($p, $this->browser($request))) {
            return true;
        }

        return in_array($p['status'], ['approved', 'delivered', 'denied'], true)
            && !in_array($p['id'], (array)$request->session()->get(self::CLAIMED, []), true);
    }

    private function alreadyUsed(Request $request): Response
    {
        $this->fail($request);

        return $this->codeCard($request, 'This code was already used in another browser. Ask the agent for a new code.', '', 200);
    }

    private function signIn(Request $request, array $p): Response
    {
        $email = trim((string)$request->input('email'));
        $service = trim((string)$request->input('service', ''));
        $result = SignIn::attempt($request, $email, (string)$request->input('password'), $service);
        if ($result['status'] === 'throttled') {
            return $this->state($request, $p, null, 'Too many attempts. Try again in a few minutes.', $email, 429);
        }
        if ($result['status'] !== 'ok') {
            if (Throttle::hit('pid-login', $p['id'], self::FAILURE_WINDOW * 2) >= self::MAX_REQUEST_FAILURES) {
                // the pending request fails for good: the agent's poll gets 410 invalid_code
                Pending::fail($p['id']);

                return $this->codeCard($request, 'Too many failed sign-ins. Ask the agent to start again.');
            }

            return $this->state($request, $p, null, $service !== '' ? 'Wrong username or password.' : 'Wrong email or password.', $email);
        }
        $request->session()->regenerate();
        $request->session()->put(self::UID, $result['user_id']);
        $user = Users::find($result['user_id']);

        // Signing in is not consent: show "Continue as ..." with Deny (identity) or the scopes (consent).
        return $this->state($request, $p, $user);
    }

    private function approvePerson(Request $request, array $p, array $user): Response
    {
        $minted = Minter::personToken($p, $user);
        if (!Pending::approve($p['id'], $minted['token'], $minted['exp'], (int)$user['id'], $minted['sub'])) {
            return $this->finished($request, Pending::find($p['id']));
        }
        $request->session()->put(self::NEXT, ['sub' => $minted['sub'], 'jkt' => $p['agent']['jkt'] ?? '', 'since' => time()]);
        $callback = $request->session()->pull('aauth_ps.cb.' . $p['id']);
        if (is_string($callback) && $callback !== '') {
            return $this->done($request, $p, true, $callback);
        }

        return View::page('next', $this->base($request) + $this->agentIdentity($p) + $this->resourceInfo($p) + [
            'heading' => $this->agentName($p),
            'code' => Pending::displayCode($p['code']),
            'script' => true,
            'attrs' => ' data-aauth-state="next" data-next-url="/aauth/interact/next"',
        ]);
    }

    private function approveAuth(Request $request, array $p, array $user): Response
    {
        $requested = array_values(array_filter(explode(' ', (string)$p['scope'])));
        $grantable = ConsentPolicy::grantable($user, $requested, $p['resource']);
        $granted = array_values(array_filter($requested, fn ($s) => $grantable[$s] ?? false));
        $posted = $request->input('scopes');
        if ($request->has('scopes_shown') && !is_array($posted)) {
            $posted = []; // the consent card showed checkboxes and every one was cleared
        }
        $any = $granted !== [];
        if (is_array($posted)) {
            $granted = array_values(array_intersect($granted, array_map('strval', $posted)));
        }
        $already = (array)($p['agent']['granted'] ?? []);
        if (!$granted || !array_diff($granted, $already)) {
            return $this->state($request, $p, $user, $any ? 'Select at least one new scope to allow, or deny.' : "You don't have a role that allows this.");
        }
        $minted = Minter::authToken($p, $user, $granted);
        if (!Pending::approve($p['id'], $minted['token'], $minted['exp'], (int)$user['id'])) {
            return $this->finished($request, Pending::find($p['id']));
        }
        if ($request->boolean('always')) {
            Grants::save((int)$user['id'], $p['resource'], $p['resource_name'], (string)($p['agent']['iss'] ?? ''),
                (string)($p['agent']['sub'] ?? ''), $p['agent']['name'] ?? null, $granted);
        }

        return $this->done($request, $p, true);
    }

    /** Renders the card for a live pending request and the current person. */
    private function state(Request $request, array $p, ?array $user, ?string $error = null, ?string $email = null, int $status = 200): Response
    {
        $base = $this->base($request) + $this->agentIdentity($p) + $this->resourceInfo($p) + [
            'heading' => $this->agentName($p),
            'pid' => $p['id'],
            'code' => Pending::displayCode($p['code']),
            'justification' => $p['justification'],
            'error' => $error,
        ];
        if ($user && $p['kind'] === 'auth' && $p['user_id'] !== null && $p['user_id'] !== (int)$user['id']) {
            $request->session()->forget(self::UID);
            $user = null;
            $base['error'] = $error ?? 'Sign in as the person this agent acts for.';
        }
        if (!$user) {
            if ($error === null && $request->query('sso') === 'failed') {
                $base['error'] = 'Single sign-on did not complete. Try again.';
            }

            return View::page('signin', $base + self::signInOptions($request) + ['email' => $email, 'canDeny' => true, 'attrs' => ' data-aauth-state="signin"'], $status);
        }
        $base += ['userName' => Users::displayName($user), 'userEmail' => (string)$user['email']];
        if ($p['kind'] === 'person') {
            return View::page('identity', $base + [
                'userFirst' => Users::firstName($user),
                'attrs' => ' data-aauth-state="identity"',
            ]);
        }
        $requested = array_values(array_filter(explode(' ', (string)$p['scope'])));
        $grantable = ConsentPolicy::grantable($user, $requested, $p['resource']);
        $scopes = [];
        foreach ($requested as $s) {
            $scopes[] = ['scope' => $s, 'description' => (string)($p['scope_descriptions'][$s] ?? $s), 'grantable' => (bool)($grantable[$s] ?? false)];
        }

        $already = (array)($p['agent']['granted'] ?? []);
        $newGrantable = array_filter($scopes, fn ($s) => $s['grantable'] && !in_array($s['scope'], $already, true));

        return View::page('consent', $base + [
            'scopes' => $scopes,
            'anyGrantable' => $newGrantable !== [],
            'attrs' => ' data-aauth-state="consent"',
        ]);
    }

    /** The sign-in card's choices: directory services, single sign-on, the login attribute. */
    public static function signInOptions(Request $request): array
    {
        try {
            $directories = app(Accounts::class)->directories();
        } catch (\Throwable $e) {
            $directories = [];
        }

        return [
            'directories' => $directories,
            'service' => trim((string)$request->input('service', '')),
            'sso' => SsoLogin::offered(),
            'loginAttribute' => strtolower((string)config('df.login_attribute', 'email')) === 'username' ? 'username' : 'email',
        ];
    }

    /** 303 to a same-origin path or our own issuer URL, with the consent page headers. */
    public static function redirect(string $url): Response
    {
        return View::secure(new RedirectResponse($url, 303));
    }

    private function done(Request $request, array $p, bool $approved, ?string $callback = null): Response
    {
        $callback ??= $request->session()->pull('aauth_ps.cb.' . $p['id']);
        $refresh = null;
        if (is_string($callback) && $callback !== '') {
            $refresh = $approved ? $callback : $this->withQuery($callback, 'error', 'access_denied');
        }

        return View::page('done', $this->base($request) + $this->agentIdentity($p) + [
            'heading' => $this->agentName($p),
            'approved' => $approved,
            'refresh' => $refresh,
            'code' => Pending::displayCode($p['code']),
            'attrs' => ' data-aauth-state="done" data-aauth-result="' . ($approved ? 'approved' : 'denied') . '"',
        ]);
    }

    /** A request that is no longer live: show its outcome when known, else the code card. */
    private function finished(Request $request, ?array $p): Response
    {
        if ($p && in_array($p['status'], ['approved', 'delivered'], true)) {
            return $this->done($request, $p, true);
        }
        if ($p && in_array($p['status'], ['denied'], true)) {
            return $this->done($request, $p, false);
        }
        $callback = $p ? $request->session()->pull('aauth_ps.cb.' . $p['id']) : null;
        $refresh = is_string($callback) && $callback !== '' ? $this->withQuery($callback, 'error', 'interaction_expired') : null;

        return $this->codeCard($request, 'This request has expired. Ask the agent for a new code.', '', 200, $refresh);
    }

    private function codeCard(Request $request, ?string $error = null, string $value = '', int $status = 200, ?string $refresh = null): Response
    {
        return View::page('code', $this->base($request) + ['error' => $error, 'value' => $value, 'refresh' => $refresh, 'attrs' => ' data-aauth-state="code"'], $status);
    }

    private function base(Request $request): array
    {
        return ['csrf' => csrf_token(), 'title' => 'DreamFactory'];
    }

    private function user(Request $request): ?array
    {
        $uid = $request->session()->get(self::UID);
        if (!$uid) {
            return null;
        }
        $user = Users::find((int)$uid);
        if (!$user || !$user['is_active']) {
            $request->session()->forget(self::UID);

            return null;
        }

        return $user;
    }

    private function allowPid(Request $request, string $pid): void
    {
        $pids = array_slice(array_values(array_unique(array_merge((array)$request->session()->get(self::PIDS, []), [$pid]))), -20);
        $request->session()->put(self::PIDS, $pids);
    }

    private function agentName(array $p): string
    {
        $name = trim((string)($p['agent']['name'] ?? ''));

        return $name !== '' ? $name : (string)($p['agent']['sub'] ?? 'Agent');
    }

    /** The verified agent identity shown under the self-asserted name: sub and the agent provider host. */
    private function agentIdentity(array $p): array
    {
        $named = trim((string)($p['agent']['name'] ?? '')) !== '';

        return [
            'agentSub' => (string)($p['agent']['sub'] ?? ''),
            'agentHost' => (string)parse_url((string)($p['agent']['iss'] ?? ''), PHP_URL_HOST),
            'agentNamed' => $named,
            // verified iss + sub, so a third-party agent can't borrow the DreamFactory gear by its name
            'agentPlayground' => AgentProvider::isPlayground($p['agent']['iss'] ?? null, $p['agent']['sub'] ?? null),
        ];
    }

    /** The resource the agent wants: its (self-asserted) name and its host, shown together. */
    private function resourceInfo(array $p): array
    {
        $host = (string)parse_url((string)$p['resource'], PHP_URL_HOST);

        return ['resourceName' => $p['resource_name'] ?: $host, 'resourceHost' => $host];
    }

    /** A random id for this browser's session (survives session id regeneration at sign-in). */
    private function browser(Request $request): string
    {
        $id = $request->session()->get(self::BROWSER);
        if (!is_string($id) || $id === '') {
            $id = Ids::random(16);
            $request->session()->put(self::BROWSER, $id);
        }

        return $id;
    }

    /** The callback must match the agent's registered callback_endpoint (origin + path); a query is allowed. */
    private function validCallback(string $callback, array $p): ?string
    {
        $registered = (string)($p['agent']['callback_endpoint'] ?? '');
        if ($callback === '' || $registered === '') {
            return null;
        }
        $c = parse_url($callback);
        $r = parse_url($registered);
        if (!is_array($c) || !is_array($r) || isset($c['fragment']) || isset($c['user'])) {
            return null;
        }
        $norm = fn (array $u) => strtolower(($u['scheme'] ?? '') . '://' . ($u['host'] ?? '') . (isset($u['port']) ? ':' . $u['port'] : '')) . ($u['path'] ?? '/');
        if (($c['scheme'] ?? '') !== 'https' && !Settings::allowInsecure()) {
            return null;
        }

        return $norm($c) === $norm($r) ? $callback : null;
    }

    private function withQuery(string $url, string $key, string $value): string
    {
        return $url . (str_contains($url, '?') ? '&' : '?') . rawurlencode($key) . '=' . rawurlencode($value);
    }

    /** Wrong codes: counted per client address and per browser session (the larger count wins). */
    private function failures(Request $request): int
    {
        return max(Throttle::count('code-ip', ClientIp::of($request)), Throttle::count('code-session', $this->browser($request)));
    }

    private function fail(Request $request): void
    {
        Throttle::hit('code-ip', ClientIp::of($request), self::FAILURE_WINDOW);
        Throttle::hit('code-session', $this->browser($request), self::FAILURE_WINDOW);
    }

    private function json(array $data): JsonResponse
    {
        return View::secure(new JsonResponse($data, 200, [], JSON_UNESCAPED_SLASHES));
    }
}
