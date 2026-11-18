<?php

namespace DreamFactory\Core\AAuth\Http\Middleware;

use DreamFactory\Core\AAuth\Protocol\AAuthError;
use DreamFactory\Core\AAuth\Protocol\Requirement;
use DreamFactory\Core\AAuth\Resource\Agents;
use DreamFactory\Core\AAuth\Resource\PersonServers;
use DreamFactory\Core\AAuth\Resource\RequestVerifier;
use DreamFactory\Core\AAuth\Resource\ResourceTokens;
use DreamFactory\Core\AAuth\Resource\ScopeResolver;
use DreamFactory\Core\AAuth\Resource\Scopes;
use DreamFactory\Core\AAuth\PersonServer\ConsentPolicy;
use DreamFactory\Core\AAuth\PersonServer\Subjects;
use DreamFactory\Core\AAuth\Support\Activity;
use DreamFactory\Core\AAuth\Support\BackingApp;
use DreamFactory\Core\AAuth\Support\ClientIp;
use DreamFactory\Core\AAuth\Support\Throttle;
use DreamFactory\Core\AAuth\Support\Problem;
use DreamFactory\Core\AAuth\Support\RawRequest;
use DreamFactory\Core\AAuth\Support\RoleGate;
use DreamFactory\Core\AAuth\Support\Settings;
use DreamFactory\Core\AAuth\Support\Users;
use DreamFactory\Core\Enums\ServiceRequestorTypes;
use DreamFactory\Core\Enums\Verbs;
use DreamFactory\Core\Models\User;
use DreamFactory\Core\Utility\Session;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Log;
use Symfony\Component\HttpFoundation\Response;

/**
 * df.aauth: runs in df.api right after df.auth_check and before df.access_check.
 *
 * A request without a Signature-Key header passes through untouched (when AAuth is enabled and DF
 * answers its own "no API key / session" 400/401, the response gains a Link to the resource
 * metadata, plus AAuth-Requirement on a 401; status and body never change). With AAuth disabled, signed requests also pass through.
 *
 * A signed request is verified and attributed to an agent: the one an agent token names, the one a
 * person or auth token of this DreamFactory's person server was issued for (401 invalid_jwt when it
 * has no record of the token), or for an external person server's token the signing key's agent. It is
 * refused when that agent or any agent id its signing key has used is blocked (403 agent_blocked; 503
 * temporarily_unavailable when the system database cannot say) and when an agent token names one
 * agent id more than a signing key may use (403 too_many_agents), and then, by token type:
 *  - agent token  -> 401 requirement=person-token
 *  - person token -> 401 requirement=auth-token + a resource token for the least privileged scope
 *                    that covers the request (403 insufficient_scope when none does)
 *  - auth token   -> the granted scope's role is seeded into the DreamFactory session (plus the
 *                    person's DF user when our own PS issued the token, never as sys admin), and the
 *                    request continues to AccessCheck; or a step-up 401 when no granted scope covers it.
 */
class AAuthMiddleware
{
    /** Activity rows per client and minute for requests that failed before any token was verified. */
    public const UNVERIFIED_LOG_LIMIT = 20;

    private ScopeResolver $scopes;

    public function __construct(?ScopeResolver $scopes = null)
    {
        $this->scopes = $scopes ?? new ScopeResolver();
    }

    public function handle(Request $request, \Closure $next)
    {
        if (!$request->headers->has('Signature-Key')) {
            $response = $next($request);
            $this->hint($response);

            return $response;
        }
        if (!Settings::enabled()) {
            return $next($request);
        }

        $method = RawRequest::method($request);
        $path = (string)parse_url((string)($_SERVER['REQUEST_URI'] ?? $request->getRequestUri()), PHP_URL_PATH);
        $log = ['method' => $method, 'path' => $path];

        try {
            if (Session::getApiKey() || Session::getSessionToken()) {
                throw new AAuthError(400, 'invalid_request', 'Send either AAuth signatures or a DreamFactory API key/session token, not both.');
            }
            if ($method !== strtoupper($request->getMethod()) || $request->headers->has('X-HTTP-Method')
                || $request->headers->has('X-HTTP-Method-Override') || $request->headers->has('X-Method-Override')) {
                throw new AAuthError(400, 'invalid_request', 'Method overrides are not allowed on AAuth-signed requests.');
            }
            if (stripos((string)$request->headers->get('Content-Type'), 'multipart/form-data') !== false) {
                throw new AAuthError(400, 'invalid_request', 'Multipart bodies cannot be covered by Content-Digest; send JSON.');
            }

            $v = RequestVerifier::verify(RawRequest::parts($request), [RequestVerifier::AGENT, RequestVerifier::PERSON, RequestVerifier::AUTH], true,
                fn (string $typ, array $payload) => PersonServers::preCheck($typ, $payload));
        } catch (AAuthError $e) {
            // nothing is verified yet: log at most UNVERIFIED_LOG_LIMIT rows per client per minute so
            // junk Signature-Key headers cannot flood the activity log
            if (!Throttle::exceeded('activity-unverified', ClientIp::of($request), self::UNVERIFIED_LOG_LIMIT, 60)) {
                $outcome = $e->status === 403 ? 'denied' : 'error';
                Activity::log($log + ['status' => $e->status, 'outcome' => $outcome, 'detail' => $e->error . ($e->detail ? ': ' . $e->detail : '')]);
            }

            return Problem::fromError($e);
        }

        $claims = $v['claims'];
        // Who is the agent? The agent token, or the agent our person server issued the token for, or
        // the signing key; a key bound to any blocked agent stays refused, whatever sub a new agent
        // token claims (Agents::admit).
        try {
            [$identity, $agent] = Agents::admit($v, true);
        } catch (AAuthError $e) {
            Activity::log($log + ['status' => $e->status, 'outcome' => 'error', 'detail' => $e->error . ': ' . $e->detail]);

            return Problem::fromError($e);
        } catch (\Throwable $e) {
            // the block state is unknown, and unknown is never "allowed"
            Log::error('df-aauth: agent state unavailable, signed request refused: ' . $e->getMessage());
            Activity::log($log + ['status' => 503, 'outcome' => 'error', 'detail' => 'temporarily_unavailable: agent state unavailable']);

            return Problem::unavailable();
        }
        $log += ['agent_row_id' => $agent['id'] ?? null, 'agent_id' => $identity['agent_id']];
        if ($agent['status'] === 'blocked') {
            Activity::log($log + ['status' => 403, 'outcome' => 'blocked']);

            return Problem::response(403, 'agent_blocked', 'This agent is blocked on this DreamFactory.');
        }

        if ($v['typ'] === RequestVerifier::AGENT) {
            Activity::log($log + ['status' => 401, 'outcome' => 'person_required']);

            return Problem::response(401, 'person_token_required', 'Get a person token from your person server and sign with it.',
                ['AAuth-Requirement' => Requirement::header('person-token')]);
        }

        $issuer = Settings::issuer();
        $service = strtolower((string)$request->route('service'));
        $component = strtolower((string)$request->route('resource'));
        $what = trim($method . ' ' . trim($service . '/' . $component, '/'));
        $tokenPs = (string)($claims['iss'] ?? '');
        $log += ['ps_issuer' => $tokenPs, 'person_sub' => (string)($claims['sub'] ?? '')];
        if (($claims['iss'] ?? null) === $issuer && !empty($claims['sub'])) {
            $log['user_id'] = Subjects::userFor((string)$claims['sub']);
        }

        try {
            if (($claims['aud'] ?? null) !== $issuer) {
                throw AAuthError::signature('invalid_jwt', "Token audience must be $issuer.");
            }
            if (empty($claims['sub'])) {
                throw AAuthError::signature('invalid_jwt', 'The token has no sub.');
            }
            // trust is anchored on the verified signer; auth tokens must be PS-issued with ps == iss
            $tokenPs = PersonServers::anchor($v['typ'], $claims);
        } catch (AAuthError $e) {
            Activity::log($log + ['status' => $e->status, 'outcome' => 'error', 'detail' => $e->error . ': ' . $e->detail]);

            return Problem::fromError($e);
        }

        $psRow = PersonServers::trusted($tokenPs);
        if ($psRow === null) {
            Activity::log($log + ['status' => 403, 'outcome' => 'denied', 'detail' => 'untrusted person server']);

            return Problem::response(403, 'untrusted_person_server', "Person server $tokenPs is not trusted by this DreamFactory.");
        }
        PersonServers::touch($psRow['id']);

        $needed = $this->scopes->covering($service, $component, $method, $psRow);

        if ($v['typ'] === RequestVerifier::PERSON) {
            if ($needed === null) {
                Activity::log($log + ['status' => 403, 'outcome' => 'denied', 'detail' => "No scope allows $what"]);

                return Problem::response(403, 'insufficient_scope', "No scope allows $what");
            }
            $rt = ResourceTokens::mint($claims, $tokenPs, $v['jkt'], $needed['scope']);
            Activity::log($log + ['status' => 401, 'outcome' => 'auth_required', 'scope' => $needed['scope']]);

            return Problem::response(401, 'auth_token_required', "Ask your person server for an auth token for scope {$needed['scope']}.",
                ['AAuth-Requirement' => Requirement::header('auth-token', ['resource-token' => $rt])]);
        }

        // Auth token. A granted scope counts only when its role held the name at the token's iat: a
        // token issued for an earlier role with that name (deleted or renamed away) never reaches it.
        $granted = array_values(array_filter(explode(' ', (string)($claims['scope'] ?? ''))));
        $candidates = $this->scopes->candidates($psRow);
        $iat = (int)($claims['iat'] ?? 0);
        $resourceGranted = array_values(array_filter($granted, fn ($s) => isset($candidates[$s]) && Scopes::heldAt($candidates[$s], $iat)));
        $use = $resourceGranted ? $this->scopes->covering($service, $component, $method, $psRow, $resourceGranted) : null;
        if ($use === null) {
            if ($needed === null) {
                Activity::log($log + ['status' => 403, 'outcome' => 'denied', 'detail' => "No scope allows $what"]);

                return Problem::response(403, 'insufficient_scope', "No scope allows $what");
            }
            $ask = array_values(array_unique(array_merge($granted, [$needed['scope']])));
            $rt = ResourceTokens::mint($claims, $tokenPs, $v['jkt'], implode(' ', $ask));
            Activity::log($log + ['status' => 401, 'outcome' => 'auth_required', 'scope' => $needed['scope'], 'detail' => 'step-up']);

            return Problem::response(401, 'insufficient_scope', "Scope {$needed['scope']} is needed for $what.",
                ['AAuth-Requirement' => Requirement::header('auth-token', ['resource-token' => $rt])]);
        }

        if (($claims['iss'] ?? null) === $issuer) {
            // our own PS issued it: the person must still be active and still hold the scope's role
            $uid = Subjects::userFor((string)$claims['sub']);
            $person = $uid ? Users::find($uid) : null;
            if (!$person || empty($person['is_active'])) {
                Activity::log($log + ['status' => 403, 'outcome' => 'denied', 'scope' => $use['scope'], 'detail' => 'person inactive or deleted']);

                return Problem::response(403, 'denied', 'The person this agent acts for is no longer active.');
            }
            if (!(ConsentPolicy::grantable($person, [$use['scope']], $issuer)[$use['scope']] ?? false)) {
                Activity::log($log + ['status' => 403, 'outcome' => 'denied', 'scope' => $use['scope'], 'detail' => 'person no longer holds the role']);

                return Problem::response(403, 'insufficient_scope', "The person no longer holds the role behind scope {$use['scope']}.");
            }
        }

        $userId = null;
        try {
            $this->authenticate($use, $claims, $issuer, $identity, $userId);
        } catch (\Throwable $e) {
            Log::warning('df-aauth: could not seed the session: ' . $e->getMessage());
            Activity::log($log + ['status' => 403, 'outcome' => 'denied', 'scope' => $use['scope'], 'detail' => 'role unavailable']);

            return Problem::response(403, 'insufficient_scope', "The role behind scope {$use['scope']} is not available.");
        }
        $log = ['user_id' => $userId ?? ($log['user_id'] ?? null), 'scope' => $use['scope']] + $log;

        if ($service !== '' && !Session::checkServicePermission($request->getMethod(), $service, $component, ServiceRequestorTypes::API, false)
            && !($request->getMethod() === Verbs::GET && $component === '_schema' && Session::getAllowedComponentsForGet($service))) {
            Activity::log($log + ['status' => 403, 'outcome' => 'denied', 'detail' => "No scope allows $what"]);

            return Problem::response(403, 'insufficient_scope', "No scope allows $what");
        }

        $response = $next($request);
        if ($response instanceof Response) {
            $response->headers->set('AAuth-Scope', $use['scope']);
            $status = $response->getStatusCode();
        } else {
            $status = 200;
        }
        Activity::log($log + ['status' => $status, 'outcome' => 'allowed']);

        return $response;
    }

    /** Seeds the DreamFactory session: role from the scope, the person's user (never sys admin), backing app. */
    private function authenticate(array $scope, array $claims, string $issuer, array $identity, ?int &$userId): void
    {
        $role = RoleGate::role((int)$scope['role_id']);
        if (!$role || empty($role['is_active'])) {
            throw new \RuntimeException('role inactive or missing');
        }
        $user = null;
        if (($claims['iss'] ?? null) === $issuer) {
            $uid = Subjects::userFor((string)$claims['sub']);
            if ($uid) {
                try {
                    $user = User::getCachedInfo($uid);
                    $user['is_sys_admin'] = false;
                    $userId = (int)$uid;
                } catch (\Throwable $e) {
                    $user = null;
                }
            }
        }
        \Session::forget('user');
        \Session::forget('role');
        \Session::put('app.id', BackingApp::id());
        if ($user) {
            Session::setUserInfo($user);
        }
        \Session::put('has_role', true);
        Session::setRoleInfo($role);
        Session::setSessionLookups();
        \Session::put('aauth', [
            'agent' => $identity['agent_id'],
            'agent_name' => $identity['name'] ?? null,
            'ps' => $claims['ps'] ?? $claims['iss'] ?? null,
            'sub' => $claims['sub'] ?? null,
            'scope' => $scope['scope'],
            'jti' => $claims['jti'] ?? null,
        ]);
        app()->instance('df.agent', (object)[
            'id' => null,
            'name' => ($identity['name'] ?? null) ?: $identity['agent_id'],
            'source' => 'aauth',
        ]);
    }

    /** Discovery hint on DF's own "no credentials" error when AAuth is enabled. Never changes status/body. */
    private function hint($response): void
    {
        try {
            if (!$response instanceof Response || !in_array($response->getStatusCode(), [400, 401], true)) {
                return;
            }
            if (Session::getApiKey() || Session::getSessionToken() || !Settings::enabled()) {
                return;
            }
            // the agent-token requirement pairs with 401 only; DF's own 400 just gets the discovery Link
            if ($response->getStatusCode() === 401) {
                $response->headers->set('AAuth-Requirement', Requirement::header('agent-token'));
            }
            $response->headers->set('Link', '<' . Settings::issuer() . '/.well-known/aauth-resource.json>; rel="aauth-resource"', false);
        } catch (\Throwable $e) {
            // never break a response over a hint
        }
    }
}
