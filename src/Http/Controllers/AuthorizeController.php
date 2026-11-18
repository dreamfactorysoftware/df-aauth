<?php

namespace DreamFactory\Core\AAuth\Http\Controllers;

use DreamFactory\Core\AAuth\Protocol\AAuthError;
use DreamFactory\Core\AAuth\Protocol\Requirement;
use DreamFactory\Core\AAuth\Resource\Agents;
use DreamFactory\Core\AAuth\Resource\PersonServers;
use DreamFactory\Core\AAuth\Resource\RequestVerifier;
use DreamFactory\Core\AAuth\Resource\ResourceTokens;
use DreamFactory\Core\AAuth\Resource\ScopeResolver;
use DreamFactory\Core\AAuth\Support\Activity;
use DreamFactory\Core\AAuth\Support\Cors;
use DreamFactory\Core\AAuth\Support\Problem;
use DreamFactory\Core\AAuth\Support\RawRequest;
use DreamFactory\Core\AAuth\Support\Settings;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\Response;

/**
 * The resource authorization_endpoint (§6.6): POST {scope} signed with a person token (or an auth
 * token) -> 200 {resource_token}. Lets agents skip the 401 round trip. A key bound to a blocked
 * agent is refused here as on the APIs (403 agent_blocked; 503 when the block state is unknown), so a
 * blocked agent cannot get resource tokens to take to another person server.
 */
class AuthorizeController
{
    public function authorize(Request $request): Response
    {
        if ($request->isMethod('OPTIONS')) {
            return Cors::preflight('POST, OPTIONS');
        }
        if (!Settings::enabled()) {
            return Cors::apply(Problem::response(404, 'not_found', 'Not found.'));
        }
        try {
            $v = RequestVerifier::verify(RawRequest::parts($request),
                [RequestVerifier::AGENT, RequestVerifier::PERSON, RequestVerifier::AUTH], true,
                fn (string $typ, array $payload) => PersonServers::preCheck($typ, $payload));
            $refused = $this->refusal($request, $v);
            if ($refused !== null) {
                return Cors::apply($refused, 'POST, OPTIONS');
            }
            if ($v['typ'] === RequestVerifier::AGENT) {
                return Cors::apply(Problem::response(401, 'person_token_required', 'Sign this request with a person token.',
                    ['AAuth-Requirement' => Requirement::header('person-token')]), 'POST, OPTIONS');
            }
            $c = $v['claims'];
            if (($c['aud'] ?? null) !== Settings::issuer() || empty($c['sub'])) {
                throw AAuthError::signature('invalid_jwt', 'Token audience must be ' . Settings::issuer() . '.');
            }
            $ps = PersonServers::anchor($v['typ'], $c);
            $psRow = PersonServers::trusted($ps);
            if ($psRow === null) {
                throw new AAuthError(403, 'untrusted_person_server', "Person server $ps is not trusted by this DreamFactory.");
            }
            $body = json_decode((string)$request->getContent(), true);
            $scope = is_array($body) ? trim((string)($body['scope'] ?? '')) : '';
            if ($scope === '') {
                throw new AAuthError(400, 'invalid_request', 'scope is required.');
            }
            $asked = array_values(array_unique(array_filter(explode(' ', $scope))));
            $allowed = (new ScopeResolver())->candidates($psRow);
            $unknown = array_diff($asked, array_keys($allowed));
            if ($unknown) {
                throw new AAuthError(400, 'invalid_scope', 'Unknown or unavailable scope: ' . implode(' ', $unknown));
            }
            PersonServers::touch($psRow['id']);
            $rt = ResourceTokens::mint($c, $ps, $v['jkt'], implode(' ', $asked));

            return Cors::apply(new JsonResponse(['resource_token' => $rt], 200, ['Cache-Control' => 'no-store'], JSON_UNESCAPED_SLASHES), 'POST, OPTIONS');
        } catch (AAuthError $e) {
            return Cors::apply(Problem::fromError($e), 'POST, OPTIONS');
        } catch (\Throwable $e) {
            \Log::error('df-aauth authorize: ' . $e->getMessage());

            return Cors::apply(Problem::response(500, 'server_error', 'Unexpected error.'), 'POST, OPTIONS');
        }
    }

    /**
     * 403 for a key bound to a blocked agent (or an agent token naming one agent id more than a key
     * may use), 401 for a token of this person server it has no record of, 503 when the block state
     * cannot be known, else null (logged like the APIs).
     */
    private function refusal(Request $request, array $v): ?Response
    {
        $log = ['method' => 'POST', 'path' => '/' . ltrim($request->path(), '/')];
        try {
            [$identity, $agent] = Agents::admit($v, false);
        } catch (AAuthError $e) {
            Activity::log($log + ['status' => $e->status, 'outcome' => 'error', 'detail' => $e->error . ': ' . $e->detail]);

            return Problem::fromError($e);
        } catch (\Throwable $e) {
            \Log::error('df-aauth authorize: agent state unavailable, request refused: ' . $e->getMessage());
            Activity::log($log + ['status' => 503, 'outcome' => 'error', 'detail' => 'temporarily_unavailable: agent state unavailable']);

            return Problem::unavailable();
        }
        if ($agent['status'] !== 'blocked') {
            return null;
        }
        Activity::log($log + ['agent_row_id' => $agent['id'] ?? null, 'agent_id' => $identity['agent_id'], 'status' => 403, 'outcome' => 'blocked']);

        return Problem::response(403, 'agent_blocked', 'This agent is blocked on this DreamFactory.');
    }
}
