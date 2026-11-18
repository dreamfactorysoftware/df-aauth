<?php

namespace DreamFactory\Core\AAuth\PersonServer;

use DreamFactory\Core\AAuth\Protocol\AAuthError;
use DreamFactory\Core\AAuth\Protocol\Discovery;
use DreamFactory\Core\AAuth\Protocol\Jwk;
use DreamFactory\Core\AAuth\Protocol\Requirement;
use DreamFactory\Core\AAuth\Resource\Agents;
use DreamFactory\Core\AAuth\Resource\RequestVerifier;
use DreamFactory\Core\AAuth\Resource\Scopes;
use DreamFactory\Core\AAuth\Support\AAuth;
use DreamFactory\Core\AAuth\Support\ClientIp;
use DreamFactory\Core\AAuth\Support\Throttle;
use DreamFactory\Core\AAuth\Support\Cors;
use DreamFactory\Core\AAuth\Support\Problem;
use DreamFactory\Core\AAuth\Support\RawRequest;
use DreamFactory\Core\AAuth\Support\Settings;
use DreamFactory\Core\AAuth\Support\Store;
use DreamFactory\Core\AAuth\Support\Users;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\Response;

/**
 * Person Server token endpoints. Every request is signed by the agent with its agent token.
 *   POST   /aauth/person        {resource, capabilities?, justification?}   -> 202 interaction (or 200)
 *   POST   /aauth/token         {resource_token, presented_token, justification?} -> 200 | 202
 *   GET    /aauth/pending/{id}  poll (same agent key only)
 *   DELETE /aauth/pending/{id}  cancel
 */
class PsController
{
    public const IDENTITY_DESCRIPTIONS = ['profile' => 'Your name', 'email' => 'Your email address'];
    /** §5.2 agent identifier: aauth:<local>@<domain>. */
    public const AGENT_SUB = '/^aauth:[A-Za-z0-9._+-]{1,255}@[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)*(:[0-9]{1,5})?$/';
    /** Live pending requests one agent may hold, and new ones per agent / client address per minute. */
    public const MAX_LIVE_PER_AGENT = 20;
    public const MAX_NEW_PER_MINUTE = 30;

    public function person(Request $request): Response
    {
        if ($request->isMethod('OPTIONS')) {
            return Cors::preflight('POST, OPTIONS');
        }

        return Cors::apply($this->guard(function () use ($request) {
            $v = $this->verifyAgent($request);
            $body = $this->json($request);
            $resource = rtrim(trim((string)($body['resource'] ?? '')), '/');
            try {
                Discovery::assertServerId($resource, Settings::allowInsecure());
            } catch (\Throwable $e) {
                throw new AAuthError(400, 'invalid_request', 'resource must be a server identifier (https origin).');
            }
            $caps = $body['capabilities'] ?? null;
            if (!is_array($caps) || !in_array('interaction', $caps, true)) {
                throw new AAuthError(403, 'user_unreachable', 'This person server must reach the person; declare the interaction capability.');
            }
            if (array_key_exists('mission_s256', $body)) {
                // the PS MUST check a requested mission; DreamFactory has no missions to check it against
                throw new AAuthError(400, 'invalid_request', 'This person server does not support missions (mission_s256).');
            }
            $this->admitPending($request, $v);
            $agent = $this->agentRecord($v, $body);
            $name = $this->resourceName($resource);
            $p = Pending::create('person', $agent, $resource, $name, [
                'justification' => $this->justification($body),
            ]);

            return $this->deferred($p);
        }), 'POST, OPTIONS');
    }

    public function token(Request $request): Response
    {
        if ($request->isMethod('OPTIONS')) {
            return Cors::preflight('POST, OPTIONS');
        }

        return Cors::apply($this->guard(function () use ($request) {
            $v = $this->verifyAgent($request);
            $body = $this->json($request);
            $issuer = Settings::issuer();
            $rtJwt = (string)($body['resource_token'] ?? '');
            $ptJwt = (string)($body['presented_token'] ?? '');
            if ($rtJwt === '' || $ptJwt === '') {
                throw new AAuthError(400, 'invalid_request', 'resource_token and presented_token are required.');
            }

            // 1. resource token
            $rt = $this->bodyToken($rtJwt, [RequestVerifier::RESOURCE], 'resource');
            $rc = $rt['payload'];
            // 2. audience: three-party only
            if (($rc['aud'] ?? null) !== $issuer) {
                throw new AAuthError(400, 'invalid_resource_token', 'The resource token is not addressed to this person server.');
            }
            // 3. bound to the signing agent key
            if (($rc['agent_jkt'] ?? null) !== $v['jkt']) {
                throw new AAuthError(400, 'invalid_resource_token', 'agent_jkt does not match the signing key.');
            }
            if (($rc['ps'] ?? null) !== $issuer) {
                throw new AAuthError(400, 'invalid_resource_token', 'The resource token names another person server.');
            }
            // 4. presented token: our own person token or auth token
            $pt = $this->bodyToken($ptJwt, [RequestVerifier::PERSON, RequestVerifier::AUTH], 'presented');
            $pc = $pt['payload'];
            if (($pc['iss'] ?? null) !== $issuer) {
                throw new AAuthError(400, 'invalid_presented_token', 'The presented token was not issued by this person server.');
            }
            if (($pc['aud'] ?? null) !== ($rc['iss'] ?? null)) {
                throw new AAuthError(400, 'invalid_presented_token', 'The presented token audience is not the resource.');
            }
            $cnf = $pc['cnf']['jwk'] ?? null;
            if (!is_array($cnf) || Jwk::thumbprint($cnf) !== $rc['agent_jkt']) {
                throw new AAuthError(400, 'invalid_presented_token', 'The presented token is bound to another key.');
            }
            // 5. binding between the two tokens
            $ptPs = $pt['typ'] === RequestVerifier::AUTH ? ($pc['ps'] ?? null) : ($pc['iss'] ?? null);
            if (($pc['jti'] ?? null) !== ($rc['presented_jti'] ?? null) || $ptPs !== $rc['ps']
                || ($pc['sub'] ?? null) !== ($rc['sub'] ?? null)
                || ($pc['mission_s256'] ?? null) !== ($rc['mission_s256'] ?? null)
                || ($pc['tenant'] ?? null) !== ($rc['tenant'] ?? null)) {
                throw new AAuthError(400, 'invalid_resource_token', 'The resource token does not match the presented token.');
            }
            $subject = Subjects::find((string)$rc['sub']);
            if (!$subject || $subject['resource'] !== $rc['iss']) {
                throw new AAuthError(400, 'invalid_presented_token', 'Unknown subject.');
            }
            $user = Users::find($subject['user_id']);
            if (!$user || !$user['is_active']) {
                throw new AAuthError(403, 'denied', 'The person is no longer active.');
            }

            $resource = (string)$rc['iss'];
            $requested = array_values(array_unique(array_filter(explode(' ', (string)($rc['scope'] ?? '')))));
            if (!$requested) {
                throw new AAuthError(400, 'invalid_resource_token', 'The resource token requests no scope.');
            }
            // Resource tokens are single-use at the PS (design 4.2: aauth:rt:{jti}), but idempotent for
            // the agent key they are bound to: a retry after a lost 202 gets the same pending request.
            // The jti is burned only once a pending request exists, so a failed attempt can be retried.
            $rtJti = (string)($rc['jti'] ?? '');
            if ($rtJti === '') {
                throw new AAuthError(400, 'invalid_resource_token', 'The resource token has no jti.');
            }
            $rtKey = 'aauth:rt:' . hash('sha256', $rc['iss'] . '|' . $rtJti);
            $rtTtl = max(1, (int)($rc['exp'] ?? 0) - time() + 60);
            $used = $this->cacheGet($rtKey);
            if ($used !== null) {
                $prior = is_string($used) ? Pending::find($used) : null;
                if ($prior && ($prior['agent']['jkt'] ?? null) === $v['jkt'] && in_array($prior['status'], ['pending', 'interacting', 'approved'], true)
                    && !Pending::isExpired($prior)) {
                    return $this->deferred($prior);
                }
                throw new AAuthError(400, 'invalid_resource_token', 'The resource token was already used.');
            }
            $meta = $this->resourceMeta($resource);
            $descriptions = [];
            $known = is_array($meta['scope_descriptions'] ?? null) ? $meta['scope_descriptions'] : [];
            foreach ($requested as $s) {
                $descriptions[$s] = isset($known[$s]) && is_string($known[$s]) ? $known[$s] : (self::IDENTITY_DESCRIPTIONS[$s] ?? $s);
            }
            // Step-up: scopes the presented auth token already carries (consent must add something new).
            $already = $pt['typ'] === RequestVerifier::AUTH ? array_values(array_filter(explode(' ', (string)($pc['scope'] ?? '')))) : [];
            $agent = $this->agentRecord($v, $body, [
                'mission_s256' => $rc['mission_s256'] ?? null, 'tenant' => $rc['tenant'] ?? null, 'account' => $rc['account'] ?? null,
            ]);
            $agent['granted'] = $already;
            $resourceName = trim((string)($meta['name'] ?? '')) ?: (string)parse_url($resource, PHP_URL_HOST);
            $extra = [
                'scope' => implode(' ', $requested),
                'scope_descriptions' => $descriptions,
                'justification' => $this->justification($body),
                'sub' => (string)$rc['sub'],
                'presented_exp' => (int)($pc['exp'] ?? 0) ?: null,
                'user_id' => (int)$user['id'],
            ];

            // Standing grant ("Always allow") covering every requested scope: answer now.
            $grant = Grants::find((int)$user['id'], $resource, $agent['iss'], $agent['sub']);
            $grantable = ConsentPolicy::grantable($user, $requested, $resource);
            if (Grants::covers($grant, $requested) && !in_array(false, $grantable, true)) {
                if (!$this->burn($rtKey, 'immediate', $rtTtl)) {
                    throw new AAuthError(400, 'invalid_resource_token', 'The resource token was already used.');
                }
                $p = Pending::create('auth', $agent, $resource, $resourceName, $extra + ['status' => 'interacting']);
                $minted = Minter::authToken($p, $user, $requested);
                Pending::approve($p['id'], $minted['token'], $minted['exp']);
                Pending::setStatus($p['id'], 'delivered');
                Grants::touch($grant['id']);

                return new JsonResponse(['auth_token' => $minted['token'], 'expires_in' => max(0, $minted['exp'] - time())], 200,
                    ['Cache-Control' => 'no-store'], JSON_UNESCAPED_SLASHES);
            }

            $this->admitPending($request, $v);
            $p = Pending::create('auth', $agent, $resource, $resourceName, $extra);
            if (!$this->burn($rtKey, $p['id'], $rtTtl)) {
                Pending::setStatus($p['id'], 'cancelled'); // lost a race with a concurrent use
                throw new AAuthError(400, 'invalid_resource_token', 'The resource token was already used.');
            }

            return $this->deferred($p);
        }), 'POST, OPTIONS');
    }

    public function poll(Request $request, string $id): Response
    {
        if ($request->isMethod('OPTIONS')) {
            return Cors::preflight('GET, DELETE, OPTIONS');
        }

        return Cors::apply($this->guard(function () use ($request, $id) {
            $v = $this->verifyAgent($request);
            $p = Pending::find($id);
            if (!$p || ($p['agent']['jkt'] ?? null) !== $v['jkt']) {
                throw new AAuthError(404, 'invalid_request', 'Unknown pending request.');
            }
            if ($request->isMethod('DELETE')) {
                if (Pending::isLive($p)) {
                    Pending::setStatus($id, 'cancelled');
                }

                return new Response('', 204, ['Cache-Control' => 'no-store']);
            }
            [$status, $body] = Pending::poll($p);
            if ($status === 200) {
                $field = $p['kind'] === 'person' ? 'person_token' : 'auth_token';

                return new JsonResponse([$field => $body['token'], 'expires_in' => $body['expires_in']], 200,
                    ['Cache-Control' => 'no-store'], JSON_UNESCAPED_SLASHES);
            }
            if ($status === 202) {
                $issuer = Settings::issuer();
                $code = Pending::displayCode($p['code']);

                return new JsonResponse($body + ['code' => $code], 202, [
                    'Location' => $issuer . '/aauth/pending/' . $p['id'],
                    'Retry-After' => '2',
                    'Cache-Control' => 'no-store',
                    'AAuth-Requirement' => Requirement::header('interaction', ['url' => $issuer . '/aauth/interact', 'code' => $code]),
                ], JSON_UNESCAPED_SLASHES);
            }

            return Problem::response($status, $body['error'], $body['detail'] ?? '');
        }), 'GET, DELETE, OPTIONS');
    }

    // ---------------------------------------------------------------------------------------------

    private function guard(\Closure $fn): Response
    {
        if (!Settings::enabled() || !Settings::localPersonServerEnabled()) {
            return Problem::response(404, 'not_found', 'Not found.');
        }
        try {
            return $fn();
        } catch (AAuthError $e) {
            return Problem::fromError($e);
        } catch (\Throwable $e) {
            \Log::error('df-aauth person server: ' . $e->getMessage(), ['exception' => $e]);

            return Problem::response(500, 'server_error', 'Unexpected error.');
        }
    }

    private function verifyAgent(Request $request): array
    {
        $v = RequestVerifier::verify(RawRequest::parts($request), [RequestVerifier::AGENT], false);
        if (isset($v['claims']['parent_agent'])) {
            throw AAuthError::signature('invalid_jwt', 'Sub-agent tokens are not supported by this person server.');
        }
        $sub = $v['claims']['sub'] ?? null;
        if (!is_string($sub) || $sub === '') {
            throw AAuthError::signature('invalid_jwt', 'The agent token has no sub.');
        }
        if (strlen($sub) > 300 || !preg_match(self::AGENT_SUB, $sub)) {
            throw AAuthError::signature('invalid_jwt', 'The agent token sub is not an agent identifier (aauth:name@domain).');
        }
        if (array_key_exists('ps', $v['claims'])) {
            try {
                Discovery::assertServerId((string)$v['claims']['ps'], Settings::allowInsecure());
            } catch (\Throwable $e) {
                throw AAuthError::signature('invalid_jwt', 'The agent token ps claim is not a server identifier.');
            }
        }
        // The person server records the key -> agent binding (the resource uses it to enforce blocks)
        // and lists the agent, so one that only talks to the person server can be blocked too. A key
        // bound to any blocked agent is refused, whatever sub this agent token claims.
        try {
            [, $agent] = Agents::admit($v, false);
        } catch (AAuthError $e) {
            throw $e; // a refusal (a key that used too many agent ids), not an unknown state
        } catch (\Throwable $e) {
            // unknown is never "allowed"
            \Log::error('df-aauth person server: agent state unavailable, request refused: ' . $e->getMessage());

            throw Problem::unavailableError();
        }
        if ($agent['status'] === 'blocked') {
            throw new AAuthError(403, 'agent_blocked', 'This agent is blocked on this DreamFactory.');
        }

        return $v;
    }

    /** Caps on deferred requests: live ones per agent, new ones per agent and per client per minute. */
    private function admitPending(Request $request, array $v): void
    {
        $iss = (string)$v['claims']['iss'];
        $sub = (string)$v['claims']['sub'];
        if (Throttle::exceeded('pending-agent', $iss . '|' . $sub, self::MAX_NEW_PER_MINUTE, 60)
            || Throttle::exceeded('pending-ip', ClientIp::of($request), self::MAX_NEW_PER_MINUTE * 2, 60)) {
            throw new AAuthError(429, 'rate_limited', 'Too many requests. Slow down.', ['Retry-After' => '60']);
        }
        if (Pending::liveCountForAgent($iss, $sub) >= self::MAX_LIVE_PER_AGENT) {
            throw new AAuthError(429, 'rate_limited', 'This agent already has too many requests waiting for the person.', ['Retry-After' => '60']);
        }
    }

    private function cacheGet(string $key): mixed
    {
        try {
            return Store::cache()->get($key);
        } catch (\Throwable $e) {
            return null;
        }
    }

    private function burn(string $key, string $value, int $ttl): bool
    {
        try {
            return Store::cache()->add($key, $value, $ttl);
        } catch (\Throwable $e) {
            return true;
        }
    }

    private function json(Request $request): array
    {
        $raw = (string)$request->getContent();
        $data = $raw === '' ? null : json_decode($raw, true);
        if (!is_array($data)) {
            throw new AAuthError(400, 'invalid_request', 'The body must be a JSON object.');
        }

        return $data;
    }

    /** Verifies a token given as a body parameter, mapping failures to the token endpoint codes. */
    private function bodyToken(string $jwt, array $typs, string $param): array
    {
        try {
            return RequestVerifier::token($jwt, $typs);
        } catch (AAuthError $e) {
            $code = match ($e->error) {
                'expired_jwt' => "expired_{$param}_token",
                'revoked_jwt' => "revoked_{$param}_token",
                'clock_skew' => 'clock_skew',
                default => "invalid_{$param}_token",
            };

            throw new AAuthError(400, $code, $e->detail);
        }
    }

    private function agentRecord(array $v, array $body, array $extra = []): array
    {
        $meta = $v['meta'];
        $callback = isset($meta['callback_endpoint']) && is_string($meta['callback_endpoint']) ? $meta['callback_endpoint'] : null;

        return [
            'sub' => (string)$v['claims']['sub'],
            'iss' => (string)$v['claims']['iss'],
            'name' => isset($meta['name']) && is_string($meta['name']) && trim($meta['name']) !== '' ? mb_substr(trim($meta['name']), 0, 120) : null,
            'jkt' => $v['jkt'],
            'jwk' => $v['jwk'],
            'exp' => (int)($v['claims']['exp'] ?? 0),
            'callback_endpoint' => $callback,
            'extra' => array_filter($extra, fn ($x) => $x !== null),
        ];
    }

    private function justification(array $body): ?string
    {
        $j = $body['justification'] ?? null;
        if (!is_string($j) || trim($j) === '') {
            return null;
        }

        return mb_substr(trim($j), 0, 1000);
    }

    private function resourceMeta(string $resource): array
    {
        if ($resource === Settings::issuer()) {
            return ['name' => Settings::instanceName(), 'scope_descriptions' => Scopes::descriptions()];
        }
        try {
            return AAuth::metadata($resource, 'aauth-resource.json');
        } catch (\Throwable $e) {
            return [];
        }
    }

    private function resourceName(string $resource): string
    {
        $meta = $this->resourceMeta($resource);

        return trim((string)($meta['name'] ?? '')) ?: (string)parse_url($resource, PHP_URL_HOST);
    }

    private function deferred(array $p): JsonResponse
    {
        $issuer = Settings::issuer();
        $code = Pending::displayCode($p['code']);

        return new JsonResponse(['status' => 'pending', 'code' => $code], 202, [
            'Location' => $issuer . '/aauth/pending/' . $p['id'],
            'Retry-After' => '2',
            'Cache-Control' => 'no-store',
            'AAuth-Requirement' => Requirement::header('interaction', ['url' => $issuer . '/aauth/interact', 'code' => $code]),
        ], JSON_UNESCAPED_SLASHES);
    }
}
