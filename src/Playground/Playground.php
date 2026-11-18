<?php

namespace DreamFactory\Core\AAuth\Playground;

use DreamFactory\Core\AAuth\AgentProvider\AgentProvider;
use DreamFactory\Core\AAuth\Protocol\Ids;
use DreamFactory\Core\AAuth\Protocol\Jwk;
use DreamFactory\Core\AAuth\Protocol\Jwt;
use DreamFactory\Core\AAuth\Support\Settings;
use DreamFactory\Core\AAuth\Support\Store;
use DreamFactory\Core\Exceptions\BadRequestException;
use DreamFactory\Core\Exceptions\NotFoundException;
use Illuminate\Support\Facades\Crypt;

/**
 * "Try it": a server-side agent hosted by this DreamFactory's Agent Provider. It makes REAL https
 * calls to {issuer}{path} (through the public TLS front end), follows the AAuth ladder
 * (agent token -> person token -> resource token -> auth token) with this DreamFactory's own Person
 * Server, and records every request/response as a step.
 *
 * Per admin: an Ed25519 agent key and the person/auth tokens (1 h) live in the cache. A run lives
 * in the cache for 15 minutes under aauth:pg:{user_id}:{run_id}. A cached token the API refuses with
 * a signature error and no requirement (no record of it, a revoked key) is forgotten, and the run
 * starts over once with the agent token.
 */
class Playground
{
    public const METHODS = ['GET', 'POST', 'PATCH', 'PUT', 'DELETE'];
    private const RUN_TTL = 900;
    private const TOKEN_TTL = 3600;
    private const MAX_CALLS = 6;
    private const REFRESH_MARGIN = 300;

    private Client $client;

    public function __construct(private int $userId, ?Client $client = null)
    {
        $this->client = $client ?? new Client();
    }

    public function handle(array $payload): array
    {
        $action = (string)($payload['action'] ?? '');

        return match ($action) {
            'send' => $this->send((string)($payload['method'] ?? 'GET'), (string)($payload['path'] ?? ''), $payload['body'] ?? null),
            'advance' => $this->advance((string)($payload['run_id'] ?? '')),
            'reset' => $this->reset(),
            default => throw new BadRequestException("action must be 'send', 'advance' or 'reset'."),
        };
    }

    public function send(string $method, string $path, $body): array
    {
        $method = strtoupper(trim($method));
        if (!in_array($method, self::METHODS, true)) {
            throw new BadRequestException('method must be one of ' . implode(', ', self::METHODS) . '.');
        }
        $path = trim($path);
        if ($path === '' || $path[0] !== '/' || str_starts_with($path, '//') || preg_match('/[\s\x00-\x1f]/', $path)) {
            throw new BadRequestException('path must start with / (for example /api/v2/sales/_table/orders).');
        }
        if (is_array($body)) {
            $body = json_encode($body, JSON_UNESCAPED_SLASHES);
        }
        $body = is_string($body) && trim($body) !== '' && in_array($method, ['POST', 'PATCH', 'PUT'], true) ? $body : null;
        if ($body !== null && json_decode($body) === null && json_last_error() !== JSON_ERROR_NONE) {
            throw new BadRequestException('body must be JSON.');
        }

        $run = [
            'run_id' => Ids::random(12),
            'status' => 'running',
            'method' => $method,
            'path' => $path,
            'body' => $body,
            'pending' => null,
            'error' => null,
            'steps' => [],
            'result' => null,
            'calls' => 0,
            'presenting' => 'agent',
            'agent_token' => null,
        ];
        $key = $this->agentKey();
        $agentToken = AgentProvider::agentToken(Jwk::publicOf($key), AgentProvider::playgroundSubject(), Settings::issuer());
        $run['agent_token'] = $agentToken;
        $run['steps'][] = $this->step('agent_token', AgentProvider::playgroundSubject(), null, null, [$agentToken]);

        $tokens = $this->tokens();
        if ($this->fresh($tokens, 'auth')) {
            $run['presenting'] = 'auth';
            $run['cached'] = true;
            $run['steps'][] = $this->step('reuse', 'Reuse auth token', null, null, [$tokens['auth_token']]);
        } elseif ($this->fresh($tokens, 'person')) {
            $run['presenting'] = 'person';
            $run['cached'] = true;
            $run['steps'][] = $this->step('reuse', 'Reuse person token', null, null, [$tokens['person_token']]);
        }

        return $this->out($this->loop($run, $key));
    }

    public function advance(string $runId): array
    {
        $run = $this->load($runId);
        if ($run['status'] !== 'waiting' || empty($run['pending']['location'])) {
            return $this->out($run);
        }
        $key = $this->agentKey();
        try {
            $x = $this->client->send('GET', $run['pending']['location'], null, $run['agent_token'], $key);
        } catch (\Throwable $e) {
            return $this->out($this->fail($run, $e->getMessage()));
        }
        $status = $x['response']['status'];
        $step = $this->step('poll', 'Poll ' . ($run['pending']['kind'] === 'person' ? 'person token' : 'auth token'), $x['request'], $x['response'], []);
        $last = end($run['steps']);
        if ($last && $last['kind'] === 'poll' && ($last['response']['status'] ?? 0) === 202) {
            array_pop($run['steps']);
        }
        if ($status === 202) {
            $run['steps'][] = $step;

            return $this->out($this->save($run));
        }
        $json = json_decode((string)$x['response']['body'], true);
        if ($status === 200 && is_array($json)) {
            $tokens = $this->tokens();
            if (!empty($json['person_token'])) {
                $tokens['person_token'] = $json['person_token'];
                $tokens['person_exp'] = $this->expOf($json['person_token']);
                unset($tokens['auth_token'], $tokens['auth_exp']);
                $run['presenting'] = 'person';
                $step['tokens'] = [$json['person_token']];
            } elseif (!empty($json['auth_token'])) {
                $tokens['auth_token'] = $json['auth_token'];
                $tokens['auth_exp'] = $this->expOf($json['auth_token']);
                $run['presenting'] = 'auth';
                $step['tokens'] = [$json['auth_token']];
            }
            $this->saveTokens($tokens);
            $run['steps'][] = $step;
            $run['pending'] = null;
            $run['status'] = 'running';

            return $this->out($this->loop($run, $key));
        }
        $run['steps'][] = $step;
        $run['pending'] = null;
        $error = is_array($json) ? (string)($json['error'] ?? 'error') : 'error';

        return $this->out($this->fail($run, $error === 'denied' ? 'The person denied the request.' : "Polling ended with HTTP $status ($error)."));
    }

    public function reset(): array
    {
        Store::cache()->forget($this->tokensKey());

        return ['run_id' => null, 'status' => 'done', 'pending' => null, 'error' => null, 'steps' => [], 'result' => null];
    }

    // --------------------------------------------------------------------------------------------

    private function loop(array $run, array $key): array
    {
        $issuer = Settings::issuer();
        while ($run['calls'] < self::MAX_CALLS) {
            $run['calls']++;
            $tokens = $this->tokens();
            $jwt = match ($run['presenting']) {
                'auth' => $tokens['auth_token'] ?? $run['agent_token'],
                'person' => $tokens['person_token'] ?? $run['agent_token'],
                default => $run['agent_token'],
            };
            try {
                $x = $this->client->send($run['method'], $issuer . $run['path'], $run['body'], $jwt, $key);
            } catch (\Throwable $e) {
                return $this->fail($run, $e->getMessage());
            }
            $status = $x['response']['status'];
            $req = (string)Client::header($x['response']['headers'], 'AAuth-Requirement');
            $resourceToken = self::param($req, 'resource-token');
            $run['steps'][] = $this->step('call', $run['method'] . ' ' . $run['path'], $x['request'], $x['response'], array_values(array_filter([$resourceToken])));
            $cached = !empty($run['cached']) && $run['presenting'] !== 'agent';
            $run['cached'] = false;

            if ($status === 401 && $req === '' && $cached && Client::header($x['response']['headers'], 'Signature-Error') !== null) {
                // the API no longer accepts the cached token (no record of it, a revoked key): forget
                // the cached tokens and start over, once, with the agent token
                $tokens = $this->tokens();
                unset($tokens['person_token'], $tokens['person_exp'], $tokens['auth_token'], $tokens['auth_exp']);
                $this->saveTokens($tokens);
                $run['presenting'] = 'agent';
                continue;
            }
            if ($status !== 401 || $req === '') {
                $run['status'] = 'done';
                $run['result'] = ['status' => $status, 'body' => $x['response']['body']];

                return $this->save($run);
            }
            $requirement = self::param($req, 'requirement');
            if ($requirement === 'agent-token') {
                $run['presenting'] = 'agent';
                continue;
            }
            if ($requirement === 'person-token') {
                $tokens = $this->tokens();
                unset($tokens['person_token'], $tokens['person_exp'], $tokens['auth_token'], $tokens['auth_exp']);
                $this->saveTokens($tokens);
                $meta = $this->discover($run);
                if ($meta === null) {
                    return $this->save($run);
                }
                $payload = json_encode(['resource' => $issuer, 'capabilities' => ['interaction'],
                    'justification' => 'Try it: ' . $run['method'] . ' ' . $run['path']], JSON_UNESCAPED_SLASHES);
                $next = $this->tokenRequest($run, $key, 'person_token', 'Person token', (string)$meta['person_token_endpoint'], $payload, 'person');
                if ($next !== null) {
                    return $next;
                }
                continue;
            }
            if ($requirement === 'auth-token' && $resourceToken) {
                $meta = $this->discover($run, true);
                if ($meta === null) {
                    return $this->save($run);
                }
                $presented = $run['presenting'] === 'auth' ? ($tokens['auth_token'] ?? null) : ($tokens['person_token'] ?? null);
                if (!$presented) {
                    $run['presenting'] = 'agent';
                    continue;
                }
                $payload = json_encode(['resource_token' => $resourceToken, 'presented_token' => $presented,
                    'justification' => 'Try it: ' . $run['method'] . ' ' . $run['path']], JSON_UNESCAPED_SLASHES);
                $next = $this->tokenRequest($run, $key, 'auth_token', 'Auth token', (string)$meta['auth_token_endpoint'], $payload, 'auth');
                if ($next !== null) {
                    return $next;
                }
                continue;
            }
            $run['status'] = 'done';
            $run['result'] = ['status' => $status, 'body' => $x['response']['body']];

            return $this->save($run);
        }

        return $this->fail($run, 'Too many round trips.');
    }

    /**
     * POSTs to a PS token endpoint. Returns the saved run when the flow must stop (waiting or failed),
     * or null to continue the loop with the new token.
     */
    private function tokenRequest(array &$run, array $key, string $kind, string $title, string $endpoint, string $payload, string $type): ?array
    {
        try {
            $x = $this->client->send('POST', $endpoint, $payload, $run['agent_token'], $key);
        } catch (\Throwable $e) {
            return $this->fail($run, $e->getMessage());
        }
        $status = $x['response']['status'];
        $json = json_decode((string)$x['response']['body'], true);
        $field = $type . '_token';
        $tokens = array_values(array_filter([json_decode($payload, true)['resource_token'] ?? null, is_array($json) ? ($json[$field] ?? null) : null]));
        $run['steps'][] = $this->step($kind, $title, $x['request'], $x['response'], $tokens);
        if ($status === 200 && is_array($json) && !empty($json[$field])) {
            $t = $this->tokens();
            $t[$field] = $json[$field];
            $t[$type . '_exp'] = $this->expOf($json[$field]);
            if ($type === 'person') {
                unset($t['auth_token'], $t['auth_exp']);
            }
            $this->saveTokens($t);
            $run['presenting'] = $type;

            return null;
        }
        if ($status === 202) {
            $req = (string)Client::header($x['response']['headers'], 'AAuth-Requirement');
            $code = self::param($req, 'code') ?? (is_array($json) ? ($json['code'] ?? null) : null);
            $url = self::param($req, 'url') ?? (Settings::issuer() . '/aauth/interact');
            $location = (string)Client::header($x['response']['headers'], 'Location');
            if ($location !== '' && $location[0] === '/') {
                $location = Settings::issuer() . $location;
            }
            $run['status'] = 'waiting';
            $run['pending'] = ['code' => $code, 'url' => $url . '?code=' . rawurlencode((string)$code), 'location' => $location, 'kind' => $type];

            return $this->save($run);
        }
        $error = is_array($json) ? trim(($json['error'] ?? 'error') . ': ' . ($json['detail'] ?? '')) : "HTTP $status";

        return $this->fail($run, "The person server refused the $type token request ($error).");
    }

    private function discover(array &$run, bool $quiet = false): ?array
    {
        $url = Settings::issuer() . '/.well-known/aauth-person.json';
        $cached = $run['ps_meta'] ?? null;
        if (is_array($cached)) {
            return $cached;
        }
        try {
            $x = $this->client->send('GET', $url);
        } catch (\Throwable $e) {
            $this->fail($run, $e->getMessage());

            return null;
        }
        $run['steps'][] = $this->step('discover', 'Person server metadata', $x['request'], $x['response'], []);
        $meta = json_decode((string)$x['response']['body'], true);
        if ($x['response']['status'] !== 200 || !is_array($meta) || empty($meta['person_token_endpoint'])) {
            $this->fail($run, 'Person server metadata is not available.');

            return null;
        }

        return $run['ps_meta'] = $meta;
    }

    private function step(string $kind, string $title, ?array $request, ?array $response, array $tokens): array
    {
        return ['kind' => $kind, 'title' => $title, 'request' => $request, 'response' => $response, 'tokens' => array_values($tokens)];
    }

    private function fail(array $run, string $error): array
    {
        $run['status'] = 'failed';
        $run['error'] = $error;
        $run['pending'] = null;

        return $this->save($run);
    }

    private function out(array $run): array
    {
        return [
            'run_id' => $run['run_id'],
            'status' => $run['status'],
            'pending' => $run['pending'] ? ['code' => $run['pending']['code'], 'url' => $run['pending']['url']] : null,
            'error' => $run['error'],
            'steps' => $run['steps'],
            'result' => $run['result'],
        ];
    }

    private function save(array $run): array
    {
        Store::cache()->put($this->runKey($run['run_id']), $run, self::RUN_TTL);

        return $run;
    }

    private function load(string $runId): array
    {
        $run = $runId !== '' ? Store::cache()->get($this->runKey($runId)) : null;
        if (!is_array($run)) {
            throw new NotFoundException('That run has expired. Send the request again.');
        }

        return $run;
    }

    private function agentKey(): array
    {
        $k = 'aauth:pg:key:' . $this->userId;
        $enc = Store::cache()->get($k);
        if (is_string($enc)) {
            try {
                $jwk = json_decode(Crypt::decryptString($enc), true);
                if (is_array($jwk) && !empty($jwk['d'])) {
                    return $jwk;
                }
            } catch (\Throwable $e) {
            }
        }
        $jwk = Jwk::generateEd25519();
        Store::cache()->put($k, Crypt::encryptString(json_encode($jwk)), 7 * 86400);
        Store::cache()->forget($this->tokensKey());

        return $jwk;
    }

    private function tokens(): array
    {
        $t = Store::cache()->get($this->tokensKey());
        if (!is_string($t)) {
            return [];
        }
        try {
            $d = json_decode(Crypt::decryptString($t), true);

            return is_array($d) ? $d : [];
        } catch (\Throwable $e) {
            return [];
        }
    }

    private function saveTokens(array $tokens): void
    {
        Store::cache()->put($this->tokensKey(), Crypt::encryptString(json_encode($tokens)), self::TOKEN_TTL);
    }

    private function fresh(array $tokens, string $type): bool
    {
        return !empty($tokens[$type . '_token']) && (int)($tokens[$type . '_exp'] ?? 0) - time() > self::REFRESH_MARGIN;
    }

    private function expOf(string $jwt): int
    {
        try {
            return (int)(Jwt::decode($jwt)['payload']['exp'] ?? 0);
        } catch (\Throwable $e) {
            return 0;
        }
    }

    private function tokensKey(): string
    {
        return 'aauth:pg:tok:' . $this->userId;
    }

    private function runKey(string $runId): string
    {
        return 'aauth:pg:' . $this->userId . ':' . $runId;
    }

    /** Reads one member/parameter of an AAuth-Requirement header (requirement=x; name="value"). */
    public static function param(string $header, string $name): ?string
    {
        if ($header === '') {
            return null;
        }
        $q = preg_quote($name, '/');
        if (preg_match('/(?:^|[;,\s])' . $q . '="((?:[^"\\\\]|\\\\.)*)"/', $header, $m)) {
            return stripcslashes($m[1]);
        }
        if (preg_match('/(?:^|[;,\s])' . $q . '=([A-Za-z0-9_.:\/*+\-]+)/', $header, $m)) {
            return $m[1];
        }

        return null;
    }
}
