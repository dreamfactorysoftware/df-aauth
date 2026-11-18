<?php

namespace DreamFactory\Core\AAuth\Resources;

use DreamFactory\Core\AAuth\Admin\ActivityLog;
use DreamFactory\Core\AAuth\Console\AAuthCommand;
use DreamFactory\Core\AAuth\Admin\Overview;
use DreamFactory\Core\AAuth\PersonServer\Grants;
use DreamFactory\Core\AAuth\Playground\Playground;
use DreamFactory\Core\AAuth\Resource\Agents;
use DreamFactory\Core\AAuth\Resource\PersonServers;
use DreamFactory\Core\AAuth\Resource\Scopes;
use DreamFactory\Core\AAuth\Support\Activity;
use DreamFactory\Core\AAuth\Support\Keys;
use DreamFactory\Core\AAuth\Support\License;
use DreamFactory\Core\AAuth\Support\Settings;
use DreamFactory\Core\Contracts\ServiceResponseInterface;
use DreamFactory\Core\Enums\Verbs;
use DreamFactory\Core\Exceptions\BadRequestException;
use DreamFactory\Core\Exceptions\ForbiddenException;
use DreamFactory\Core\Exceptions\NotFoundException;
use DreamFactory\Core\Exceptions\ServiceUnavailableException;
use DreamFactory\Core\Resources\BaseRestResource;
use DreamFactory\Core\Utility\ResponseFactory;
use DreamFactory\Core\Utility\Session;
use Illuminate\Database\QueryException;

/**
 * System resource `aauth`: /api/v2/system/aauth[/...]. Sys admins only, on every verb, on an
 * instance whose license level is Gold (Support\License).
 *
 *   GET    /                         overview          PATCH /  {enabled}
 *   GET    /scopes                   all roles + scope config
 *   PATCH  /scopes/{role_id}         {enabled?, scope?, description?}
 *   GET    /person_servers           POST {issuer}
 *   PATCH  /person_servers/{id}      {enabled?, scopes?}      DELETE /person_servers/{id}
 *   GET    /agents[/{id}]            PATCH /agents/{id} {status}   DELETE /agents/{id}
 *   GET    /activity?limit=&before_id=&outcome=
 *   GET    /grants                   DELETE /grants/{id}
 *   POST   /playground               {action: send|advance|reset, ...}
 *   GET    /keys                     signing keys (no private material)   POST /keys {purpose?, revoke?} rotate
 *   GET    /status                   deployment readiness (php artisan df:aauth status)
 *
 * Wire format: snake_case keys; JWTs as raw strings; headers as [[name, value], ...].
 */
class AAuth extends BaseRestResource
{
    public function __construct($settings = [])
    {
        $settings = (array)$settings;
        $settings['verbAliases'] = [Verbs::PUT => Verbs::PATCH];
        parent::__construct($settings);
    }

    protected function handleGET()
    {
        self::requireSysAdmin(false);

        return $this->guarded(fn () => match ($this->resource) {
            null, '' => Overview::get(),
            'scopes' => $this->resourceId === null ? ['resource' => Scopes::all()] : Scopes::get($this->id()),
            'person_servers' => $this->resourceId === null ? ['resource' => PersonServers::list()] : PersonServers::get($this->id()),
            'agents' => $this->resourceId === null ? ['resource' => Agents::list()] : Agents::get($this->id()),
            'activity' => $this->listOnly(fn () => ActivityLog::list(
                $this->request->getParameter('limit'),
                $this->request->getParameter('before_id'),
                $this->request->getParameter('outcome'),
            )),
            'grants' => $this->resourceId === null ? ['resource' => Grants::list()] : Grants::get($this->id()),
            'keys' => $this->listOnly(fn () => self::keys()),
            'status' => $this->listOnly(fn () => AAuthCommand::report()),
            default => throw new NotFoundException("Resource '{$this->resource}' not found."),
        });
    }

    protected function handlePATCH()
    {
        self::requireSysAdmin(true);

        return $this->guarded(fn () => match ($this->resource) {
            null, '' => Overview::patch($this->payload()),
            'scopes' => Scopes::patch($this->id(), $this->payload()),
            'person_servers' => PersonServers::patch($this->id(), $this->payload()),
            'agents' => Agents::patch($this->id(), $this->payload()),
            default => $this->unsupported(),
        });
    }

    protected function handlePOST()
    {
        self::requireSysAdmin(true);

        return $this->guarded(function () {
            if ($this->resource === 'person_servers' && $this->resourceId === null) {
                return ResponseFactory::create(PersonServers::add((string)($this->payload()['issuer'] ?? '')), null, ServiceResponseInterface::HTTP_CREATED);
            }
            if ($this->resource === 'playground' && $this->resourceId === null) {
                if (!Settings::enabled()) {
                    throw new BadRequestException('Turn AAuth on first.');
                }
                $uid = (int)Session::getCurrentUserId();

                return (new Playground($uid))->handle($this->payload());
            }
            if ($this->resource === 'keys' && $this->resourceId === null) {
                return $this->rotate($this->payload());
            }

            return $this->unsupported();
        });
    }

    protected function handleDELETE()
    {
        self::requireSysAdmin(true);

        return $this->guarded(fn () => match ($this->resource) {
            'person_servers' => PersonServers::delete($this->id()),
            'agents' => Agents::delete($this->id(), filter_var($this->request->getParameter('purge_activity', false), FILTER_VALIDATE_BOOLEAN)),
            'grants' => Grants::delete($this->id()),
            default => $this->unsupported(),
        });
    }

    private static function keys(): array
    {
        return [
            'resource' => Keys::inventory(),
            'overlap_seconds' => Keys::overlap(),
            'rotation_days' => max(0, (int)config('df-aauth.key_rotation_days', 0)),
        ];
    }

    /** POST /keys {purpose?: resource|person|agent or a list (default all), revoke?: bool} */
    private function rotate(array $data): array
    {
        $purposes = $data['purpose'] ?? Keys::PURPOSES;
        $purposes = array_values(array_unique(array_map('strval', is_array($purposes) ? $purposes : [$purposes])));
        if (!$purposes || array_diff($purposes, Keys::PURPOSES)) {
            throw new BadRequestException('purpose must be resource, person or agent (or a list of them).');
        }
        $revoke = filter_var($data['revoke'] ?? false, FILTER_VALIDATE_BOOLEAN);
        try {
            $rotated = array_map(fn ($p) => Keys::rotate($p, $revoke), $purposes);
        } catch (\RuntimeException $e) {
            throw new ServiceUnavailableException($e->getMessage());
        }

        return ['rotated' => $rotated] + self::keys();
    }

    private function id(): int
    {
        if ($this->resourceId === null || !ctype_digit((string)$this->resourceId)) {
            throw new BadRequestException('An id is required: system/aauth/' . $this->resource . '/{id}.');
        }

        return (int)$this->resourceId;
    }

    private function listOnly(\Closure $fn): mixed
    {
        if ($this->resourceId !== null && $this->resourceId !== '') {
            throw new BadRequestException("system/aauth/{$this->resource} is a list; it takes no id.");
        }

        return $fn();
    }

    private function payload(): array
    {
        $data = $this->request->getPayloadData();

        return is_array($data) ? $data : [];
    }

    private function guarded(\Closure $fn): mixed
    {
        try {
            return $fn();
        } catch (QueryException $e) {
            if (stripos($e->getMessage(), 'aauth_') !== false) {
                throw new ServiceUnavailableException('AAuth is not set up yet. Run: php artisan migrate');
            }
            throw $e;
        }
    }

    /** @throws ForbiddenException */
    private static function requireSysAdmin(bool $write): void
    {
        if (!Session::isSysAdmin()) {
            throw new ForbiddenException('Only a system administrator can ' . ($write ? 'change' : 'view') . ' AAuth settings.');
        }
        License::requireGold();
    }

    /** @throws BadRequestException */
    private function unsupported(): never
    {
        $path = trim('aauth/' . $this->resourcePath, '/');
        throw new BadRequestException(ucfirst(strtolower((string)$this->getRequestedAction())) . " is not supported on system/$path.");
    }

    protected function getApiDocPaths()
    {
        $base = '/' . $this->name;
        $ok = ['200' => ['description' => 'Success', 'content' => ['application/json' => ['schema' => ['type' => 'object']]]]];
        $op = function (string $id, string $summary, ?array $body = null, array $params = []) use ($ok) {
            $o = ['summary' => $summary, 'operationId' => $id, 'responses' => $ok];
            if ($params) {
                $o['parameters'] = $params;
            }
            if ($body !== null) {
                $o['requestBody'] = ['required' => true, 'content' => ['application/json' => ['schema' => ['type' => 'object', 'properties' => $body]]]];
            }

            return $o;
        };
        $path = fn (string $name, string $desc) => ['name' => $name, 'in' => 'path', 'required' => true, 'description' => $desc, 'schema' => ['type' => 'integer']];
        $q = fn (string $name, string $desc) => ['name' => $name, 'in' => 'query', 'required' => false, 'description' => $desc, 'schema' => ['type' => 'integer', 'minimum' => 1]];
        $bool = ['type' => 'boolean'];
        $str = ['type' => 'string'];
        $list = ['type' => 'array', 'items' => ['type' => 'string']];
        $roleId = [$path('role_id', 'Role id.')];
        $id = [$path('id', 'Row id.')];

        return [
            $base => ['get' => $op('getAAuth', 'AAuth overview.'), 'patch' => $op('patchAAuth', 'Turn AAuth on or off.', ['enabled' => $bool])],
            $base . '/scopes' => ['get' => $op('getAAuthScopes', 'Roles and the scopes agents can ask for.')],
            $base . '/scopes/{role_id}' => [
                'get' => $op('getAAuthScope', 'The scope configuration of a role.', null, $roleId),
                'patch' => $op('patchAAuthScope', 'Configure the scope of a role.', ['enabled' => $bool, 'scope' => $str, 'description' => $str], $roleId),
            ],
            $base . '/person_servers' => ['get' => $op('getAAuthPersonServers', 'Trusted person servers.'),
                'post' => $op('addAAuthPersonServer', 'Trust a person server (it starts with no scopes).', ['issuer' => $str])],
            $base . '/person_servers/{id}' => [
                'get' => $op('getAAuthPersonServer', 'One person server.', null, $id),
                'patch' => $op('patchAAuthPersonServer', 'Update a person server.', ['enabled' => $bool, 'scopes' => $list, 'all_scopes' => $bool], $id),
                'delete' => $op('deleteAAuthPersonServer', 'Stop trusting a person server.', null, $id),
            ],
            $base . '/agents' => ['get' => $op('getAAuthAgents', 'Agents seen by this DreamFactory.')],
            $base . '/agents/{id}' => [
                'get' => $op('getAAuthAgent', 'One agent.', null, $id),
                'patch' => $op('patchAAuthAgent', 'Block or allow an agent.', ['status' => ['type' => 'string', 'enum' => ['allowed', 'blocked']]], $id),
                'delete' => $op('deleteAAuthAgent', 'Forget an agent (its activity stays unless purge_activity=true).', null,
                    [$path('id', 'Row id.'), ['name' => 'purge_activity', 'in' => 'query', 'required' => false, 'schema' => ['type' => 'boolean']]]),
            ],
            $base . '/activity' => ['get' => $op('getAAuthActivity', 'AAuth requests, newest first.', null,
                [$q('limit', 'Rows per page (1-500, default 100).'), $q('before_id', 'Only rows with a smaller id (paging).'),
                    ['name' => 'outcome', 'in' => 'query', 'required' => false, 'style' => 'form', 'explode' => false,
                        'description' => 'Only rows with one of these outcomes (comma-separated). Absent: every outcome.',
                        'schema' => ['type' => 'array', 'items' => ['type' => 'string', 'enum' => Activity::OUTCOMES]]]])],
            $base . '/grants' => ['get' => $op('getAAuthGrants', 'Standing grants given at this person server.')],
            $base . '/grants/{id}' => [
                'get' => $op('getAAuthGrant', 'One standing grant.', null, $id),
                'delete' => $op('deleteAAuthGrant', 'Revoke a standing grant.', null, $id),
            ],
            $base . '/playground' => ['post' => $op('postAAuthPlayground', 'Run the built-in agent against this DreamFactory.',
                ['action' => ['type' => 'string', 'enum' => ['send', 'advance', 'reset']], 'method' => $str, 'path' => $str, 'run_id' => $str])],
            $base . '/keys' => [
                'get' => $op('getAAuthKeys', 'Signing keys: signing, retiring (still published) and their dates. Never private material.'),
                'post' => $op('rotateAAuthKeys', 'Rotate signing keys. The previous keys stay published for the overlap window unless revoke is true.',
                    ['purpose' => ['type' => 'string', 'enum' => Keys::PURPOSES], 'revoke' => $bool]),
            ],
            $base . '/status' => ['get' => $op('getAAuthStatus', 'Deployment readiness: issuer, cache store and consent sessions, egress, keys, sign-in methods, warnings.')],
        ];
    }
}
