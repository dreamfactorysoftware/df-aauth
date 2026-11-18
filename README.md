# df-aauth: AAuth agent authorization for DreamFactory

`dreamfactory/df-aauth` is a commercial (Gold) DreamFactory package. It lets AI agents call any
DreamFactory API with signed HTTP requests instead of API keys. A person approves the agent, and what
they approve is a **scope**, which is an ordinary DreamFactory **role**: the agent gets exactly that
role's access, with its filters, lookups, scripts and limits, and Data Masking treats the call as an
AI session. There is no new permission model and no client registration.

It implements AAuth, draft-hardt-oauth-aauth-protocol-11 (three-party "PS authorization" mode) with
draft-hardt-httpbis-signature-key-09 (HTTP message signatures, RFC 9421). DreamFactory plays three
AAuth roles on one https origin, the **issuer**:

| Role | Published at | What it does |
|---|---|---|
| Resource | `/.well-known/aauth-resource.json` | Verifies signed `/api/v2/...` calls, challenges with `AAuth-Requirement`, issues resource tokens |
| Person server | `/.well-known/aauth-person.json` | People sign in with their DreamFactory account and approve agents at `/aauth/interact` |
| Agent provider | `/.well-known/aauth-agent.json` | Identity of the built-in **Try it** agent in the admin app |

DreamFactory can also trust external person servers, so agents approved in your organization's own
person server can call it.

AAuth is off after install. A request without AAuth headers is handled exactly as before, whether AAuth
is on or off.

## Quickstart

On a DreamFactory Gold instance with an https origin in front of it, public or internal
([why and how](docs/install.md#the-issuer-and-the-reverse-proxy)):

```bash
cd /opt/dreamfactory
composer require "dreamfactory/df-aauth:~0.1.0" --update-no-dev   # repository setup: docs/install.md
php artisan migrate --force
echo 'DF_AAUTH_ISSUER=https://api.example.com' >> .env            # your https origin (public or internal)
php artisan config:clear && php artisan cache:clear
```

Then, in the admin app, under **API Security > AAuth**:

1. Switch **Enabled** on.
2. In **Scopes**, enable a role agents may ask for, for example "Sales read" as `sales.read`, with the
   description "Read customers and orders".
3. In **Try it**, send `GET /api/v2/<service>/_table/<table>?limit=5`. Press **Approve**, sign in,
   **Continue**, then **Allow**. The API response appears, with every request, challenge and token
   along the way.

`php artisan df:aauth status` checks the deployment. Your own agents follow the same flow, with the
Node or Python client in this package: [docs/building-agents.md](docs/building-agents.md).

## Documentation

| | |
|---|---|
| [Install](docs/install.md) | Requirements, the issuer and reverse proxy, Composer, migrations, enabling, upgrading, removing |
| [Configuration](docs/configuration.md) | Every setting with its default, built-in limits |
| [Admin guide](docs/admin-guide.md) | Scopes, person servers, agents, activity, grants, Try it, the admin API |
| [Building agents](docs/building-agents.md) | What an agent needs, the HTTP exchange step by step, errors, client libraries |
| [Trust model](docs/trust-model.md) | What is verified, replay, outbound fetches, consent pages, what is out of scope |
| [Operations](docs/operations.md) | Keys and rotation, backups, `APP_KEY`, several nodes, monitoring, pruning |
| [AAuth for OAuth developers](docs/oauth-mapping.md) | OAuth and OpenID Connect concepts and their AAuth and DreamFactory equivalents |
| [Changelog](CHANGELOG.md) | |

## Compatibility

| | |
|---|---|
| DreamFactory | 7.8 or later 7.x, Gold. Requires `dreamfactory/df-core ~1.0.4` and `dreamfactory/df-system ~0.6.2`. The instance's license level must be Gold: on other levels the admin API answers 403 and AAuth behaves as off. |
| PHP | 8.3 or later with `sodium`, `openssl`, `curl`, `json`, `mbstring` |
| System database | MySQL/MariaDB, PostgreSQL, SQLite, SQL Server (tested on MySQL 5.7) |
| Cache | Any store for one node; a shared Redis or Memcached for several |
| Protocol | draft-hardt-oauth-aauth-protocol-11, draft-hardt-httpbis-signature-key-09; Ed25519 and ES256 |
| Not supported in 0.1.0 | Access servers, missions, sub-agents, call chaining, the revocation endpoint, multipart bodies ([details](docs/trust-model.md#out-of-scope-in-010)) |

## License

Commercial software, part of the DreamFactory Gold package, licensed under the DreamFactory Terms of
Use in [LICENSE](LICENSE). Third-party notices: [NOTICE](NOTICE). Support: dspsupport@dreamfactory.com.

## Development

| Path | |
|---|---|
| `src/Protocol` | Pure PHP protocol library (no Laravel): JWK/JWS/JWT, structured fields, `Signature-Key`, RFC 9421 signatures, discovery. See `src/Protocol/README.md`. |
| `src/Http`, `src/Resource` | The `df.aauth` middleware (runs in `df.api` before `df.access_check`), metadata and authorization endpoints, scopes, person servers, agents |
| `src/PersonServer`, `resources/views` | Token endpoints, pending requests, consent and grants pages |
| `src/AgentProvider`, `src/Playground` | The built-in agent provider and the **Try it** agent |
| `src/Admin`, `src/Resources/AAuth.php` | The `system/aauth` admin API |
| `src/Console` | `php artisan df:aauth status \| rotate-keys \| prune` |
| `agent/` | `@dreamfactory/aauth-agent`: Node client library, the `aauth` CLI, agent provider helpers, end-to-end suite |
| `clients/python/` | `dreamfactory-aauth`: Python client |

Tests:

```bash
bin/test.sh                      # PHPUnit, Protocol and Platform suites, in the DreamFactory image (no network)
(cd agent && node --test)        # Node client library and consent page client
node agent/e2e.mjs               # end-to-end scenarios against a live issuer; see agent/README.md
```

`bin/test.sh` needs a PHPUnit 11 phar (`PHPUNIT_PHAR`, or `./phpunit.phar`). `e2e.mjs` changes the
instance it runs against (it creates throwaway agents and restores what it changes) and has no default
target.

Install a working tree into a running DreamFactory container for development (no network; bind-mount
the package first):

```bash
bin/dev-install.sh <container> /src/df-aauth   # symlink into vendor, autoload, package discovery, migrate
```

### Development demo

`bin/demo-seed.sh <admin-password-file> [base-url] [user-password-file]` seeds a demo through the
DreamFactory API: a SQLite service `sales` (customers, orders), roles "Sales read" and "Sales refunds",
scopes `sales.read` and `sales.refund`, and a non-admin user Jordan Lee who holds only "Sales read"
(his generated password goes to the user password file). It is idempotent and touches nothing else.
With it, **Try it** on `GET /api/v2/sales/_table/orders?limit=5` asks for `sales.read`;
`PATCH /api/v2/sales/_table/orders/5 {"status":"refunded"}` steps up to `sales.refund`, which Jordan
cannot grant and an admin can.
