# Installing AAuth

This page takes a DreamFactory Gold instance to a working AAuth issuer: package installed, tables
created, an https origin in front of it, and AAuth switched on. The admin steps that follow
(choosing scopes, trusting person servers) are in [admin-guide.md](admin-guide.md).

Installing the package changes nothing on its own. AAuth is off until a sys admin turns it on, and a
request without AAuth headers is handled exactly as before, on or off.

## Requirements

| | |
|---|---|
| DreamFactory | 7.8 or later 7.x (Laravel 13). Tested on 7.7.1 (df-core 1.0.18, df-system 0.6.6) and 7.8. The package requires `dreamfactory/df-core ~1.0.4` and `dreamfactory/df-system ~0.6.2`. |
| License | DreamFactory **Gold**. `dreamfactory/df-aauth` is distributed with the Gold package and is not licensed for other tiers. If your Gold build already includes it, skip [Install the package](#1-install-the-package). The instance's license level must be Gold: on other levels `system/aauth` answers 403 ("AAuth is not available for your license. Please upgrade to Gold."), AAuth behaves as off, and `php artisan df:aauth status` warns. |
| PHP | 8.3 or later with `sodium`, `openssl`, `curl`, `json` and `mbstring`. The DreamFactory images have all five; check with `php -m`. |
| Https origin | One host name that agents and approvers use to reach DreamFactory, served on port 443: `https://api.example.com`. It need not be public: when the agents, their provider and the people who approve them are all inside your network, an internal name such as `https://data.corp.internal` with a certificate from your internal CA works (see [Private networks and custom CAs](configuration.md#private-networks-and-custom-cas)). No port, no path. See [The issuer](#the-issuer-and-the-reverse-proxy). |
| Outbound https | DreamFactory fetches the metadata and keys of the agent providers and external person servers that agents use: public addresses only, unless you admit internal ones ([configuration.md](configuration.md#private-networks-and-custom-cas)). **Try it** in the admin app calls DreamFactory through its own https origin, so the server must be able to reach that origin too. |
| Cache | Any Laravel cache store works for one node. With several DreamFactory nodes, every node needs the same shared cache (Redis or Memcached) and shared consent sessions (`DF_AAUTH_CACHE_STORE`, `DF_AAUTH_SESSION_DRIVER`). See [operations.md](operations.md#several-dreamfactory-nodes). |
| Clock | Signatures are accepted for 60 seconds either side of the server clock. Run NTP on the DreamFactory hosts. |
| System database | Tested on MySQL 5.7. The migrations use Laravel's schema builder only and are written for MySQL/MariaDB, PostgreSQL, SQLite and SQL Server. |

## The issuer and the reverse proxy

The **issuer** is the https origin of this DreamFactory as an AAuth server: its resource,
its person server and its agent provider all use it. Agents sign the host name they call
(`@authority`), and DreamFactory accepts a signed request only when that host is the issuer host,
so all agent traffic must reach DreamFactory at exactly that name.

The issuer is `DF_AAUTH_ISSUER`. When it is not set, DreamFactory uses the `APP_URL` origin if
`APP_URL` is https. It is never taken from the request's `Host` header. It must be `https://` plus a
lowercase host name, with no port, path, query or trailing slash; anything else leaves AAuth unable to
turn on (the admin app shows `Set DF_AAUTH_ISSUER to an https URL`). The admin app itself can stay
where it is (for example plain http on an internal address): only agents and the people approving
them need the issuer.

DreamFactory's own web server speaks plain http. Put a TLS reverse proxy (nginx, Caddy, a cloud load
balancer) in front of it for the issuer host. The proxy must:

- **Preserve `Host`.** DreamFactory compares the signed `@authority` with the issuer host.
- **Pass the request target unchanged.** Signatures cover the raw path and the raw query string.
  No path rewriting, no decoding or re-encoding, no query reordering.
- **Pass the request body and these headers unchanged:** `Signature`, `Signature-Input`,
  `Signature-Key`, `Content-Type`, `Content-Digest`.
- **Not block `/.well-known/`.** Many configurations deny every path that starts with a dot
  (`location ~ /\. { deny all; }`). Allow `/.well-known/aauth-resource.json`,
  `/.well-known/aauth-person.json` and `/.well-known/aauth-agent.json`, and pass `/aauth/*`.
- **Send `X-Forwarded-For`.** Then set `DF_AAUTH_TRUSTED_PROXIES` to the address the proxy connects
  to DreamFactory from, so the sign-in and request limits see real client addresses (see
  [configuration.md](configuration.md#df_aauth_trusted_proxies)).

nginx:

```nginx
server {
    listen 443 ssl;
    http2 on;
    server_name api.example.com;
    ssl_certificate     /etc/ssl/api.example.com/fullchain.pem;
    ssl_certificate_key /etc/ssl/api.example.com/privkey.pem;
    client_max_body_size 100m;

    location / {
        # no URI after the upstream address: nginx then forwards the original request target as is
        proxy_pass http://dreamfactory:80;
        proxy_http_version 1.1;
        proxy_set_header Host              $host;
        proxy_set_header X-Forwarded-For   $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto https;
    }
}
```

Caddy (keeps `Host` and the request target by default):

```caddyfile
api.example.com {
    reverse_proxy dreamfactory:80 {
        header_up X-Forwarded-Proto https
    }
}
```

## 1. Install the package

Add the package's GitHub repository and require the package:

```bash
cd /opt/dreamfactory
composer config repositories.df-aauth vcs https://github.com/dreamfactorysoftware/df-aauth
composer require "dreamfactory/df-aauth:~0.1.0" --update-no-dev
```

If Composer stops on platform requirements of other DreamFactory packages (for example
`ext-mongodb` or `ext-oci8` on a host without them), add the same `--ignore-platform-req=...` flags
your DreamFactory build uses. The package registers itself through Laravel package discovery
(`DreamFactory\Core\AAuth\ServiceProvider`).

### Docker

Install the package into the image, not into a running container. A package installed with
`composer require` inside a container lives in that container's writable layer and disappears when the
container is re-created. The AAuth settings survive in the system database, but the endpoints are
gone: agents get DreamFactory's normal "no API key" errors (AAuth fails closed).

```dockerfile
FROM <your DreamFactory Gold image>
RUN cd /opt/dreamfactory \
 && composer config repositories.df-aauth vcs https://github.com/dreamfactorysoftware/df-aauth \
 && composer require "dreamfactory/df-aauth:~0.1.0" --update-no-dev --no-interaction
```

Pass the GitHub token to the build as a build secret (`COMPOSER_AUTH`), never as a layer. Run artisan
commands as the web user:

```bash
docker exec -u www-data <container> php /opt/dreamfactory/artisan migrate --force
```

## 2. Create the tables

```bash
php artisan migrate --force
```

The package's six migrations create twelve tables, all prefixed `aauth_`: `aauth_settings`,
`aauth_keys`, `aauth_scopes`, `aauth_person_servers`, `aauth_agents`, `aauth_agent_keys`,
`aauth_activity`, `aauth_ps_pending`, `aauth_ps_grants`, `aauth_ps_subjects`, `aauth_ps_tokens` and `aauth_sessions`
(used only with `DF_AAUTH_SESSION_DRIVER=database`). The migrations are idempotent: each table or
column is created only when missing, and `000004` rebuilds `aauth_agent_keys` and keeps its rows.
`aauth_scopes.role_id` references `role.id` with `ON DELETE CASCADE`.

Until the migrations have run, `GET /api/v2/system/aauth` answers 503 `AAuth is not set up yet. Run:
php artisan migrate`.

## 3. Configure

Add to DreamFactory's `.env` (in the Docker image: `/opt/dreamfactory/.env`; PHP-FPM does not pass
the container's environment to PHP):

```dotenv
DF_AAUTH_ISSUER=https://api.example.com
DF_AAUTH_TRUSTED_PROXIES=172.18.0.1
```

Then reload the configuration:

```bash
php artisan config:clear      # or php artisan config:cache, if your deployment caches config
php artisan cache:clear
```

Every setting, with its default, is in [configuration.md](configuration.md). The defaults are meant
for production; `DF_AAUTH_ISSUER` is the only one you must set (unless `APP_URL` is already the
https origin). With several DreamFactory nodes, also set `DF_AAUTH_CACHE_STORE` and
`DF_AAUTH_SESSION_DRIVER` ([operations.md](operations.md#several-dreamfactory-nodes)).

## 4. Turn AAuth on

In the admin app, open **API Security > AAuth** and switch **Enabled** on. The issuer is shown next to
the switch. Or through the API, as a sys admin:

```bash
curl -s -X PATCH https://api.example.com/api/v2/system/aauth \
  -H "X-DreamFactory-Session-Token: $DF_SESSION_TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"enabled": true}'
```

Turning AAuth on the first time generates the three Ed25519 signing keys (resource, person server,
agent provider), adds the row for this DreamFactory's own person server, and creates a hidden app named
`aauth` that agent sessions run under. Do not delete that app while AAuth is in use.

## 5. Check

```bash
curl -s https://api.example.com/.well-known/aauth-resource.json
```

answers 200 with `"issuer":"https://api.example.com"` (404 while AAuth is off). A request without
credentials keeps DreamFactory's own error and gains a discovery link:

```bash
curl -s -o /dev/null -D - https://api.example.com/api/v2/db/_table | grep -i '^link'
# link: <https://api.example.com/.well-known/aauth-resource.json>; rel="aauth-resource"
```

`GET /api/v2/system/aauth` returns `"enabled": true, "issuer_ok": true`.

`php artisan df:aauth status` prints the deployment facts (issuer, cache store and consent sessions,
and whether they are shared across nodes, private-network egress, CA bundle, signing keys, sign-in
methods) followed by a warning for anything that needs attention. `--json` gives the same as JSON.

The service provider registers `df:aauth` and schedules `df:aauth prune` daily (03:17), plus
`df:aauth rotate-keys --older-than=N` daily (03:47) when `DF_AAUTH_KEY_ROTATION_DAYS` is N > 0.
`php artisan schedule:list | grep aauth` shows them. DreamFactory Docker images run
`php artisan schedule:run` every minute from cron; on other installs add that cron line
(see [operations.md](operations.md#pruning)).

Next: give agents something to ask for. In **Scopes**, enable the roles agents may request, then run
**Try it** ([admin-guide.md](admin-guide.md)).

## Upgrading

```bash
composer update dreamfactory/df-aauth --update-no-dev
php artisan migrate --force
php artisan config:clear && php artisan cache:clear
```

Check [CHANGELOG.md](../CHANGELOG.md) for migrations and changed behavior before upgrading.

## Turning it off, removing it

Switching **Enabled** off (or `PATCH /api/v2/system/aauth {"enabled": false}`) stops all agent
access at once: every AAuth endpoint answers 404, signed requests go through DreamFactory's normal
authentication (and fail, as they carry no API key), and settings, scopes, grants and activity are
kept.

To remove the package and its tables:

```bash
cd /opt/dreamfactory
php artisan migrate:reset --path=vendor/dreamfactory/df-aauth/database/migrations --force
composer remove dreamfactory/df-aauth
php artisan config:clear && php artisan cache:clear
```

`migrate:reset --path` rolls back only this package's migrations and drops the `aauth_*` tables.
The hidden `aauth` app stays; delete it under **Apps** if you no longer need it. If you already removed
the package, drop the twelve tables listed above and delete the package's six rows from `migrations`
by exact name: `2026_11_10_000001_create_aauth_tables`, `2026_11_11_000002_create_aauth_agent_keys_table`,
`2026_11_12_000003_add_aauth_key_rotation_and_sessions`, `2026_11_16_000004_keep_aauth_agent_key_history`,
`2026_11_16_000005_add_aauth_scope_since`, `2026_11_17_000006_create_aauth_ps_tokens_table`. Leaving a row behind makes a later reinstall skip that
migration.
