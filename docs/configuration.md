# Configuration

AAuth has two kinds of settings:

- **Environment settings** (this page): the issuer, token lifetimes, discovery limits, proxies. They
  are read from `config/df-aauth.php`, and every value there comes from an environment variable, so
  `php artisan config:cache` is safe. Change them in DreamFactory's `.env`, then run
  `php artisan config:clear` (or `config:cache` again).
- **Policy** (the on/off switch, scopes, person servers, agents, grants): stored in the system
  database and managed in the admin app or through `/api/v2/system/aauth`. See
  [admin-guide.md](admin-guide.md).

To keep a copy of the config file in the app (optional; the package's own file is used otherwise):

```bash
php artisan vendor:publish --provider="DreamFactory\Core\AAuth\ServiceProvider" --tag=config
```

## Environment settings

### Issuer and network

| Variable | Config key `df-aauth.*` | Default | Meaning |
|---|---|---|---|
| `DF_AAUTH_ISSUER` | `issuer` | the `APP_URL` origin when it is https, else none | Https origin of this DreamFactory as an AAuth server, public or internal. Required unless `APP_URL` is that origin. [Details](#df_aauth_issuer). |
| `DF_AAUTH_TRUSTED_PROXIES` | `trusted_proxies` | empty | Comma-separated IPs or CIDRs whose `X-Forwarded-For` AAuth believes. [Details](#df_aauth_trusted_proxies). |
| `DF_AAUTH_PRIVATE_HOSTS` | `private_hosts` | empty | Comma-separated host names that discovery may fetch from although they resolve to private-use addresses. [Details](#private-networks-and-custom-cas). |
| `DF_AAUTH_PRIVATE_NETWORKS` | `private_networks` | empty | Comma-separated CIDRs or addresses that discovery may connect to. [Details](#private-networks-and-custom-cas). |
| `DF_AAUTH_CA_BUNDLE` | `ca_bundle` | the system trust store | PEM bundle file (or hashed CA directory) that discovery and **Try it** trust instead of the system store. [Details](#private-networks-and-custom-cas). |

### Tokens and requests

| Variable | Config key `df-aauth.*` | Default | Meaning |
|---|---|---|---|
| `DF_AAUTH_AUTH_TOKEN_TTL` | `auth_token_ttl` | `3600` | Seconds an auth token from the built-in person server is valid. Never longer than the agent token or the presented token. Capped at 3600 (see below). It does not change how long a scope name a role gives up (rename, role deleted) stays reserved: 3660 s, because tokens from any person server may live an hour. |
| `DF_AAUTH_PERSON_TOKEN_TTL` | `person_token_ttl` | `3600` | Seconds a person token from the built-in person server is valid. Never longer than the agent token. Capped at 3600. |
| `DF_AAUTH_RESOURCE_TOKEN_TTL` | `resource_token_ttl` | `300` | Seconds a resource token (in a `401 requirement=auth-token` challenge) is valid. The protocol allows at most 300. |
| `DF_AAUTH_AGENT_TOKEN_TTL` | `agent_token_ttl` | `3600` | Seconds an agent token from the built-in agent provider (the **Try it** agent) is valid. Clamped to 60 to 86400. |
| `DF_AAUTH_PENDING_TTL` | `pending_ttl` | `600` | Seconds a person or auth token request (and its interaction code) stays open for the person to approve. |
| `DF_AAUTH_SIGNATURE_WINDOW` | `signature_window` | `60` | Seconds a signature's `created` time may differ from the server clock. Published as `signature_window` in the resource metadata. Non-GET/HEAD requests are remembered (agent key and signature base) for twice this long to refuse replays. |
| `DF_AAUTH_PLAYGROUND_AGENT_NAME` | `playground_agent_name` | `DreamFactory Playground` | Name of the built-in **Try it** agent, shown on consent pages and in `aauth-agent.json`. |

**Token lifetimes above 3600.** The protocol caps person and auth tokens at one hour, and
DreamFactory's verifier (like any conforming verifier) refuses a person or auth token whose `exp - iat`
exceeds 3600 seconds. The built-in person server therefore caps `DF_AAUTH_AUTH_TOKEN_TTL` and
`DF_AAUTH_PERSON_TOKEN_TTL` at 3600 (and raises values below 60 to 60): a larger setting gives
one-hour tokens.

### Discovery

| Variable | Config key `df-aauth.*` | Default | Meaning |
|---|---|---|---|
| `DF_AAUTH_FETCH_TIMEOUT` | `fetch_timeout` | `3` | Seconds for one discovery fetch (metadata or JWKS of an agent provider or external person server). The connect timeout is the smaller of this and 2 s. |
| `DF_AAUTH_FETCH_MAX_BYTES` | `fetch_max_bytes` | `262144` | Largest metadata or JWKS document accepted (minimum 1024). |
| `DF_AAUTH_DISCOVERY_CACHE_SECONDS` | `discovery_cache_seconds` | `300` | Seconds fetched metadata and JWKS are cached. An unknown key id triggers at most one refresh per minute per URL. |

### Several nodes

| Variable | Config key `df-aauth.*` | Default | Meaning |
|---|---|---|---|
| `DF_AAUTH_CACHE_STORE` | `cache_store` | DreamFactory's default store | A store from `config/cache.php` (for example `redis`) for AAuth's short-lived state: replay records, rate limits, code claims, discovery results, **Try it** runs. With several nodes it must be shared (`redis`, `memcached`, `database`). An unknown name falls back to the default store and logs an error. |
| `DF_AAUTH_SESSION_DRIVER` | `session_driver` | `SESSION_DRIVER` | Session driver for the consent and grants pages only. With several nodes and no sticky sessions use `redis`, or `database` (table `aauth_sessions`, created by the package's migrations). Other routes are not affected. |

See [operations.md](operations.md#several-dreamfactory-nodes).

### Signing keys and housekeeping

| Variable | Config key `df-aauth.*` | Default | Meaning |
|---|---|---|---|
| `DF_AAUTH_KEY_OVERLAP` | `key_overlap` | `86400` | Seconds a retired signing key stays published and accepted after a rotation. Never less than the longest token lifetime + 300. |
| `DF_AAUTH_KEY_ROTATION_DAYS` | `key_rotation_days` | `0` | Rotate signing keys automatically once they are this many days old, from the Laravel scheduler. `0`: only by hand (`php artisan df:aauth rotate-keys`). |
| `DF_AAUTH_ACTIVITY_RETENTION_DAYS` | `activity_retention_days` | `30` | Days **Activity** rows are kept; remembered agent keys not seen for that long are dropped too. `0` keeps both forever. See [operations.md](operations.md#pruning). |

### Consent sign-in

| Variable | Config key `df-aauth.*` | Default | Meaning |
|---|---|---|---|
| `DF_AAUTH_SSO` | `sso` | `auto` | Sign-in on the consent pages through DreamFactory's login page (OAuth, OpenID Connect, SAML, LDAP). `auto`: offered when an OAuth, OpenID Connect or SAML login service is active; `on`; `off`. |
| `DF_AAUTH_SSO_LOGIN_PATH` | `sso_login_path` | `/dreamfactory/dist/#/auth/login` | The admin app's login route on the issuer origin, which returns to the consent page signed in. |

LDAP and Active Directory sign-in needs no setting: it is offered whenever such a service is active.
See [sso-approval.md](sso-approval.md).

### Development

| Variable | Config key `df-aauth.*` | Default | Meaning |
|---|---|---|---|
| `DF_AAUTH_ALLOW_INSECURE` | `allow_insecure` | `false` | **Development only.** Allows an http issuer or one with a port, http server identifiers, and discovery fetches to private and loopback addresses. Link-local and cloud metadata addresses stay refused. Never set it on a reachable instance. |

## Details

### DF_AAUTH_ISSUER

`https://` plus a lowercase host name, nothing else: `https://api.example.com`. A port, a path, a
query or a trailing slash is refused. The name may be internal (`https://data.corp.internal`): AAuth
needs only that agents and approvers reach it over https, and that DreamFactory trusts the certificates
of any internal agent providers ([Private networks and custom CAs](#private-networks-and-custom-cas)). Agents must call DreamFactory at this host: a signed request for
another host name of the same server gets `401` with `Signature-Error: error=invalid_signature` and
`Use https://api.example.com`. The issuer appears in every token DreamFactory issues (`iss`, `aud`) and
in its standing grants, so changing it later invalidates every issued token and every "Always allow"
grant (see [operations.md](operations.md#changing-the-issuer)).

The issuer is never taken from the request `Host`, so a client cannot change it.

### DF_AAUTH_TRUSTED_PROXIES

AAuth limits sign-in attempts, code attempts, pending requests and discovery fetches per client
address. Behind a reverse proxy, every request comes from the proxy's address, so without this
setting all clients share one budget and one client can lock out the others.

Set it to the address (or CIDR) the proxy connects to DreamFactory from, as PHP sees it in
`REMOTE_ADDR`. With Docker port publishing that is usually the bridge network's gateway (for a
compose network: `docker network inspect <network> -f '{{(index .IPAM.Config 0).Gateway}}'`). AAuth
then reads `X-Forwarded-For` from right to left and uses the first address that is not a trusted proxy;
`X-Forwarded-For` from any other peer is ignored, so clients cannot choose their own address. Never
list a range that clients can connect from.

This setting is used only by AAuth. DreamFactory's own trusted-proxy configuration is not changed.

### Private networks and custom CAs

Discovery fetches agent provider and person server metadata and keys only from public addresses
(see [trust-model.md](trust-model.md#discovery-and-outbound-fetches)). When agents, agent providers or a person server
live on an internal network, admit them explicitly:

- `DF_AAUTH_PRIVATE_HOSTS`: host names, exact (`agents.corp.internal`) or with a leading `*.`
  (`*.corp.internal`: any subdomain, not `corp.internal` itself). A listed host may resolve to
  private-use addresses (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, `100.64.0.0/10`, `fc00::/7`),
  not to loopback.
- `DF_AAUTH_PRIVATE_NETWORKS`: CIDRs or single addresses (`10.20.0.0/16`, `fd12:3456::/48`). Any host
  that resolves inside them is admitted, loopback included if listed.

Either list admits an address. Some addresses are never reachable, whatever is listed: link-local
(`169.254.0.0/16`, which holds cloud metadata services, and `fe80::/10`), AWS IMDS (`fd00:ec2::/32`),
`100.100.100.200`, `0.0.0.0/8` and `::`, multicast, broadcast and `240.0.0.0/4`, also when written
as IPv4-mapped, IPv4-compatible, NAT64 or 6to4 IPv6 addresses. Use the narrowest entries that cover
those servers. Never list the networks of DreamFactory's own database, cache or other internal
services: anyone who can get a token in front of DreamFactory chooses the URLs it fetches.

`DF_AAUTH_CA_BUNDLE` points at a PEM file (or a `c_rehash`ed directory) of CA certificates that
discovery and **Try it** trust **instead of** the system store, for servers behind an internal CA. To
keep trusting public CAs as well, append your CA to a copy of the system bundle. If the path is not
readable, every discovery fetch fails (closed) and DreamFactory logs an error.

`php artisan df:aauth status` prints the effective lists and whether the bundle is readable.

## Built-in limits

These are fixed in 0.1.0. The counters (attempts, new requests, fetches and rows per period) live in
the cache (`DF_AAUTH_CACHE_STORE`): while the cache is unavailable they are off, and the cap of 20
open pending requests per agent, which the database enforces, still applies (see
[trust-model.md](trust-model.md#without-a-cache)).

| What | Limit |
|---|---|
| Consent and grants page sign-in failures | 10 per client address per 10 minutes; 20 per account per 15 minutes. A locked bucket answers "Too many attempts" without checking the password. |
| Wrong passwords on one request | 5; the request then ends and the agent's poll gets `410 invalid_code`. |
| Unknown or reused interaction codes | 10 per client address and per browser session per 10 minutes. |
| Pending requests | 20 open per agent; 30 new per agent per minute; 60 new per client address per minute (`429 rate_limited`, `Retry-After: 60`). |
| Discovery fetches that miss the cache | 20 per client address per minute. A failed fetch is remembered for 60 s; an unreachable host is skipped for 60 s. |
| Activity rows for requests that fail before any token verifies | 20 per client address per minute (the requests are still refused). |
| Token `iat` in the future | 60 s leeway, then `clock_skew`. |
| Justification text | 1000 characters. Agent names: 120 characters on consent pages. |
| **Try it** | 6 calls per run; a run is kept 15 minutes, its tokens 1 hour; recorded request and response bodies are cut at 64 KB. |

## Settings stored in the database

`aauth_settings` holds `enabled` (the admin switch), `retired_scopes` (scope names reserved after a
rename or a role deletion, maintained by DreamFactory), and two values without an admin control in
0.1.0:

| Name | Default | Meaning |
|---|---|---|
| `ps_local_enabled` | `true` | The built-in person server. `false` removes `/.well-known/aauth-person.json` and answers 404 on `/aauth/person`, `/aauth/token`, `/aauth/pending/*`, `/aauth/interact` and `/aauth/grants`; the resource keeps accepting tokens from trusted external person servers. |
| `name` | `DreamFactory` | Display name in the resource and person server metadata, and the resource name on consent pages and in grants. |

Values are JSON. To set them:

```sql
INSERT INTO aauth_settings (name, value, updated_at) VALUES ('name', '"Acme Data API"', CURRENT_TIMESTAMP);
-- or, when the row exists: UPDATE aauth_settings SET value = '"Acme Data API"' WHERE name = 'name';
```

## Related DreamFactory and Laravel settings

| Setting | Why it matters for AAuth |
|---|---|
| `APP_KEY` | Encrypts the private signing keys and derives the pairwise subject identifiers. Changing or losing it breaks AAuth; see [operations.md](operations.md#app_key). |
| `APP_URL` | Issuer fallback when `DF_AAUTH_ISSUER` is not set and `APP_URL` is https without a port. |
| `CACHE_STORE` | AAuth's short-lived state uses this store unless `DF_AAUTH_CACHE_STORE` names another. Must be shared (Redis, Memcached) across nodes. |
| `SESSION_DRIVER` | The consent and grants pages keep the signed-in person in a Laravel session with this driver unless `DF_AAUTH_SESSION_DRIVER` is set. Default `file` is per node. |
| `SESSION_SECURE_COOKIE` | The consent pages' session cookie is always `Secure` when the issuer is https. Set this to `true` as well when the admin app is served over https. |
| `DF_LOGIN_ATTRIBUTE` | The consent pages sign people in with this attribute (default `email`) and their DreamFactory password. |
