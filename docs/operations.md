# Operations

Running AAuth in production: keys, backups, several nodes, monitoring and housekeeping. Installation is
in [install.md](install.md), settings in [configuration.md](configuration.md).

## Where state lives

Everything durable is in the DreamFactory system database, in the `aauth_*` tables. The cache holds
only short-lived state.

| Table | Holds | If lost |
|---|---|---|
| `aauth_settings` | The on/off switch, stored settings, and reserved names of renamed scopes and deleted roles' scopes | AAuth is off |
| `aauth_keys` | Signing keys (private halves encrypted with `APP_KEY`) | New keys are generated; every issued token stops verifying |
| `aauth_scopes` | Which roles are scopes, their names and descriptions | No scopes; agents get `403 insufficient_scope` |
| `aauth_person_servers` | Trusted person servers and their scope allow-lists | External person servers untrusted |
| `aauth_agents` | Agents seen, **blocks** | Blocks are lost |
| `aauth_agent_keys` | Every agent id each signing key has presented an agent token for (attributes external person servers' tokens and enforces blocks on person and auth tokens; bindings to blocked agents are never pruned) | Rebuilt as agents present agent tokens again; until a key presents one, a block of another agent id it used does not reach its tokens |
| `aauth_activity` | The activity log | History only |
| `aauth_ps_pending` | Open person and auth token requests (minutes) | Agents in the middle of an approval start over |
| `aauth_ps_tokens` | The agent each person and auth token of this person server was issued for, by `jti`, until an hour after the token expires (attributes those tokens' requests and blocks) | Tokens issued before are refused with `401 invalid_jwt`; agents get new ones |
| `aauth_ps_grants` | "Always allow" grants | People approve again |
| `aauth_ps_subjects` | Pairwise `sub` to DreamFactory user | Issued tokens no longer map to a person |
| `aauth_sessions` | Consent page sessions, only with `DF_AAUTH_SESSION_DRIVER=database` | People signed in on a consent page sign in again |

The cache (`DF_AAUTH_CACHE_STORE`, else DreamFactory's default store) holds the replay cache,
single-use resource token markers, interaction code ownership, rate limit counters, cached discovery
results, and **Try it** runs and tokens. Keys, scopes, blocks and grants never depend on it. Emptying it
(flushed, or restarted without persistence) loses what it held once: rate limits reset, cached
metadata is fetched again, a request signed within the last signature window (60 s) can be replayed
once more, a resource token can be exchanged again until it expires (300 s by default), open
approval requests lose their owning browser (another browser holding the code can take one over),
and **Try it** starts over. While the cache is unreachable, those checks and every rate limit are
skipped rather than failed: see [trust-model.md](trust-model.md#without-a-cache).

## Backups

A normal backup of the system database covers AAuth. Keep with it, as secrets:

- `APP_KEY`: without it the signing keys in the backup cannot be decrypted (see below);
- the `DF_AAUTH_*` lines of `.env`, in particular `DF_AAUTH_ISSUER`.

Restore onto a new host with the same `APP_KEY` and the same issuer, and agents carry on.

## APP_KEY

AAuth depends on Laravel's `APP_KEY`, like DreamFactory's own encrypted service settings:

- the private signing keys in `aauth_keys`, the finished tokens held in `aauth_ps_pending` until the
  agent collects them, and **Try it**'s cached tokens are encrypted with it;
- pairwise subject identifiers are HMACs keyed from it.

If `APP_KEY` changes, DreamFactory cannot decrypt its signing keys (enabling AAuth and minting tokens
fail with server errors), and every person gets new subject identifiers, so existing subject mappings
and grants no longer find them. Restore the previous `APP_KEY` to recover.

If the old key is gone for good, start AAuth's keys and approvals over (back up the tables first):

```sql
DELETE FROM aauth_keys;           -- new keys are generated on the next use
DELETE FROM aauth_ps_pending;
DELETE FROM aauth_ps_grants;
DELETE FROM aauth_ps_subjects;
```

Then `php artisan cache:clear`. Scopes, person servers, agents, blocks and activity are kept. Every
agent goes through approval again; parties that cached the old JWKS fetch the new one on the unknown
`kid`.

## Signing keys

There are three keys, one per role: `resource` (resource tokens), `person` (person and auth tokens)
and `agent` (agent tokens of the **Try it** agent). Each is Ed25519, generated when AAuth is first
enabled, and published at `<issuer>/aauth/jwks/{resource,person,agent}.json`. `php artisan df:aauth
status` lists them (key id, state, created, retired, published until), never their private halves.

Rotate with:

```bash
php artisan df:aauth rotate-keys                      # all three roles
php artisan df:aauth rotate-keys --purpose=person     # one role (repeat --purpose for several)
php artisan df:aauth rotate-keys --older-than=90      # only keys at least 90 days old
```

A new key signs at once. The previous key is retired: it stays published in the JWKS, and tokens it
signed keep verifying, for `DF_AAUTH_KEY_OVERLAP` seconds (default 86400, never less than the longest
token lifetime + 5 minutes). Verifiers that cached the old JWKS see an unknown `kid` on the next token
and fetch the new one, as the protocol requires. After the overlap, `prune` deletes the retired key,
private half included.

To rotate on a schedule, set `DF_AAUTH_KEY_ROTATION_DAYS` (for example `90`); the Laravel scheduler,
which DreamFactory images run every minute, then rotates keys that reach that age.

**If a key may have been exposed**, rotate with `--revoke`: the previous keys are deleted at once and every
token they signed stops verifying. Agents run the flow again and people approve again.

```bash
php artisan df:aauth rotate-keys --purpose=person --revoke
```

Rotation needs the `2026_11_12_000003` migration (`aauth_keys.retired_at`); until it has run,
`rotate-keys` refuses and `status` warns.

The same is available to sys admins over the API: `GET /api/v2/system/aauth/keys` lists the keys and
`POST /api/v2/system/aauth/keys {"purpose": "person", "revoke": true}` rotates (both fields optional).

## Several DreamFactory nodes

All nodes behind one issuer must share:

- the system database (as DreamFactory requires anyway);
- the same `APP_KEY` and the same `DF_AAUTH_*` settings;
- **one cache store** for AAuth's short-lived state: `DF_AAUTH_CACHE_STORE=redis` (or `memcached`,
  `database`), or a shared `CACHE_STORE`, pointing at the same server on every node. The replay cache,
  single-use resource tokens, interaction code ownership and rate limits only work when every node sees
  the same counters. With a per-node store (`file`, `array`, `apc`), a replayed request sent to another
  node is accepted and every limit is multiplied by the number of nodes;
- **the consent pages' sessions**: `DF_AAUTH_SESSION_DRIVER=redis` (or `database`, which uses the
  `aauth_sessions` table), or sticky sessions on the load balancer for `/aauth/*`. This setting
  changes the session driver for the consent and grants pages only. With the default `file` driver the
  signed-in person lives on one node, and a form post that reaches another node starts over.

`php artisan df:aauth status` says whether the cache store and the consent sessions are shared, and
warns when they are not.

The load balancer must preserve `Host` and the request target (see
[install.md](install.md#the-issuer-and-the-reverse-proxy)). Run NTP on every node: a node whose clock
drifts by more than the signature window refuses fresh signatures with `clock_skew` or
`invalid_signature`.

Enable AAuth once, through any node. That call generates the keys; if two nodes race to create a key,
both keys are published and the oldest is used for signing, which is harmless.

## Monitoring

| Check | Healthy |
|---|---|
| `GET <issuer>/.well-known/aauth-resource.json` | `200` with the expected `issuer`. `404` means AAuth is off or the package is missing. |
| `GET /api/v2/system/aauth` (sys admin) | `"enabled": true, "issuer_ok": true`; `counts.activity_24h` for traffic. |
| An unauthenticated `GET <issuer>/api/v2/...` | Has `Link: <...aauth-resource.json>; rel="aauth-resource"` (the middleware is active). |
| `php artisan migrate:status` | The six `aauth` migrations ran. |
| `php artisan df:aauth status` | No `!` warnings. `--json` for scripts. |

**Activity** (or the `aauth_activity` table) shows why agents fail. Watch the `error` outcome; its
detail names the cause:

| Detail | Usual cause |
|---|---|
| `clock_skew`, or `invalid_signature` about `created` | Clock drift on the agent or the server |
| `invalid_signature: Use https://...` | The agent calls another host name, or the proxy rewrites `Host` |
| `invalid_signature` on every request through one path | The proxy changes the path, query, body or signature headers |
| `unknown_key: Discovery failed: ...` | The agent provider's metadata or JWKS is unreachable, too large, not https, or on a private address |
| `invalid_signature: This signature was already used.` | An agent retries a POST/PATCH without re-signing, or sends the same request twice within one second (same token, same `created`) |
| `invalid_jwt: This DreamFactory has no record of issuing this token. Get a new one.` | A token issued before the `2026_11_17_000006` migration ran, or whose record was deleted; the agent clients and Try it drop it and start over |
| `too_many_agents: This signing key has already presented agent tokens for 20 agent ids at this DreamFactory. ...` (`403`) | One key presented agent tokens for more than 20 agent ids. A real agent uses one id per key; look at that key's agents (`shares_key_with`) and block them if this is not expected |

DreamFactory's log has a line starting with `df-aauth` for every internal failure. The ones to alert on:

| Message | Means |
|---|---|
| `df-aauth: df.access_check not found in df.api; AAuth requests are not accepted.` | This DreamFactory version's middleware layout is not supported; signed requests get DreamFactory's normal errors. |
| `df-aauth: middleware not registered: ...` | As above, with the reason. |
| `df-aauth: agent state unavailable, signed request refused: ...` | The system database could not say whether the agent is blocked; the API request got `503 temporarily_unavailable` with `Retry-After: 30`. |
| `df-aauth person server: agent state unavailable, request refused: ...` | The same at the person server (`/aauth/person`, `/aauth/token`, `/aauth/pending/*`). |
| `df-aauth person server: ...` (other) | A person server endpoint answered `500 server_error`. |
| `df-aauth authorize: agent state unavailable, request refused: ...` | The same at the resource authorization endpoint (`/aauth/authorize`). |
| `df-aauth authorize: ...` (other) | The resource authorization endpoint answered `500`. |
| `df-aauth: role <id> not deleted, its AAuth scope name could not be released: ...` | A role delete was refused (`500`): its scope name could not be reserved before the delete, or not removed from grants and person server lists while the delete ran in a transaction (rolled back). Nothing changed. Retry once the database is healthy. |
| `df-aauth: role <id> deleted, but its AAuth scope name could not be removed from grants and person server lists: ...` | The role was deleted (outside a transaction) and the cleanup after it failed. It is tried once more when the request ends: a `df-aauth: role <id> deleted; its AAuth scope name was removed from grants and person server lists when the request ended.` notice follows when that works, this line again when it does not. Either way the name stays reserved for no role for 61 minutes (names the role renamed away earlier stay reserved for its id until their 61 minutes are up), and grants and person server lists that still show it pass nothing on (a role that takes the name starts without them). Revoke such grants by hand if you want them gone. |
| `df-aauth: could not seed the session: ...` | An approved request could not get its role (`403`). |
| `df-aauth: activity not recorded: ...` | A database write failure; requests are still served. |

## Pruning

```bash
php artisan df:aauth prune              # what it removed, per kind
php artisan df:aauth prune --dry-run    # count only
```

`prune` removes pending requests that expired more than an hour ago, activity rows older than
`DF_AAUTH_ACTIVITY_RETENTION_DAYS` (30), agent key bindings not seen for that long (never one to a
blocked agent), retired signing keys past the overlap window, expired scope-name reservations, and
records of issued tokens that expired more than an hour ago. It is idempotent and safe on every node; it exits non-zero when a step failed (the other
steps still run). It is scheduled daily, and also runs on about one in 100 activity writes.

A retention of `0` keeps activity and agent keys forever. Grants stay until revoked, agents until
deleted, and subject mappings indefinitely: they are needed for as long as tokens and grants refer to
them.

The schedule is registered by the service provider (`php artisan schedule:list | grep aauth`):
`df:aauth prune` daily at 03:17 and, when `DF_AAUTH_KEY_ROTATION_DAYS` is set,
`df:aauth rotate-keys --older-than=N` daily at 03:47, each on one server and never overlapping.
DreamFactory Docker images already run the Laravel scheduler every minute. On an install that does
not, add it to the web server user's crontab:

```cron
* * * * * cd /opt/dreamfactory && php artisan schedule:run >> /dev/null 2>&1
```

`onOneServer()` needs a cache store with atomic locks shared by every node (`redis`, `memcached`,
`database`); with the `file` store each node runs the job itself, which is harmless for `prune`.

## Changing the issuer

The issuer is in every token DreamFactory issues and in every grant and subject mapping of its person
server. Changing `DF_AAUTH_ISSUER`:

- invalidates every issued token; agents must discover the new issuer and start over;
- leaves grants and subject mappings for the old issuer unused: people approve again;
- moves DreamFactory's own person server row to the new issuer automatically;
- requires other resources that trusted DreamFactory as a person server to trust the new issuer.

Treat it as a migration, announced to agent owners.

## Performance

Each signed API request adds a few small writes to the system database: one activity row, the agent's
counter, and (for agent tokens) the key mapping. A request with this DreamFactory's own person or
auth token also reads that token's record (one primary-key lookup); issuing a token writes it. DreamFactory's own tokens are verified from the
database without network calls. Tokens from other issuers need their metadata and JWKS, fetched once
and cached for 5 minutes. Data Masking, limits, scripts and logging cost what they cost for any API
key request.

## Responding to an incident

[admin-guide.md](admin-guide.md#responding-to-an-incident) lists the controls (block an agent, remove a
person server, revoke grants, remove a role from a person, disable a scope, switch AAuth off). Each
takes effect on the next request. Activity rows are kept for the investigation.
