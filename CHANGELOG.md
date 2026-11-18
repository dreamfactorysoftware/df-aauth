# Changelog

All notable changes to `dreamfactory/df-aauth` are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versions follow semantic versioning.

## [0.1.0] - 2026-11-18

First release, shipped with DreamFactory 7.8.0. Commercial (Gold). Requires DreamFactory 7.8 or
later 7.x.

### Added
- AAuth resource for every `/api/v2` API: verifies RFC 9421 HTTP message signatures with the
  `Signature-Key` `jwt` scheme (draft-hardt-oauth-aauth-protocol-11, three-party "PS authorization"
  mode, and draft-hardt-httpbis-signature-key-09). Ed25519 and ES256. Covered components:
  `@method @authority @path signature-key`, plus `content-type` and `content-digest` with a body and
  `@query` when the URL has a query. `@authority` must be the issuer host.
- Challenges in the protocol's form: an agent token gets `401 AAuth-Requirement:
  requirement=person-token`; a person token gets `401 requirement=auth-token; resource-token="..."`
  for the least privileged enabled scope that allows the request; an auth token whose scopes do not
  cover the request gets a step-up challenge. Errors are `application/problem+json`; signature
  failures carry `Signature-Error`.
- Scopes are DreamFactory roles. An auth token's granted scope seeds that role (and, for tokens from
  this DreamFactory's Person Server, the person's user, never as a sys admin) into the session, so
  role access, filters, lookups, event scripts, limits and Data Masking apply as for any API key.
  Responses carry `AAuth-Scope`.
- Built-in Person Server: person and auth token endpoints, deferred responses with polling, a
  resource authorization endpoint, and server-rendered consent pages at `/aauth/interact`
  (interaction code `XXXX-XXXX`, DreamFactory email and password sign-in, "Continue as", per-scope
  consent, justification, "Always allow"). A person can grant a scope only when they hold its role
  (sys admins: any enabled scope). Standing grants are revocable by the person at `/aauth/grants`
  and by admins. Pairwise subject identifiers per resource.
- Trust in external Person Servers by issuer, each with its own scope allow-list (empty until an
  admin picks scopes, or "All scopes").
- A scope name a role gives up (scope renamed, role deleted) stays reserved for 61 minutes (a
  deleted role's names for no role at all). Standing grants and person server allow-lists at this
  DreamFactory follow a rename in the same transaction, and lose a deleted role's name, including
  the name of a rename saved while the delete ran, once the role row is gone (a delete that fails,
  for example because a login service still has the role as its default role, changes nothing the
  role can notice; a cleanup that fails after the delete is tried once more when the request ends).
  A role that takes a name starts without grants or allow-list entries for it, and an auth
  token issued before a role took its scope name never covers a request through it. A later role
  with that name therefore inherits no grants, allow-list entries or auth tokens here; person servers
  set to "All scopes" still trust it, and an external person server's own approvals are outside
  DreamFactory's reach.
- Agent registry: agents appear on their first signed request (APIs, authorization endpoint or
  person server); admins can block them. Blocks also apply to person and auth tokens through the
  key bindings (`aauth_agent_keys`, one row for every agent id a key has presented an agent token
  for): a key is refused while any of those agents, or its `jkt:` stand-in, is blocked, whatever
  agent id a later agent token claims, and pruning keeps bindings to blocked agents. The
  authorization endpoint and the person server refuse blocked agents as the APIs do. When the block
  state cannot be read, signed requests get `503 temporarily_unavailable`. Requests with person and
  auth tokens from this DreamFactory's person server belong to the agent each token was issued for
  (recorded in `aauth_ps_tokens` when it is issued; a token without a record gets `401 invalid_jwt`),
  not to the agent id the key presented last, so Activity, request counts and blocks follow the agent
  that got the approval or standing grant; tokens from external person servers follow the key's
  newest agent token. A signing key may present agent tokens for at most 20 agent ids (one more gets
  `403 too_many_agents`). The admin API's agent records list the other agents that share a signing
  key (`shares_key_with`, one hop, matched to agent rows by the database so collation-equal ids are
  linked as the block check links them; at most 20 per agent in the list, with
  `shares_key_with_truncated`, all of them from `GET /agents/{id}`).
- Activity log of every AAuth-signed API request with its outcome, retained 30 days by default.
- Built-in Agent Provider and the "Try it" playground agent: runs the whole flow against this
  DreamFactory from the admin app and shows every request, response and decoded token. A cached
  token the API refuses with a signature error is forgotten and the run starts over once.
- Well-known documents `aauth-resource.json`, `aauth-person.json`, `aauth-agent.json` and JWKS for
  each role; signing keys (Ed25519) generated on first use, private halves encrypted with
  `APP_KEY`.
- System resource `system/aauth` (sys admins only): overview and on/off switch, scopes, person
  servers, agents, activity, grants, playground.
- Request checks: replay cache for signed non-GET/HEAD requests (keyed on the agent key and the
  signature base; the SDKs' `verifySignedRequest` and
  `verify_request` replay sets key the same way), single-use resource tokens, single-use
  interaction codes claimed by the first browser that acts on them, which then owns the request and
  its outcome (opening the link claims nothing, so link previews and mail scanners cannot use a code
  up), discovery
  outbound guard (https only, public addresses only, pinned DNS, no redirects, timeout and size cap,
  cached results and failures, per-client fetch budget), CSRF and framing protection on the consent
  pages, sign-in and code attempt limits, pending request caps, `DF_AAUTH_TRUSTED_PROXIES` for
  client addresses behind a TLS proxy. Method overrides and multipart bodies are refused on signed
  requests; mixing AAuth with an API key or session token is refused.
- Agent clients: `@dreamfactory/aauth-agent` (`agent/`, Node 20+, no dependencies: library,
  `aauth` command line with `init`, `serve` and `request`, agent provider helpers, end-to-end suite)
  and `dreamfactory-aauth` (`clients/python/`, Python 3.9+). Both read the same identity file.
- Production settings: `DF_AAUTH_PRIVATE_HOSTS` and `DF_AAUTH_PRIVATE_NETWORKS` (explicitly admitted
  internal agent providers and person servers; link-local and metadata addresses stay refused),
  `DF_AAUTH_CA_BUNDLE` (internal CA for discovery and Try it), `DF_AAUTH_CACHE_STORE` and
  `DF_AAUTH_SESSION_DRIVER` (shared state and consent sessions across nodes).
- `php artisan df:aauth status | rotate-keys | prune`: deployment checks with warnings, signing key
  rotation with an overlap window (`DF_AAUTH_KEY_OVERLAP`, default 24 h; `--revoke` for a compromised
  key; optional scheduled rotation with `DF_AAUTH_KEY_ROTATION_DAYS`), and housekeeping.
- Migration `2026_11_12_000003_add_aauth_key_rotation_and_sessions`: `aauth_keys.retired_at` and the
  `aauth_sessions` table. Additive.
- Migration `2026_11_16_000004_keep_aauth_agent_key_history`: `aauth_agent_keys` holds one row per key
  and agent id instead of one per key (rebuilt through a new table; existing bindings are kept).
- Migration `2026_11_16_000005_add_aauth_scope_since`: `aauth_scopes.scope_since`, when the role took
  its scope name. Additive; existing rows stay unconstrained.
- Migration `2026_11_17_000006_create_aauth_ps_tokens_table`: `aauth_ps_tokens`, the agent each
  person and auth token of the built-in person server was issued for. Additive; tokens issued before
  it ran are refused (`401 invalid_jwt`), and the agent clients then get new ones.
- Documentation in `docs/`: install, configuration, admin guide, building agents, trust model,
  operations, OAuth mapping, single sign-on approval.
- Consent sign-in with LDAP and Active Directory accounts (df-adldap's bind and role mapping) and
  with every DreamFactory login method (OAuth, OpenID Connect, SAML) through a handoff to
  DreamFactory's login page (`DF_AAUTH_SSO`, `DF_AAUTH_SSO_LOGIN_PATH`, routes
  `GET|POST /aauth/interact/sso`). Signing in is still never consent. See `docs/sso-approval.md`.
- Admin API: `GET|POST /api/v2/system/aauth/keys` (list and rotate signing keys) and
  `GET /api/v2/system/aauth/status` (the `df:aauth status` facts).
- Person and auth token lifetimes above one hour are capped at 3600 seconds (longer tokens would
  fail verification).
- License level: AAuth needs a Gold license level, as df-compliance's service reports do. On other
  levels `system/aauth` answers 403 ("AAuth is not available for your license. Please upgrade to
  Gold."), AAuth behaves as off (signed requests go on to DreamFactory's own authentication, the
  AAuth endpoints answer 404) and `df:aauth status` says so.

### Unchanged behavior
- AAuth is off after install. A request without AAuth headers is handled exactly as before; with
  AAuth on, DreamFactory's own "no API key or session" responses only gain a discovery `Link`
  header (and `AAuth-Requirement: requirement=agent-token` on a 401). Status and body never change.
- While AAuth is off, every AAuth endpoint answers 404 and signed requests go through DreamFactory's
  normal authentication.

### Known limits
- Three-party mode only: no access server federation, missions, sub-agents, call chaining,
  revocation endpoint or `AAuth-Access` sessions.
- Person and auth tokens last at most one hour. Each person token request needs the person to open
  the link and continue; "Always allow" skips only the scope consent.
- Multipart uploads cannot be signed (no raw body for `Content-Digest`).
