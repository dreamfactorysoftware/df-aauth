# Trust model

What AAuth on DreamFactory protects, what it verifies, and what it leaves to you. Configuration
names are in [configuration.md](configuration.md).

## What is protected

| Asset | How AAuth protects it |
|---|---|
| The data behind DreamFactory's APIs | An agent reads or changes only what a person approved, and only with its own key. |
| DreamFactory users' credentials | The consent pages use CSRF tokens, refuse framing and limit sign-in attempts. |
| DreamFactory's internal network | Discovery fetches go only to public addresses unless an admin admits internal ones. |
| DreamFactory's signing keys | Private halves are encrypted with `APP_KEY` and can be rotated or withdrawn at once. |

The design rests on three properties:

1. **No bearer credentials.** Every token is bound to the agent's key (`cnf.jwk`), and every request is
   signed with that key. A token copied from a log or a proxy is useless without the private key.
2. **People approve, roles decide.** An agent gets a scope only when a person approves it, and a
   scope is a DreamFactory role that the person must hold. DreamFactory enforces the role exactly as
   it would for an API key.
3. **Off by default, closed on failure.** Nothing changes until an admin enables AAuth. A request
   that fails any check is refused; nothing falls back to anonymous access. A check against the
   system database that cannot be made is a failure too: when DreamFactory cannot say whether an
   agent is blocked, or for whom its own person server issued a token, the request gets `503
   temporarily_unavailable` with `Retry-After: 30`. The checks kept in the cache are the exception:
   without a working cache they are skipped, not failed, so a cache outage does not stop agent
   access (see [Without a cache](#without-a-cache)).

## What DreamFactory verifies on a signed API request

In this order. Malformed requests get `400`, signature and token failures `401` with
`Signature-Error`, refusals after everything verified `403`:

1. `Signature`, `Signature-Input` and `Signature-Key` are present. The request does not also carry an
   API key or session token, does not override its method (`X-HTTP-Method-Override` and similar) and
   has no multipart body. Mixed credentials are ambiguous; an override or an unsigned multipart body
   would let what runs differ from what was signed.
2. `@authority` is the issuer host. Requests to another host name of the same server are refused.
3. `Signature-Key` uses the `jwt` scheme; the token's `typ` is an agent, person or auth token (checked
   before anything else in the token).
4. For person and auth tokens, the issuer is a trusted, enabled person server. This is checked before
   any network fetch, so untrusted issuers cannot make DreamFactory fetch anything.
5. The token verifies: issuer metadata (`issuer` must equal `iss` byte for byte), key by `kid` from the
   issuer's JWKS, signature, `alg` (Ed25519 or ES256 only, never `none` or `EdDSA`), `exp`, `iat` (at most
   60 s ahead), person and auth tokens at most one hour long, `cnf.jwk` present with a supported `alg`.
   DreamFactory's own tokens are verified from its database, never over HTTP.
6. The HTTP signature verifies with `cnf.jwk`: required components covered (`@method @authority @path
   signature-key`, `content-type` and `content-digest` with a body, `@query` with a query), `created`
   within the window, `expires` honored, `Content-Digest` matching the exact body, raw path and query
   from the request line (not Laravel's normalized forms).
7. A signed non-GET/HEAD request has not been seen before (replay cache).
8. The agent is not blocked. The request belongs to the agent its agent token names; with a person
   or auth token from DreamFactory's own person server, to the agent the token was issued for
   (recorded when it was issued; a token without a record gets `401 invalid_jwt`); with an external
   person server's token, to the agent the signing key last presented an agent token for. Neither
   that agent nor any agent id the signing key has presented an agent token for (a key never seen
   with one is its `jkt:` stand-in) may be blocked. So an agent token naming a new agent id, sent
   before or after the block, frees neither the key nor the person and auth tokens issued to it.
   With tokens from DreamFactory's own person server, moving the key to a throwaway agent id does
   not hide the agent that got the approval either. With an external person server's tokens it
   does steer the attribution: the agent provider can put any agent id in the key's next agent
   token, and the agent the external person server approved need never be presented here. Block the
   ids that key used (or its `jkt:` row; the block holds on the key), or stop trusting that person
   server. A key may present agent tokens for at most 20 agent ids; one more gets `403
   too_many_agents`. The authorization endpoint and this DreamFactory's person server make the same
   checks.
9. For person and auth tokens: `aud` is this DreamFactory, `sub` is present, and auth tokens come
   from a person server that names itself (`ps == iss`, metadata `aauth-person.json`). Tokens from
   access servers are refused; DreamFactory federates with none.
10. For auth tokens: a granted scope that is enabled, allowed for that person server, already held
    by its role when the token was issued (`iat`), and whose role allows the request. For tokens from DreamFactory's own person server, the person must still be
    active and still hold that role, checked on every request.

Only then is the session seeded: the scope's role, the person's DreamFactory user (own person server
only) with sys-admin rights forced off, and the hidden `aauth` app. DreamFactory's access check then
runs as usual, and so do filters, lookups, scripts, limits and Data Masking.

## Replay

- `created` must be within ±60 s (`DF_AAUTH_SIGNATURE_WINDOW`).
- Non-GET/HEAD requests are remembered for twice the window by what was signed (the agent key and
  the signature base), not by the signature bytes, and refused the second time. An ES256 signature
  has a second valid form; both count as the same request. A captured GET could be replayed within
  the window; it is read-only, and TLS between agent and DreamFactory keeps signatures out of reach.
- Resource tokens are single-use at the person server. A retry with the same agent key gets the
  pending request it already created, so a lost response does not strand the agent.
- Replay protection and single-use resource tokens need the cache (`DF_AAUTH_CACHE_STORE`); see
  [Without a cache](#without-a-cache). With several nodes the store must be shared (see
  [operations.md](operations.md#several-dreamfactory-nodes)); `php artisan df:aauth status` warns
  when it is not.

## Without a cache

Short-lived state lives in the cache (`DF_AAUTH_CACHE_STORE`, else DreamFactory's default store).
When the store fails (errors on every call), these checks are skipped rather than failed, so a cache
outage does not take agent access down:

| Check | While the cache is unavailable |
|---|---|
| Replay of signed non-GET/HEAD requests | Not detected: a captured request can be sent again while its `created` is within the signature window (60 s by default). |
| Single-use resource tokens (person server) | Not enforced: a resource token can be exchanged again until it expires (`DF_AAUTH_RESOURCE_TOKEN_TTL`, 300 s by default). Each exchange still needs the person's consent or a standing grant. |
| Interaction code ownership | Not enforced: any browser holding the code can act on an open request, not only the first one. Approving still needs a signed-in person who may grant what is asked, and a scope request still only the person its presented token names. |
| Rate limits and failure counters | Off: sign-in failures per address and per account, wrong codes, five wrong passwords ending a request, single sign-on returns, new pending requests per agent and per address per minute, uncached discovery fetches per address, and logging of unverified requests. The cap of 20 open pending requests per agent is kept in the database and still applies. |
| Discovery results | Not cached: agent providers' and external person servers' metadata and JWKS are fetched for every request that needs them, and failures are not remembered. |
| Try it | Does not work (its runs and tokens live in the cache). |

Everything that decides access (keys, scopes, person servers, blocks, grants, pending requests,
issued-token records) is in the system database and fails closed. DreamFactory logs no line per
skipped check, so monitor the cache store itself. When the cache is emptied instead (flushed, or
restarted without persistence), what it held is lost once: a request signed within the last signature
window can be replayed once more, resource tokens can be exchanged again until they expire, and open
requests lose their owning browser, so another browser holding the code can take one over.

## Discovery and outbound fetches

DreamFactory fetches metadata and JWKS for agent providers and external person servers named in
tokens. Every fetch is admitted first:

- https only;
- the host must resolve only to public unicast addresses. Loopback, private, link-local (including
  cloud metadata addresses), CGNAT, multicast, documentation and reserved ranges are refused, for IPv4
  and IPv6; IPv4-mapped, NAT64 and 6to4 addresses are judged by the IPv4 address inside;
- the connection is pinned to the address that was checked (no DNS rebinding);
- no redirects, a 3 s timeout, a 256 KB cap, no credentials in URLs;
- results are cached 5 minutes, an unknown `kid` refreshes at most once per minute per URL, failures
  are cached 60 s, and uncached fetches are limited to 20 per client address per minute.

Internal agent providers and person servers are admitted only explicitly, per host name
(`DF_AAUTH_PRIVATE_HOSTS`, which may then resolve to private-use addresses but not loopback) or per
network (`DF_AAUTH_PRIVATE_NETWORKS`). Link-local addresses (including `169.254.169.254` and the other
cloud metadata addresses), `0.0.0.0/8`, multicast and reserved ranges stay unreachable whatever is
listed, in every IPv6 spelling. Keep both lists to the servers that need them: whoever presents a
token chooses the issuer URL DreamFactory fetches. `DF_AAUTH_CA_BUNDLE` replaces the trusted CAs for
these fetches; an unreadable bundle makes every fetch fail. Details:
[configuration.md](configuration.md#private-networks-and-custom-cas).

`DF_AAUTH_ALLOW_INSECURE=true` lifts the https and public-address rules (not the link-local and
metadata ones) and is for local development only.

## Consent pages

The pages at `/aauth/interact` and `/aauth/grants` are where people sign in, so they get the usual web
protections:

- CSRF tokens on every form; `X-Frame-Options: DENY` and CSP `frame-ancestors 'none'; default-src
  'self'`; `Cache-Control: no-store`; the session cookie is `Secure` when the issuer is https.
- Sign-in uses the DreamFactory password check without creating a DreamFactory session. Failures are
  limited per client address (10 per 10 minutes) and per account (20 per 15 minutes); a locked bucket
  does not check the password, so the pages cannot be used to test passwords. Five wrong passwords on
  one request end that request.
- **Directory and single sign-on.** LDAP and Active Directory accounts are checked with df-adldap's own
  bind and role mapping (same limits, one bucket per directory account). OAuth, OpenID Connect and SAML
  users go through DreamFactory's login page, which hands back a DreamFactory session token in the URL
  fragment (never the query, so it stays out of logs and `Referer`); the return needs a single-use state
  bound to the browser that started it, and the token is checked like any DreamFactory session
  (signature, expiry, logout blacklist, active user). Details: [sso-approval.md](sso-approval.md).
- **The interaction code is a correlation id, not a credential, and whoever acts on it first owns the
  request.** Every decision is a CSRF-protected POST: approving needs a signed-in person who may grant
  what is asked, denying needs no sign-in. A code is single-use: the first browser that submits
  anything for it (signs in, starts single sign-on, presses any button on the card, or types the
  code; the waiting card after Continue claims the agent's next request the same way) owns the
  request and its outcome; every other browser, including one that opened the link earlier, gets
  "already used". Opening the link claims nothing and changes nothing, so chat link previews and
  mail scanners that fetch it first cannot use it up. Until the person acts, anyone holding the link
  can act first: deny the request, or, at the identity step, sign in with their own account and
  continue as themselves (the agent then acts for that account). A scope request can be approved
  only by the person its presented token names. Agents should show the code to the person only,
  never in a shared channel. A code expires with its request (10 minutes), and wrong codes are
  limited (while the cache works, see [Without a cache](#without-a-cache)).
- **Signing in is not consent.** The person always chooses Continue or Allow, sees which account is
  signed in, and can switch accounts.
- The agent's name is self-asserted (from its agent provider's metadata), so the cards also show the
  verified agent id.
- The browser returns only to the agent's registered `callback_endpoint` (same origin and path, https).
  Tokens never pass through the browser.
- All text from agents (names, justifications) is escaped and shown as plain text.

## Who can grant what

- On DreamFactory's own person server, a person can approve a scope only when they are a sys admin or
  hold its role. A person cannot give an agent more than they have.
- A newly added external person server can vouch for no scopes until an admin chooses some. The
  external person server decides who approves; DreamFactory enforces the role and attaches no
  DreamFactory user.
- Agents never get sys-admin rights, whoever approved them.
- A scope name a role gives up does not pass to the next role that takes it. On a rename, standing
  grants and person server scope lists move to the new name in the same transaction (a rename whose
  cleanup fails is not made). A role delete gives the name up only once the role row is gone; then
  the name is removed from them (a grant left with no scope is deleted), and so is the name of a
  rename saved while the delete ran. A delete that fails, for example on another table's reference
  to the role such as a login service's default role, changes nothing the role can notice. A role
  that takes a name starts without grants or scope-list entries for it, so not even a cleanup that
  failed after a delete (it is tried once more when the request ends) passes anything on. The old
  name stays reserved for 61 minutes, the longest auth token lifetime DreamFactory accepts plus a
  minute: for the renamed role; for no role at all from the moment a role delete starts (a role
  whose delete is refused may still keep and re-save it); and, once the row is gone, the names the
  deleted role renamed away for no role too (if its cleanup fails both times, those stay reserved
  for its id until their 61 minutes are up).
  DreamFactory also records when a role took its scope name and ignores that name in an auth token
  issued (`iat`) before then, so a token minted for the earlier holder, even late by an external
  person server, never reaches the new role. A person server set to **All scopes** trusts every
  enabled scope, including a later one with the same name, and an external person server's own
  standing approvals are keyed by scope name and outside DreamFactory's reach.
- Subject identifiers (`sub`) are pairwise per resource, so two resources cannot correlate a person by
  `sub`.

## Keys

- Three Ed25519 signing keys (resource, person server, agent provider), generated when AAuth is first
  enabled. Private halves are encrypted with `APP_KEY` in `aauth_keys`; public halves are published in
  the JWKS documents.
- Anyone with `APP_KEY` and a copy of the system database can mint tokens this DreamFactory accepts.
  Protect both as you protect the admin password.
- Keys rotate with `php artisan df:aauth rotate-keys` (retired keys stay published for an overlap
  window) or on a schedule; `--revoke` withdraws a compromised key at once. Details and the `APP_KEY`
  dependency: [operations.md](operations.md#signing-keys).

## Abuse limits

Pending requests (20 open per agent, 30 new per agent and 60 per client address per minute),
sign-in and code attempts, discovery fetches, and activity logging of unverified junk (20 rows per
client per minute) are all bounded while the cache works (see [Without a cache](#without-a-cache));
see [configuration.md](configuration.md#built-in-limits). Limits are per client address, so set
`DF_AAUTH_TRUSTED_PROXIES` behind a reverse proxy, or every client shares the proxy's budget.

## What is recorded

**Activity** stores, per signed API request and per refused authorization endpoint request: time,
agent id, person server, `sub`, DreamFactory user
id (when known), scope, method, path (no query string, no headers, no bodies), status and outcome. The
person server stores pending requests (with the encrypted resulting token until delivered), standing
grants, subject mappings, and for every person and auth token it issues its `jti` and the agent it
was issued for (until an hour after the token expires). Cache keys for rate limits are hashed, so emails and addresses do not
appear in the cache.

## Out of scope in 0.1.0

- **Access servers and other access modes.** Three-party mode only: no access server federation,
  missions, sub-agents, call chaining or `AAuth-Access` sessions. Missions are refused, not ignored.
- **Revocation endpoint.** Not implemented. To cut an agent off, block it, revoke its grants, remove
  the person's role, disable the scope or the person server, or switch AAuth off; each takes effect on
  the next request. Issued auth tokens otherwise live until they expire (at most one hour).
- **Binding an agent to one person** (protocol §13.14). Any signed-in DreamFactory user with the role
  can approve any agent's request.
- **Agent key custody.** How an agent and its agent provider protect their keys is theirs to decide.
  DreamFactory cannot tell a compromised agent provider from a genuine one; block the agent or stop
  trusting the provider's agents if that happens.
- **Tokens from external person servers** do not name the agent: their requests belong to the agent
  the key last presented an agent token for (which its agent provider chooses), and blocks cover the
  keys DreamFactory has seen with that agent's agent token, and a key's `jkt:` stand-in row.
- **Blocks follow keys.** Blocking an agent id refuses every key that ever presented it. An agent that
  comes back with a new key under a new agent id is a new agent to DreamFactory: it has no grants and
  needs a person's approval again.
- **Multipart uploads** cannot be signed.
- **The admin app** is protected by DreamFactory's own admin authentication; AAuth adds nothing to it.

## Reporting a problem

Email dspsupport@dreamfactory.com with "AAuth" in the subject. Please send details of a suspected
problem with these checks by email rather than in a public issue.
