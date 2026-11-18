# Building agents for DreamFactory AAuth

This page is for developers who write an AI agent, or a tool an agent uses, that calls DreamFactory
APIs through AAuth. It covers what the agent needs, the exact HTTP exchange, the errors, and the client
libraries in this package. The protocol is draft-hardt-oauth-aauth-protocol-11 (three-party "PS
authorization" mode) with draft-hardt-httpbis-signature-key-09. An agent that follows those drafts
works with DreamFactory without DreamFactory-specific code.

Examples use:

| | |
|---|---|
| DreamFactory (resource and person server) | `https://api.example.com` |
| Your agent provider | `https://agents.example.com` |
| Your agent's id | `aauth:reports@agents.example.com` |

## What an agent needs

1. **A request key.** An Ed25519 key pair (or ECDSA P-256 for ES256). The private key never leaves
   the agent; every request is signed with it. Its public JWK must carry `alg` (`"Ed25519"` or
   `"ES256"`); the polymorphic `"EdDSA"` is refused.
2. **An agent provider**, an https origin you control that vouches for your agents. It serves:
   - `https://agents.example.com/.well-known/aauth-agent.json`:
     ```json
     {
       "issuer": "https://agents.example.com",
       "jwks_uri": "https://agents.example.com/jwks.json",
       "name": "Acme Reports",
       "callback_endpoint": "https://agents.example.com/callback"
     }
     ```
     `issuer` must equal the origin byte for byte. `name` is what people see on the consent page
     (it is self-asserted, so DreamFactory also shows the agent id). `callback_endpoint` is optional: an
     https URL the person's browser returns to after approving.
   - its JWKS (`{"keys": [...]}`): the public keys that sign agent tokens, each with `kid` and `alg`.
   The provider must be reachable from DreamFactory over https on a public address (or one an admin
   allowed; see [configuration.md](configuration.md#private-networks-and-custom-cas)).
3. **An agent token** (`typ: aa-agent+jwt`), signed by the agent provider's key, binding the agent id
   to the request key:
   ```text
   header  {"alg": "Ed25519", "typ": "aa-agent+jwt", "kid": "ap-1"}
   payload {
     "iss": "https://agents.example.com",
     "dwk": "aauth-agent.json",
     "sub": "aauth:reports@agents.example.com",
     "cnf": {"jwk": {"kty": "OKP", "crv": "Ed25519", "x": "<request key>", "alg": "Ed25519"}},
     "jti": "<random>",
     "iat": 1794312000,
     "exp": 1794315600
   }
   ```
   The agent id is `aauth:<name>@<agent provider host>` (letters, digits and `. _ + -` before the `@`;
   DreamFactory's person server refuses other forms). The protocol caps `exp` at 24 hours after `iat`;
   DreamFactory refuses an `iat` more than 60 s in the future.
4. **A person server** that the DreamFactory admin trusts. Usually that is DreamFactory itself
   (`/.well-known/aauth-person.json` on the issuer). It can also be your organization's own person
   server, once an admin adds it under **Person Servers** and allows it scopes.
5. **The person** the agent acts for: someone with a DreamFactory account (on the built-in person server)
   who holds the role behind the scope the agent needs.

DreamFactory needs no client registration. The agent shows up in the admin app under **Agents** on its
first signed request.

## Endpoints

All on the issuer origin. Everything except `/api/v2` answers 404 while AAuth is off. The JSON
endpoints send `Access-Control-Allow-Origin: *` and answer `OPTIONS`, so browser-based agents can use
them.

| Endpoint | Signed with | |
|---|---|---|
| `GET /.well-known/aauth-resource.json`, `aauth-person.json`, `aauth-agent.json` | not signed | Metadata |
| `GET /aauth/jwks/{resource,person,agent}.json` | not signed | Public keys |
| any `/api/v2/...` | agent, person or auth token | The APIs |
| `POST /aauth/authorize` | person or auth token | Resource token for named scopes |
| `POST /aauth/person` | agent token | Person token request |
| `POST /aauth/token` | agent token | Auth token request |
| `GET`, `DELETE /aauth/pending/{id}` | agent token (same key) | Poll, cancel |
| `/aauth/interact`, `/aauth/grants` | browser | Consent pages; a person's standing grants |

For `/api/v2` calls from a browser, the DreamFactory CORS entry for the agent's origin must exist;
DreamFactory then also allows the signature headers and exposes the AAuth ones.

## Signing requests

Every request to DreamFactory (API calls and person server calls) is an RFC 9421 HTTP message
signature with label `sig` and the `Signature-Key` header carrying one of the agent's tokens:

```http
Signature-Key: sig=jwt;jwt="<agent token | person token | auth token>"
Signature-Input: sig=("@method" "@authority" "@path" "@query" "signature-key");created=1794312000
Signature: sig=:<standard base64 of the raw signature bytes>:
```

| Rule | |
|---|---|
| Covered components | Always `@method`, `@authority`, `@path`, `signature-key`. With a body, also `content-type` and `content-digest`. With a query string, also `@query`. The resource metadata lists these in `additional_signature_components` (`@query` applies only when there is a query; `content-type` and `content-digest` only when there is a body). |
| `@authority` | The issuer host (`api.example.com`), lowercase, no port. A signature for any other host name gets `Use https://api.example.com`. |
| `@path`, `@query` | Exactly as sent on the wire: the raw, still-encoded path, and `?` plus the raw query. |
| `created` | Current Unix time; accepted within 60 s of the server clock (`signature_window`). `expires` is optional and honored. No `alg` parameter (ignored) and no `keyid`. |
| Signature bytes | Ed25519: the 64-byte signature. ES256: raw `r‖s` (64 bytes), not DER. |
| `Content-Digest` | `sha-256=:<standard base64 of SHA-256(body)>:` over the exact body bytes. |
| Replays | A signed POST, PUT, PATCH or DELETE is accepted once. DreamFactory remembers what was signed (your key and the signature base), not the signature bytes, so a new signature over the same request with the same `created` is a replay too, for ES256 as for Ed25519. Sign each request afresh. |
| Not allowed | Method overrides (`X-HTTP-Method-Override` and similar), multipart bodies (send JSON), and an API key or session token in the same request. |

The signature base for that request:

```
"@method": GET
"@authority": api.example.com
"@path": /api/v2/sales/_table/orders
"@query": ?limit=5
"signature-key": sig=jwt;jwt="eyJhbGciOiJFZDI1NTE5IiwidHlwIjoiYWEtYWdlbnQrand0Iiwia2lkIjoiYXAtMSJ9.eyJ...."
"@signature-params": ("@method" "@authority" "@path" "@query" "signature-key");created=1794312000
```

Lines are joined with `\n`, no trailing newline, in the order of `Signature-Input`.

## The flow, request by request

Every request except the metadata fetch is signed; `Signature-Input` and `Signature` are shown only
in step 2. Error bodies are `application/problem+json`.

### 0. Discover

```http
GET /.well-known/aauth-resource.json HTTP/1.1
Host: api.example.com

HTTP/1.1 200 OK
Content-Type: application/json

{"issuer":"https://api.example.com",
 "jwks_uri":"https://api.example.com/aauth/jwks/resource.json",
 "name":"DreamFactory",
 "access_mode":"auth-token",
 "authorization_endpoint":"https://api.example.com/aauth/authorize",
 "scope_descriptions":{"sales.read":"Read customers and orders","sales.refund":"Update order status"},
 "signature_window":60,
 "additional_signature_components":["@query","content-type","content-digest"]}
```

Check that `issuer` equals the origin you fetched. An unauthenticated API response also points here:
`Link: <https://api.example.com/.well-known/aauth-resource.json>; rel="aauth-resource"`. The person
server's document is `/.well-known/aauth-person.json` (`person_token_endpoint`,
`auth_token_endpoint`, `jwks_uri`).

### 1. Call with the agent token

```http
GET /api/v2/sales/_table/orders?limit=5 HTTP/1.1
Host: api.example.com
Signature-Key: sig=jwt;jwt="<agent token>"

HTTP/1.1 401 Unauthorized
AAuth-Requirement: requirement=person-token
Cache-Control: no-store

{"error":"person_token_required","detail":"Get a person token from your person server and sign with it."}
```

### 2. Ask the person server for a person token

```http
POST /aauth/person HTTP/1.1
Host: api.example.com
Content-Type: application/json
Content-Digest: sha-256=:0USp0eQ3uMl6lOVxZAu9lKaHt51g0gQ35rgiEOwUDJY=:
Signature-Key: sig=jwt;jwt="<agent token>"
Signature-Input: sig=("@method" "@authority" "@path" "signature-key" "content-type" "content-digest");created=1794312001

{"resource":"https://api.example.com","capabilities":["interaction"],"justification":"Weekly sales report for the ops review"}

HTTP/1.1 202 Accepted
Location: https://api.example.com/aauth/pending/Xq3...
Retry-After: 2
Cache-Control: no-store
AAuth-Requirement: requirement=interaction; url="https://api.example.com/aauth/interact"; code="7KQM-4D2P"

{"status":"pending","code":"7KQM-4D2P"}
```

`capabilities` must include `"interaction"` (the person server has to reach the person; without it the
answer is `403 user_unreachable`). `justification` (up to 1000 characters) is shown to the person.
Missions (`mission_s256`) are refused with `400`.

### 3. Send the person to the consent page

Show or open `https://api.example.com/aauth/interact?code=7KQM-4D2P`. If your agent provider publishes
a `callback_endpoint`, you may append `&callback=<that URL>` (https, same origin and path; a query is
allowed); the browser returns there afterwards, with `?error=access_denied` or
`?error=interaction_expired` when it did not work out. The callback carries no token: the result
always comes from polling. Without `error`, the callback means only that the browser came back (after
a person request it can come back after the identity step, before any scope consent), not that the
request was approved.

The link can reach the person through chat or mail: opening it does not use up the code, so link
previews and mail scanners that fetch it first do no harm. The first browser that submits anything
for it (signs in, starts single sign-on, presses any button or types the code) owns the request, so
show the link to the person only, never in a shared channel.

### 4. Poll

```http
GET /aauth/pending/Xq3... HTTP/1.1
Host: api.example.com
Signature-Key: sig=jwt;jwt="<agent token>"

HTTP/1.1 202 Accepted            (keep polling after Retry-After)
{"status":"interacting","code":"7KQM-4D2P"}

HTTP/1.1 200 OK
Cache-Control: no-store
{"person_token":"eyJ...","expires_in":3600}
```

`status` is `pending` until a browser first submits anything for it on the consent page (signs in,
starts single sign-on, presses any button or types the code), then `interacting`. Opening the link
does not change it.

Poll with the same key that created the request; other keys get `404`. Other answers: `403 denied`
(the person said no), `408 expired` (no answer within 10 minutes), `410 invalid_code` (finished:
delivered, cancelled, or too many wrong passwords). `DELETE` on the pending URL cancels it (`204`).

### 5. Call with the person token

```http
GET /api/v2/sales/_table/orders?limit=5 HTTP/1.1
Host: api.example.com
Signature-Key: sig=jwt;jwt="<person token>"

HTTP/1.1 401 Unauthorized
AAuth-Requirement: requirement=auth-token; resource-token="eyJ..."
Cache-Control: no-store

{"error":"auth_token_required","detail":"Ask your person server for an auth token for scope sales.read."}
```

DreamFactory picked the least privileged enabled scope that allows this request (`sales.read`). The
resource token (`typ: aa-resource+jwt`, valid 5 minutes) has `iss` = the resource, `aud` and `ps` = the
person server, `sub` and `presented_jti` from your person token, `agent_jkt` = the RFC 7638 thumbprint
of your request key, and `scope`. Verify it before you forward it: signature (resource JWKS), `iss` is the
resource you called, `agent_jkt` is your key, `ps` is your person server, `sub` and `presented_jti` match
the token you presented, `exp` is in the future.

Instead of the 401 round trip you can ask for a resource token up front:
`POST /aauth/authorize {"scope":"sales.read"}` signed with the person token answers
`200 {"resource_token":"eyJ..."}` (`400 invalid_scope` for a scope this person server may not vouch for).

### 6. Ask the person server for an auth token

```http
POST /aauth/token HTTP/1.1
Host: api.example.com
Content-Type: application/json
Content-Digest: sha-256=:<digest of the body>:
Signature-Key: sig=jwt;jwt="<agent token>"

{"resource_token":"eyJ...","presented_token":"<person token>","justification":"Weekly sales report for the ops review"}

HTTP/1.1 202 Accepted
Location: https://api.example.com/aauth/pending/Bv8...
Retry-After: 2
AAuth-Requirement: requirement=interaction; url="https://api.example.com/aauth/interact"; code="R9TW-2HXC"
{"status":"pending","code":"R9TW-2HXC"}
```

Requests to the person server are always signed with the **agent** token. If the person gave this
agent "Always allow" for these scopes, the answer is `200 {"auth_token":"eyJ...","expires_in":3600}`
at once. Otherwise the person approves on the consent page (when they just approved the identity
step in the same browser, the page moves on to this consent by itself), and you poll as in step 4
until `200 {"auth_token":"eyJ...","expires_in":...}`.

The auth token (`typ: aa-auth+jwt`) has `iss` and `ps` = the person server, `aud` = the resource,
`sub`, `cnf.jwk` = your key, and the granted `scope` (the person may grant fewer scopes than asked).
Check that `iss` is the resource token's `aud`, `aud` is the resource, `cnf.jwk` is your key and `sub`
matches.

### 7. Call with the auth token

```http
GET /api/v2/sales/_table/orders?limit=5 HTTP/1.1
Host: api.example.com
Signature-Key: sig=jwt;jwt="<auth token>"

HTTP/1.1 200 OK
AAuth-Scope: sales.read

{"resource":[...]}
```

Reuse the auth token for every request it covers until it expires; sign each request afresh.

### Step-up

When a request needs a scope the auth token does not carry (here a PATCH that needs `sales.refund`):

```http
PATCH /api/v2/sales/_table/orders/5 HTTP/1.1
Signature-Key: sig=jwt;jwt="<auth token>"

HTTP/1.1 401 Unauthorized
AAuth-Requirement: requirement=auth-token; resource-token="eyJ..."
{"error":"insufficient_scope","detail":"Scope sales.refund is needed for PATCH ..."}
```

The new resource token asks for the granted scopes plus the new one. Send it to `/aauth/token` with the
**auth token** as `presented_token`. The person sees only the new scope to approve.

## How long tokens last

| Token | Lifetime (defaults) |
|---|---|
| Agent token | set by your agent provider, at most 24 h |
| Person token, auth token | 1 h at most, and never longer than the agent token |
| Resource token | 5 minutes, single use at the person server (a retry with the same key gets the same pending request back) |
| Pending request and its code | 10 minutes |

There are no refresh tokens. When the auth token nears expiry, get a new resource token (call again
with the person token, or use `/aauth/authorize`) and go back to `/aauth/token`; with "Always allow"
that is answered at once. When the person token expires, the agent must ask for a new one (step 2), and
the person has to open the link and continue again. Plan for one person interaction per hour of
continuous work in 0.1.0.

## Errors

| Status | `error` | Means | Do |
|---|---|---|---|
| 401 | `person_token_required` | Agent token only | Get a person token (step 2) |
| 401 | `auth_token_required` | Person token; the challenge carries a resource token | Get an auth token (step 6) |
| 401 | `insufficient_scope` + `AAuth-Requirement` | Step-up | Get an auth token for the new resource token |
| 401 | `Signature-Error` header | The signature or a token did not verify; the body's `type` is `urn:ietf:params:sig-error:<code>` | See below |
| 403 | `insufficient_scope` (no `AAuth-Requirement`) | No enabled scope allows this request, or the person no longer holds the role | Ask the DreamFactory admin |
| 403 | `agent_blocked` | An admin blocked this agent, or another agent id your key has used here (a new agent id in your agent token does not change that). A request with DreamFactory's own person or auth token belongs to the agent id the token was issued for | Stop |
| 403 | `too_many_agents` | Your signing key has already presented agent tokens for 20 agent ids at this DreamFactory. Use one key per agent id | Stop, or use a new key |
| 403 | `untrusted_person_server` | The token's person server is not trusted | Use a trusted person server |
| 403 | `denied` | The person was deactivated, or (when polling) declined | Stop, or ask again |
| 400 | `invalid_request` | Malformed body; API key mixed with AAuth; method override; multipart | Fix the request |
| 400 | `invalid_resource_token`, `invalid_presented_token`, `expired_resource_token`, `expired_presented_token` | Person server checks failed | Get a fresh resource token |
| 429 | `rate_limited` | Too many pending requests (`Retry-After: 60`) | Back off |
| 503 | `temporarily_unavailable` | DreamFactory could not check whether your agent is blocked (`Retry-After: 30`); from the APIs, `/aauth/authorize` and the person server | Retry after `Retry-After` |
| 404 | `not_found` | From `/aauth/*` or `/.well-known/aauth-*`: AAuth (or the built-in person server) is off. Signed API calls then get DreamFactory's normal "no API key" `400`/`401`. | Stop |

`Signature-Error` codes: `invalid_signature` (missing headers, wrong host, bad signature, replay, stale
`created`), `invalid_input` with `required_input=(...)` (a required component is not covered),
`clock_skew` (`created` or `iat` in the future), `unsupported_scheme` (not the `jwt` scheme;
`Accept-Signature-Scheme: jwt`), `unsupported_algorithm` (`Accept-Signature-Alg: Ed25519, ES256`),
`invalid_key`, `unknown_key` (also when your agent provider's metadata or JWKS cannot be fetched),
`issuer_missing`, `issuer_mismatch`, `invalid_jwt` (also `This DreamFactory has no record of issuing
this token. Get a new one.`: drop the token and get a new one), `expired_jwt`.

## Client libraries in this package

Both clients implement the whole flow above (discovery, signing, challenges, polling, step-up, token
checks and caching) and share one identity file, so a Node and a Python agent can be the same agent.

| | |
|---|---|
| `agent/`: `@dreamfactory/aauth-agent` | Node 20+, no dependencies. Library (`Agent`), `./config` (identity files), `./provider` (agent provider documents and a request handler), and the `aauth` command line. Reference: `agent/README.md`. |
| `clients/python/`: `dreamfactory-aauth` | Python 3.9+ (`requests`, `cryptography`), module `dreamfactory_aauth`. |

The fastest path from nothing to a working agent:

```bash
# 1. create an identity: agent id, request key and agent provider key, plus the provider's two documents
aauth init --issuer https://agents.example.com --name "Acme Reports" --callback

# 2. publish the provider: serve it behind TLS at that origin, or copy the two documents to any https host
aauth serve --port 8799

# 3. call DreamFactory; the first call prints the approval link for the person
aauth request GET 'https://api.example.com/api/v2/sales/_table/orders?limit=5' --why "Weekly sales report"
aauth request PATCH https://api.example.com/api/v2/sales/_table/orders/5 -d '{"status":"refunded"}'
```

`aauth whoami --check` confirms the provider documents are published correctly. The identity file
(`~/.config/aauth/agent.json`, mode 600) holds private keys; treat it as a secret.

From code, Node:

```js
import { createAgent, loadIdentity } from '@dreamfactory/aauth-agent/config';

const agent = createAgent(loadIdentity());
const r = await agent.request('GET', 'https://api.example.com/api/v2/sales/_table/orders?limit=5', {
  why: 'Weekly sales report',
  onInteraction: ({ userUrl }) => console.log('Approve at', userUrl),
});
console.log(r.status, r.body);
```

Python:

```python
from dreamfactory_aauth import AgentIdentity

agent = AgentIdentity.load().agent()        # ~/.config/aauth/agent.json
r = agent.get("https://api.example.com/api/v2/sales/_table/orders",
              params={"limit": 5},
              on_interaction=lambda i: print("Approve at", i.user_url))
print(r.status_code, r.json())
```

In production the agent provider usually mints agent tokens and the agent never holds the provider's
key: the Node `Agent` takes `agentToken: async (ps) => '<aa-agent+jwt>'` instead of `apKey`.

### Getting the clients

Both clients ship inside this package; they are not published to npm or PyPI. On a Gold DreamFactory
server they are under `vendor/dreamfactory/df-aauth/`; copy that directory (or check out the
`dreamfactorysoftware/df-aauth` repository) to the machine the agent runs on:

```bash
npm install --global ./df-aauth/agent        # the aauth command, and import '@dreamfactory/aauth-agent'
pip install ./df-aauth/clients/python        # import dreamfactory_aauth
```

A project can also depend on the directory (`"@dreamfactory/aauth-agent": "file:./vendor/aauth-agent"`)
or a tarball made with `npm pack ./df-aauth/agent`. Both clients are licensed with df-aauth (the
DreamFactory Terms of Use). Any client that implements the two drafts works too; nothing above is
DreamFactory-specific. Full references: `agent/README.md` and `clients/python/README.md`.

## Testing your agent

- **Try it** in the admin app runs DreamFactory's own agent through the same flow and shows every
  request and response; compare yours with it.
- The admin app's **Activity** tab shows each of your agent's requests and why it was refused.
- A DreamFactory with `DF_AAUTH_ALLOW_INSECURE=true` accepts http identifiers and private addresses
  for local development. Never in production.

## Checklist

- [ ] Agent provider metadata and JWKS on https; `issuer` equals the origin; every key has `kid` and `alg`.
- [ ] Agent id `aauth:<name>@<agent provider host>`; agent token `typ` `aa-agent+jwt`, `dwk` `aauth-agent.json`, `cnf.jwk` with `alg`.
- [ ] Label `sig`; `@authority` is the issuer host; `@query` covered with a query; `content-type` and `content-digest` with a body; fresh `created` per request.
- [ ] `401` handling for `person-token`, `auth-token` (including step-up), and `Signature-Error`.
- [ ] `202` handling: show the link, honor `Retry-After`, poll `Location` with the same key, stop on `403`/`408`/`410`.
- [ ] Resource token and auth token checks before use.
- [ ] Tokens cached per (resource, person server); renewed before expiry.
