# @dreamfactory/aauth-agent

Build AI agents that call DreamFactory APIs with **AAuth**, without API keys. Every request is
signed by the agent's own key. When DreamFactory needs a person's approval, the agent prints a link
and a code, the person approves in the browser, and the agent gets a token scoped to the
DreamFactory role it was granted.

This package is a library, an `aauth` command line tool and an Agent Provider, for Node 20 or
later, with no dependencies. It implements draft-hardt-oauth-aauth-protocol-11 and
draft-hardt-httpbis-signature-key-09. A Python client lives in [`../clients/python`](../clients/python).

## Quickstart

```bash
npm install --global ./agent        # in df-aauth: a checkout, or vendor/dreamfactory/df-aauth on a DF server
aauth init --issuer https://agents.example.com --name "Acme Reports"
#   publish the two files it prints at https://agents.example.com (any static https host),
#   or run `aauth serve` behind TLS, then check what DreamFactory will see:
aauth whoami --check
aauth request GET 'https://df.example.com/api/v2/sales/_table/orders?limit=5'
#   -> "approval needed": open the link, sign in, Allow. The JSON prints on stdout.
aauth request GET 'https://df.example.com/api/v2/sales/_table/orders?limit=5'   # cached: no prompt
```

DreamFactory side: AAuth turned on (API Security > AAuth), `DF_AAUTH_ISSUER` set to the instance's
https origin, and at least one role enabled as a scope (for example `sales.read`).

## How agent identity works

An agent is identified by an **agent id**, `aauth:<name>@<host>` (here
`aauth:acme-reports@agents.example.com`), vouched for by an **Agent Provider**: the https origin
`<host>`, which publishes two documents.

```
https://agents.example.com/.well-known/aauth-agent.json   {"issuer", "jwks_uri", "name", "callback_endpoint"?}
https://agents.example.com/jwks.json                      {"keys": [<public key that signs agent tokens>]}
```

The agent holds two Ed25519 keys:

| Key | Signs | Who sees the public half |
|---|---|---|
| `ap` (provider key) | **agent tokens** (`aa-agent+jwt`): `iss` = the provider, `sub` = the agent id, `cnf.jwk` = the request key, `exp` ≤ 1 h | everyone, in `jwks.json` |
| `agent` (request key) | **every HTTP request** (RFC 9421 `Signature`, `Signature-Input`, `Signature-Key: sig=jwt;jwt="<token>"`) | DreamFactory, inside each token's `cnf.jwk` |

The first time DreamFactory sees the agent token it fetches `aauth-agent.json` (whose `issuer` must
equal the token's `iss`, byte for byte), then the JWKS, and checks the token's signature. Every
request must then carry a valid signature by `cnf.jwk` over the method, authority, path, query and
(when there is a body) `Content-Digest`. A stolen token is useless without the request key.
DreamFactory lists the agent under API Security > AAuth > Agents with the provider's `name`, where an
admin can block it.

The tokens DreamFactory's Person Server issues next are bound to the same request key:

| Step | The agent sends | DreamFactory answers |
|---|---|---|
| 1 | the request, signed with the agent token | `401 AAuth-Requirement: requirement=person-token` |
| 2 | `POST /aauth/person` | `202` + link and code; the person signs in; polling returns a **person token** |
| 3 | the request, signed with the person token | `401 requirement=auth-token; resource-token="..."` (the scope that covers the request) |
| 4 | `POST /aauth/token` | `202` + link; the person clicks Allow (or an "Always allow" grant answers `200` at once); polling returns an **auth token** |
| 5 | the request, signed with the auth token | the API response, run under the role mapped to that scope |

A later request that needs more (say a `PATCH` needing `sales.refund`) gets a new `auth-token`
challenge, and the agent asks again (step-up). With `--scope` the agent asks DreamFactory's
`authorization_endpoint` for the scope up front and skips the challenge round trip.

**Production layout.** For one developer the identity file holds both keys. For a fleet, keep the
provider key in one service (your Agent Provider) and give each agent instance only its own request
key: the instance sends its public key to your provider (authenticated however you already
authenticate workloads), the provider answers with `mintAgentToken()`, and the instance runs
`new Agent({ agentToken: (ps) => ... })`. Rotate the provider key by publishing the new key first and
keeping the old one in the JWKS (`previousKeys`) until tokens signed with it have expired.

## CLI

```
aauth request <METHOD> <URL> [options]   call an API; the person approves when needed
aauth whoami [--check]                   this agent's identity (--check: is it published?)
aauth logout [<URL>]                     forget cached tokens for one API, or all of them
aauth reset                              forget every cached token of this agent
aauth init --issuer <url> --name <name>  create an agent identity and its provider files
aauth serve [--port <n>] [--host <h>]    serve the provider files (put TLS in front)
aauth agent-token [--ps <url>]           print a fresh agent token
aauth decode <jwt>                       print a token's header and claims
```

Request options: `-d/--data <json|@file|@->`, `-s/--scope "<scopes>"`, `-H/--header "Name: value"`,
`-w/--why <text>` (shown on the approval screen), `-i/--include`, `-v/--verbose` (every request,
challenge and token), `-q/--quiet`, `--json`, `--open` (open the approval page in the browser),
`--fresh`, `--ps <url>`, `--timeout <s>`. `aauth GET <url>` is short for `aauth request GET <url>`.
Progress goes to stderr and the response body to stdout, so `aauth request ... | jq` works.
Exit status: `0` 2xx, `1` error response or failure, `2` usage, `3` not approved (denied, expired,
timed out), `130` interrupted (Ctrl-C withdraws the pending request first).

```
$ aauth request GET 'https://df.example.com/api/v2/sales/_table/orders?limit=2' --why "Weekly sales report"
GET df.example.com/api/v2/sales/_table/orders?limit=2
  as aauth:acme-reports@agents.example.com
  401  person token required
  ! approval needed: sign in to identify the person
      open  https://df.example.com/aauth/interact?code=J2KS-SQP2
      code  J2KS-SQP2
  ✓ person token
  401  consent required for sales.read
  ! approval needed: allow sales.read
      open  https://df.example.com/aauth/interact?code=7BNF-WDVS
      code  7BNF-WDVS
  ✓ auth token  sales.read  expires in 60 min
  ✓ 200 OK  scope sales.read  ·  2 records  ·  8.9 s
{ "resource": [ ... ] }
```

## Configuration

`aauth init` writes the identity to `~/.config/aauth/agent.json` (mode 600) and the two public files
to `~/.config/aauth/public/`. The file holds `issuer`, `agent_id`, `name`, optional
`callback_endpoint`, and the private JWKs `ap` and `agent`; the Python client reads the same file.
Cached person/auth tokens go to `tokens.json` beside it. `--config <file>` (or `AAUTH_CONFIG`) picks
another identity, so one machine can run several agents.

| Variable | Meaning |
|---|---|
| `AAUTH_CONFIG` | identity file to use |
| `AAUTH_HOME` | directory for `agent.json` and `tokens.json` (default `$XDG_CONFIG_HOME/aauth` or `~/.config/aauth`) |
| `AAUTH_TOKENS` | token cache file |
| `AAUTH_AGENT_ID`, `AAUTH_AGENT_ISSUER`, `AAUTH_AGENT_NAME` | override the identity's agent id, provider, name |
| `AAUTH_PS` | Person Server (default: the API's own, when it publishes `aauth-person.json`) |
| `AAUTH_KEYS` | a bare keys file `{ap, agent}` (the reference deployment's format; issuer from `AAUTH_AGENT_ISSUER`) |
| `NO_COLOR`, `FORCE_COLOR` | plain or forced colour output |
| `AAUTH_DEBUG` | print stack traces |

Lookup order: `--config`/`AAUTH_CONFIG`, `AAUTH_KEYS`, `$AAUTH_HOME/agent.json`. An installed copy
looks nowhere else and has no default provider: without an identity it asks you to run `aauth init`.
(A development checkout of df-aauth also falls back to the reference deployment described by
`agent/reference.json`, which is never shipped.)

## Library

```js
import { loadIdentity, createAgent } from '@dreamfactory/aauth-agent/config';

const agent = createAgent(loadIdentity()); // ~/.config/aauth/agent.json, tokens cached in tokens.json
const r = await agent.request('GET', 'https://df.example.com/api/v2/sales/_table/orders?limit=5', {
  why: 'Weekly sales report',
  onInteraction: ({ purpose, userUrl, code }) => notifyPerson(`Please approve: ${userUrl} (code ${code})`),
});
if (r.failed || r.cancelled) throw new Error(`not approved: ${r.error}`);
console.log(r.status, r.body); // r.headers['aauth-scope'] names the scope DreamFactory used
```

`agent.request(method, url, options)` resolves to `{ status, headers, body, text, steps,
interactions }`, plus `failed`, `cancelled`, `error`, `detail` when the flow did not finish. API
errors (403, 404, ...) come back as ordinary statuses. Options:

| Option | |
|---|---|
| `body` | object (sent as JSON) or string; signed with `Content-Digest` |
| `headers` | extra request headers |
| `scope` | scopes to ask for up front (`"sales.read sales.refund"`) |
| `why` | justification shown to the person |
| `onInteraction(i)` | called with `{ purpose: 'person'\|'auth', userUrl, url, code, location }` before polling; return `'cancel'` to withdraw |
| `onStep(step)` | every discovery, request and poll, for logging (`{ kind, title, status, request, response }`) |
| `signal` | an `AbortSignal`; aborting while waiting withdraws the pending request |
| `fresh`, `ps`, `pollTimeoutMs` | ignore the cache, pick the Person Server, how long to wait (default 10 min) |

Without an identity file:

```js
import { Agent } from '@dreamfactory/aauth-agent';
const agent = new Agent({ issuer: 'https://agents.example.com', sub: 'aauth:reports@agents.example.com', apKey, agentKey });
// or, when your Agent Provider mints the tokens:  new Agent({ issuer, sub, agentKey, agentToken: async (ps) => token })
```

Serve the provider documents from your own Node server, and mint tokens for agent instances:

```js
import { createProviderHandler, mintAgentToken } from '@dreamfactory/aauth-agent/provider';
const provider = createProviderHandler({ issuer: 'https://agents.example.com', name: 'Acme Reports', apKey, previousKeys: [] });
http.createServer((req, res) => provider(req, res) || app(req, res)); // serves /.well-known/aauth-agent.json, /jwks.json, /callback
const token = mintAgentToken({ issuer, apKey, sub: 'aauth:reports@agents.example.com', agentJwk: instancePublicKey, ps: 'https://df.example.com' });
```

The `/callback` page (also served by `aauth serve`) says **Done** and "Return to your terminal.", or
**Not approved** with the `error` the person server added. It never claims the request was approved:
the browser can come back after the identity step alone, and the agent learns the result by polling.

| Import | |
|---|---|
| `@dreamfactory/aauth-agent` | `Agent`, keys (`generateJwk`, `publicJwk`, `jwkThumbprint`), JWTs (`signJwt`, `decodeJwt`, `claims`), `signRequest`/`signedFetch`/`verifySignedRequest`, `Discovery`, structured-field parsers, `memoryCache`/`fileCache`, `scopesOf` |
| `@dreamfactory/aauth-agent/config` | `initIdentity`, `loadIdentity`, `createAgent` |
| `@dreamfactory/aauth-agent/provider` | `providerDocuments`, `createProviderHandler`, `startProvider`, `mintAgentToken`, `checkProvider` |
| `@dreamfactory/aauth-agent/person` | drives the consent pages over HTTP with a password, for automated tests on test instances (`node person.mjs approve <url> <code> --email <e>`) |

## Files

| File | What |
|---|---|
| `aauth.mjs` | the library: keys, JWTs, RFC 9421 signatures (`@query` covered when present or declared), discovery, the full flow (`Agent`). Derived from the AAuth reference demo (MIT, attribution in the file header) |
| `config.mjs`, `provider.mjs` | identity files; the Agent Provider documents, handler and token minting |
| `cli.mjs` | the `aauth` command |
| `server.mjs` | a minimal Agent Provider (`AAUTH_AGENT_ISSUER`, `AAUTH_KEYS`, `PORT`, `HOST`); it runs the reference deployment's "Acme Reports" |
| `person.mjs` | the person's side of the consent pages (cookie jar, CSRF, the contract below) |
| `e2e.mjs` | 14 end-to-end scenarios against a live DreamFactory (plays the person over HTTP); repository only |
| `*.test.mjs`, `mock-df.mjs` | offline unit tests (mock resource + Person Server), CLI tests, interop with the reference demo; repository only |

## Tests

```bash
cd agent
node --test                                        # offline units, CLI, config/provider tests
DF_URL=https://api.example.com AAUTH_AGENT_ISSUER=https://agents.example.com AAUTH_KEYS=keys.json \
  DF_ADMIN_EMAIL=admin@example.com DF_USER_EMAIL=jordan@example.com node e2e.mjs [--only 1,8] [-v]
cd ../clients/python && python3 -m unittest discover -s tests   # the Python client
```

The tests, `e2e.mjs` and `mock-df.mjs` are in the df-aauth repository (development checkouts), not in
the installed package. e2e needs a **test** DreamFactory with AAuth on, the demo seed
(`bin/demo-seed.sh`: a `sales` service, scopes `sales.read`/`sales.refund`, the user Jordan Lee) and
an Agent Provider running `server.mjs` with the keys file `AAUTH_KEYS` (the suite signs as that
provider; `DF_ALT_URL`, the same DreamFactory under another authority, enables the wrong-authority
check), and credentials in `DF_ADMIN_PASSWORD` / `DF_USER_PASSWORD` (or two lines on stdin with
`--creds-stdin`); it never prints them. It enables AAuth if it was off (and turns it off again at the end), deletes
leftover grants for `aauth:e2e-*` agents, deletes the `aauth:e2e-*` agent rows it created, and restores
what it changes (the order status it PATCHes, blocked agents, the enabled flag). Scenarios: 1 full
flow · 2 token reuse · 3 step-up (+ single-use resource token) · 4 Jordan can't grant `sales.refund` ·
5 deny · 6 always-allow + revoke · 7 blocked agent · 8 tampering (digest, replay, stale/future
`created`, query changed, `@query` not covered, wrong authority, wrong key) · 9 untrusted PS · 10
unsigned request headers · 11 disabled pass-through · 12 admin regression · 13 forged auth tokens · 14
blocked agent at the Person Server. Maintainers: the reference deployment and its exact commands are in
`agent/DEVELOPMENT.md` in the repository.

## Consent page contract

`e2e.mjs` plays the person with a cookie jar and an HTML scanner. It does NOT depend on wording, CSS
classes, element order or layout. It depends only on the following. Anything not listed here may change freely.

### Card state

Exactly one element per page carries `data-aauth-state`, with one of these values:

| value      | when |
|------------|------|
| `code`     | no / unknown / expired code; shows the code entry form |
| `signin`   | the pending request is valid, nobody is signed in (or after "Not you?") |
| `identity` | signed in, pending kind `person` |
| `consent`  | signed in, pending kind `auth` |
| `next`     | after identity approval, while the page waits for the agent's follow-up auth request |
| `done`     | final page |

On `done` the same element also carries `data-aauth-result="approved"` or `data-aauth-result="denied"`.

An error for the current form (bad code, wrong password, rate limited, nothing grantable) is rendered in an element
with the attribute `data-aauth-error` (text content = the message). Its absence means no error.

### Forms

- All forms are `method="post"` and carry the CSRF field `<input type="hidden" name="_token" value="...">`.
  The e2e takes `action` from the form; a missing/empty `action` means "post to the current URL". Relative actions are fine
  (resolved against the page URL, which is on the issuer origin).
- The e2e submits *all* `<input type="hidden">` fields of the form it uses, verbatim, plus the fields below.
  So any extra hidden fields (pending id, code, nonce) round-trip automatically.
- `code` state: a text input `name="code"`. Submitted value `XXXX-XXXX` (the server normalizes case/hyphen).
- `signin` state: inputs `name="email"` and `name="password"`. Signing in is not consent: a person request then
  shows `identity`, an auth request `consent`. A separate form offers `name="decision" value="deny"` without signing in.
- A code is single-use: the first browser (session) that POSTs for the request (sign-in, single sign-on, any
  `decision`, or the code form) owns it and its outcome; other browsers then get `code` with an error, on GET and
  POST, also once the request is decided. Opening the link (GET) never claims it and never changes the request
  (link previews and mail scanners fetch links first).
  Five wrong passwords on one request end it (polls answer `410 invalid_code`).
- `identity` state: submit buttons `name="decision"` with `value="allow"` (Continue) and `value="deny"`;
  "Not you?" is `name="decision" value="switch"` (signs out, returns to `signin`).
- `consent` state: submit buttons `name="decision"` with `value="allow"` / `value="deny"` (and `value="switch"`, "Not you?",
  under the signed-in account); checkbox `name="always" value="1"` (only when something is grantable).
  Each requested scope is an element with `data-aauth-scope="<scope>"` and `data-aauth-grantable="1"` or `"0"`
  (0 = the person lacks that role). The form posts per-scope checkboxes `name="scopes[]" value="<scope>"` (grantable ones
  checked, the rest disabled) plus a hidden `scopes_shown`; the e2e submits every grantable one that is present. When nothing is grantable the Allow button carries `disabled`.
- The e2e reaches every pending request by GET `{issuer}/aauth/interact?code=XXXX-XXXX` (the code from the 202 response),
  including the follow-up auth request after an identity approval. It never runs the page's JS and never needs the `next` poll.
- A successful POST may answer 200 with the next state or 302/303 to a GET that renders it; both are followed.

### Pending responses the CLI/e2e rely on (agent side)

`POST /aauth/person` / `POST /aauth/token` answering `202` with JSON body containing `code` (`XXXX-XXXX`) and `status`,
plus header `Location` (absolute or relative pending URL) and `AAuth-Requirement: requirement=interaction; url="...";
code="XXXX-XXXX"` (spec form). The agent reads the code from the header first, then the body. It polls `Location`
with signed GETs, honouring `Retry-After`.
