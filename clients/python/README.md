# dreamfactory-aauth (Python)

Call DreamFactory APIs from Python agents with **AAuth**: no API keys, every request signed by the
agent's own key, a person's approval when DreamFactory asks for it, and tokens scoped to the
DreamFactory role that was granted. Depends only on `requests` and `cryptography`; Python 3.9+.

It implements the agent side of draft-hardt-oauth-aauth-protocol-11 and
draft-hardt-httpbis-signature-key-09: agent token minting from a provider key, RFC 9421 signatures
with `Signature-Key: sig=jwt`, `Content-Digest`, the `401 AAuth-Requirement` loop (person token,
resource token, auth token, step-up), `202` polling, and up-front scopes through DreamFactory's
`authorization_endpoint`. It checks every token DreamFactory hands back before using it.

## Quickstart

```bash
pip install ./clients/python            # in df-aauth: a checkout, or vendor/dreamfactory/df-aauth on a DF server
python3 clients/python/examples/create_identity.py --issuer https://agents.example.com --name "Acme Reports"
#   publish the two printed files at https://agents.example.com (any static https host)
```

```python
from dreamfactory_aauth import AgentIdentity

agent = AgentIdentity.load().agent()        # ~/.config/aauth/agent.json; tokens cached beside it
r = agent.get("https://df.example.com/api/v2/sales/_table/orders", params={"limit": 5},
              justification="Weekly sales report",
              on_interaction=lambda i: print(f"Approve at {i.user_url} (code {i.code})"))
print(r.status_code, r.json())             # a second run reuses the cached auth token
```

The identity file is the same one the Node CLI writes (`aauth init`), so `aauth whoami --check`
can confirm the provider files are published correctly.

## How it works

The agent id (`aauth:acme-reports@agents.example.com`) is vouched for by your **Agent Provider**,
the https origin that serves `/.well-known/aauth-agent.json` and `/jwks.json`
(`AgentIdentity.provider_documents()` returns both). The provider key signs short-lived agent
tokens binding the agent id to the request key (`cnf.jwk`); the request key signs every request.
DreamFactory discovers the provider from the token's `iss`, verifies the token against the JWKS,
then verifies each request's signature against `cnf.jwk`.

| The agent sends | DreamFactory answers | The client does |
|---|---|---|
| request + agent token | `401 requirement=person-token` | `POST person_token_endpoint` |
| | `202` + code | calls `on_interaction`, polls `Location` (honours `Retry-After`, `429` backs off) |
| request + person token | `401 requirement=auth-token; resource-token=...` | checks the resource token (iss, agent_jkt, aud, sub, presented_jti), `POST auth_token_endpoint` |
| | `202` + code, or `200` (standing grant) | polls, then checks the auth token (iss, aud, cnf, sub) |
| request + auth token | the API response | returns it; a later `401 auth-token` is a step-up and repeats the last two rows |

## API

`Agent(issuer, agent_id=, provider_key= | agent_token=, agent_key=None, token_cache=None, callback=None, insecure=False, session=None, timeout=30)`

- `provider_key`: the private JWK that signs agent tokens. Or `agent_token=lambda ps: ...`, a callable
  returning a token your Agent Provider minted for `agent_key` (the production layout: the provider
  key stays in one service, agent instances hold only their request key).
- `agent_key`: the request key; generated when omitted. `token_cache`: `MemoryTokenCache()` (default)
  or `FileTokenCache(path)` (same format as the Node CLI's `tokens.json`).

`agent.request(method, url, *, params=, json=, data=, headers=, scope=, justification=, on_interaction=, on_step=, fresh=False, poll_timeout=600)`
returns the API's `requests.Response`; `response.aauth` holds the `Flow` (`steps`, `interactions`).
Also `agent.get/post/put/patch/delete`. `scope="sales.refund"` asks for the scope up front.
`on_interaction(Interaction)` gets `purpose` (`"person"` or `"auth"`), `user_url`, `url`, `code`,
`scope`; return `"cancel"` to withdraw the request (Ctrl-C while waiting withdraws it too).

Errors: API errors (403, 404, ...) are returned as responses. Flow failures raise `NotApproved`
(`denied`, `expired`, `timeout`, ...), `Cancelled`, `InvalidToken` (a token failed the client's
checks) or `AAuthError` (`.error`, `.detail`, `.status`, `.response`).

Lower level: `sign_request()` / `verify_request()`, `mint_agent_token()`, `Discovery`, `generate_jwk()`,
`jwk_thumbprint()`, `sign_jwt()` / `decode_jwt()` / `claims()`.

| Variable | Meaning |
|---|---|
| `AAUTH_CONFIG` | identity file (default `$AAUTH_HOME/agent.json`, `~/.config/aauth/agent.json`) |
| `AAUTH_TOKENS` | token cache file (default `tokens.json` next to the identity) |
| `AAUTH_AGENT_ISSUER`, `AAUTH_AGENT_ID` | override the identity's provider and agent id |

## Examples

```bash
python3 examples/aauth_request.py GET 'https://df.example.com/api/v2/sales/_table/orders?limit=5'
python3 examples/aauth_request.py PATCH https://df.example.com/api/v2/sales/_table/orders/7 \
    --data '{"status": "refunded"}' --scope sales.refund --why "Customer asked for a refund"
python3 examples/create_identity.py --issuer https://agents.example.com --name "Acme Reports"
```

## Tests

```bash
cd clients/python
python3 -m unittest discover -s tests        # offline (pytest works too)
```

Offline: RFC 8037 thumbprint, RFC 9530 digest and RFC 9421 B.2.6 Ed25519 vectors; JWT and
structured-field parsing; signing round trips and tampering; requests signed by the AAuth reference
demo's own code (`../../tests/fixtures`); the whole flow against an in-process mock DreamFactory
(person + consent, reuse, step-up, deny, standing grant, cancel, timeout, up-front scope, a resource
token for another key); and, when `node` is installed, cross-verification with the Node library in
both directions plus reading an identity written by `aauth init`.

Live, against a DreamFactory with the demo seed (`bin/demo-seed.sh`), an Agent Provider whose key you
hold, and `node` (the person is played by `agent/person.mjs approve`):

```bash
cat provider-keys.json | python3 tests/live_dreamfactory.py --df https://df.example.com --keys - \
    --issuer https://agents.example.com --person-email admin@example.com \
    --person-password-file ~/pw --admin-password-file ~/pw
```

Six scenarios: full flow, token reuse, up-front `sales.refund` via the authorization endpoint (and
restoring the order), deny, "Always allow" standing grant, a tampered body rejected by DreamFactory.
It deletes the agents (`aauth:e2e-py-*`), their activity and grants at the end.
