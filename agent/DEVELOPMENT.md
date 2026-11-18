# Developing @dreamfactory/aauth-agent

Maintainer notes for the df-aauth repository. This file, the tests, `mock-df.mjs` and `e2e.mjs` are
not shipped (`.gitattributes` export-ignore; not in `package.json` `files`).

## Local reference deployment (optional)

A development checkout can describe a reference deployment of its own in `agent/reference.json`
(git-ignored, never shipped):

```json
{
  "issuer": "https://agent.example.com",
  "name": "Acme Reports",
  "container": "my-agent-container",
  "admin_password_file": "/path/to/admin-password",
  "user_password_file": "/path/to/aauth-user-password"
}
```

When it is present, `aauth.mjs` exports its issuer and container as `DEFAULT_ISSUER` /
`DEFAULT_CONTAINER`, the CLI falls back to the container's keys when no identity is configured (so
`node agent/cli.mjs GET <url>` works on that host), and `person.mjs` reads the test passwords from
the files it names. Without it (every installed copy) there is no default issuer and nothing is read
from a container.

## Tests

```bash
cd agent
node --test                         # offline units, CLI, config/provider, interop (+ live parts when DF_URL is up)
DF_URL=https://df.example.com DF_ALT_URL=http://192.0.2.10:8080 node e2e.mjs [--only 1,8] [-v]
AAUTH_WRITE_FIXTURE=1 node --test interop.test.mjs   # regenerate ../tests/fixtures/demo-*.json
cd ../clients/python && python3 -m unittest discover -s tests   # the Python client
```

`interop.test.mjs` imports the AAuth reference demo's library (`shared/aauth.mjs` from a checkout of
https://github.com/wjgilmore/aauth-demo, path in `$AAUTH_DEMO_LIB`) and is skipped without it. Its
live parts run only when `DF_URL` is set and that instance answers with AAuth on.

e2e needs AAuth installed on DreamFactory, the demo seed (`bin/demo-seed.sh`: `sales` service,
scopes `sales.read`/`sales.refund`, Jordan Lee) and credentials: `DF_ADMIN_EMAIL` /
`DF_USER_EMAIL` (defaults match the demo seed), `DF_ADMIN_PASSWORD` / `DF_USER_PASSWORD`, else two
lines on stdin with `--creds-stdin`, else the files named in `reference.json`. It never prints them.
Inside an agent container:

```bash
{ cat admin-password; echo; cat aauth-user-password; echo; } \
  | docker exec -i <agent-container> node /agent/e2e.mjs --creds-stdin
```

It enables AAuth if it was off (and turns it off again at the end), deletes leftover grants for
`aauth:e2e-*` agents, deletes the `aauth:e2e-*` agent rows it created, and restores what it changes
(the order status it PATCHes, blocked agents, the enabled flag). Scenarios: 1 full flow · 2 token
reuse · 3 step-up (+ single-use resource token) · 4 Jordan can't grant `sales.refund` · 5 deny · 6
always-allow + revoke · 7 blocked agent · 8 signature checks (digest, replay, stale/future `created`,
query changed, `@query` not covered, wrong authority, wrong key) · 9 untrusted PS · 10 unsigned request
headers · 11 disabled pass-through · 12 admin regression · 13 auth tokens from untrusted signers ·
14 blocked agent at the Person Server.

## Running the agent provider

`node agent/server.mjs` serves an Agent Provider (keys in `agent/.keys.json`, git-ignored; env
`AAUTH_KEYS`, `AAUTH_AGENT_ISSUER`, `PORT`, `HOST`). Put it behind an https origin that DreamFactory
can reach, and set `AAUTH_AGENT_ISSUER` to that origin. Keys: `ap` signs agent tokens (published in
`/jwks.json`); `agent` is the CLI's request key (`cnf.jwk`); `test_ps` is only for e2e scenarios 9
and 13.

Scenario 9 mints a person token whose issuer is this provider's origin: `server.mjs` also serves a
throwaway Person Server identity there (`/.well-known/aauth-person.json`, key `test_ps`, no
endpoints that work). DreamFactory must discover it and refuse it as untrusted.
