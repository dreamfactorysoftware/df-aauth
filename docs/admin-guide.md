# Admin guide

AAuth lets an AI agent call this DreamFactory's APIs with signed requests and no API key. A person
approves the agent at a person server, and what they approve is a **scope**. A scope is a
DreamFactory **role**: the agent gets exactly that role's access, with the role's filters, lookups,
scripts and limits, and Data Masking treats the call as an AI session.

Everything on this page is in the admin app under **API Security > AAuth**, and in the system API
under `/api/v2/system/aauth` (sys admins only, on every verb). Installation is in
[install.md](install.md).

## The page

The top row has the **Enabled** switch and the issuer, the https origin agents use, with a
copy button and a link to the resource metadata. When the issuer is not configured the switch is
disabled and the row reads `Set DF_AAUTH_ISSUER to an https URL`.

Switching AAuth off stops all agent access at once: every AAuth endpoint answers 404 and signed
requests fail DreamFactory's normal authentication. Scopes, person servers, agents, grants and
activity are kept for when it is switched on again.

Below the switch are six tabs: **Scopes**, **Person Servers**, **Agents**, **Activity**, **Grants**
and **Try it**.

## Scopes

Every role is listed, with its scope name, a description and an **Enabled** switch. Enabled scopes
come first. An agent can only ever get the access of an enabled scope.

- **Scope** is the name agents and person servers see, for example `sales.read`. It defaults to the
  role name in lowercase. Use 1 to 64 characters: lowercase letters, digits and `. _ : -`, starting with
  a letter or digit. Each scope name belongs to one role. `profile` and `email` are reserved for
  identity claims.
- **Description** is shown to the person on the consent page and published in the resource
  metadata (`scope_descriptions`). Without one, the role name is used. Write it for the person who
  approves: "Read customers and orders".
- Click a name or description to edit it; Enter or leaving the field saves.

How DreamFactory picks the scope for a request: among the enabled scopes whose role allows the
request (service, path and verb, checked exactly as for an API key with that role), it asks for the
least privileged one, meaning the role with the fewest service access rows, then the fewest verbs,
then the lowest role id. When no enabled scope allows the request, the agent gets
`403 insufficient_scope` and no one is asked.

Guidelines:

- Create roles for agents rather than reusing broad ones: one read role and one narrow write role per
  use case ("Sales read", "Sales refunds") give people a clear choice.
- Agents never get sys-admin rights. The session holds exactly the scope's role, even when the
  person who approved is a sys admin.
- Turning a scope off takes effect at once: auth tokens that carry it stop covering requests.
- **Renaming** a scope keeps it attached to its role: person server allow-lists and standing grants
  move to the new name. The old name stays reserved for that role for 61 minutes (the longest auth
  token lifetime plus a minute).
- **Deleting a role** deletes its scope. Once the role is gone, the name is removed from standing
  grants (a grant left with no scope is deleted) and from every person server's scope list, and
  stays reserved for 61 minutes for no role at all (not even a new role that gets the deleted role's
  id), and so do the names the role renamed away in the last 61 minutes. A rename that another admin
  saves while the delete runs is given up with the role too. A delete that DreamFactory refuses
  changes nothing the role can notice, for example `500 Failed to delete resource: SQLSTATE[23000]:
  Integrity constraint violation ...` because a login service (LDAP, Active Directory, OAuth, OpenID
  Connect, SAML, Azure AD) still has the role as its default role: the role keeps its scope name
  (saving it again is accepted), the names it renamed away (it may take them back), its grants and
  its person server trust.
- A role that takes a scope name, as a new scope or by a rename, starts with no grants and no person
  server trust for it, except from person servers set to **All scopes**.
- A rename and its cleanup happen together or not at all: when DreamFactory cannot update the grants
  (a database error), the rename fails. A role delete is refused with `500 Failed to delete resource:
  AAuth could not release this role's scope name, so the role was not deleted. Try again.` when the
  name cannot be reserved before the delete, or when the cleanup fails while the delete runs in a
  transaction (`rollback=true`), which is then rolled back. When the cleanup fails after a delete
  outside a transaction (or another part of DreamFactory fails before it runs), the role stays
  deleted, the failure is logged and the cleanup is tried once more when the request ends. If that
  fails too, the name still stays reserved for no role for the hour (names the role renamed away
  earlier stay reserved for its id until their hour is up), and the grants and scope lists that
  still show it pass nothing to the next role that takes it.
- An auth token never covers a request through a scope whose role took that name after the token
  was issued, so a token issued for an earlier holder of a name (however late an external person
  server minted it) never reaches the role that holds it now.
- An inactive role cannot be used; requests that need it get `403 insufficient_scope`.

### Who can approve a scope

On this DreamFactory's own person server, a person can approve a scope only when they **hold its
role**, in any app (**Users > Roles**), or when they are a sys admin. Other scopes are shown on the
consent page but cannot be selected. A person cannot hand an agent more than they have.

This is checked again on every request: when the person is deactivated, deleted, or loses the role,
the agent's auth token stops working on its next request (`403`).

## Person Servers

A person server is where people approve agents. Tokens are accepted only from the person servers in
this list that are enabled.

- **This DreamFactory** is the built-in person server: people sign in with their DreamFactory
  credentials. It is always listed first and can vouch for every enabled scope. Switch it off to stop
  accepting its tokens. Its pages and token endpoints stay up; to turn the built-in person server
  off entirely, see `ps_local_enabled` in [configuration.md](configuration.md#settings-stored-in-the-database).
- **Add** an external person server by its issuer (`https://ps.example.com`). DreamFactory fetches
  its `/.well-known/aauth-person.json` and refuses the issuer with the reason if that fails. A new
  person server can vouch for **no scopes** until you choose some in its **Scopes** column, or pick
  **All scopes** (every enabled scope, including ones enabled later).
- An external person server decides who may approve what; DreamFactory then enforces the scope's role.
  Agents approved there act without a DreamFactory user (only the role applies).
- **Remove** an external person server to stop accepting its tokens at once. **Last used** shows when
  it last vouched for a request.

## Agents

An agent appears the first time it sends a signed request to this DreamFactory: to an API, to the
authorization endpoint, or to this DreamFactory's person server.

| Column | |
|---|---|
| Name | The name in its agent provider's metadata. Self-asserted: anyone can publish any name. |
| Agent | Its agent id, `aauth:<name>@<agent provider host>`. This is what identifies it. |
| Provider | The host of its agent provider. |
| Last seen, Requests | When it last called, and how many signed API requests it has made (person server calls are not counted). |
| Blocked | Blocks or allows it. |

A blocked agent gets `403 agent_blocked` on every request, whatever token it presents: at the APIs,
at the authorization endpoint, and at this DreamFactory's person server, which issues it no tokens.

Which agent a request belongs to (its Activity row, its **Requests** count and the block that applies):

- With an agent token: the agent id in it.
- With a person or auth token from this DreamFactory's person server: the agent the token was issued
  for, the one the person approved or whose "Always allow" answered, even when its key has since
  presented an agent token for another agent id. DreamFactory records every token it issues for
  this. A token it has no record of (one issued before this version, for example) gets `401
  invalid_jwt` `This DreamFactory has no record of issuing this token. Get a new one.`, and the agent
  starts over.
- With a token from an external person server, which does not name the agent: the agent id the
  signing key most recently presented an agent token for. A key DreamFactory has never seen with an
  agent token is listed as `jkt:` and the start of its key thumbprint; block that row like any other.

DreamFactory also remembers every agent id a key has presented an agent token for, and refuses the
key while any of them is blocked (Activity **Blocked**, under the blocked agent). An agent token for
that key that names a new agent id, before or after the block, frees neither the key nor the person
and auth tokens issued to it. A key may present agent tokens for at most 20 agent ids; an agent token
naming one more gets `403 too_many_agents` (Activity **Error**, no agent), so a key cannot spawn
throwaway agent ids without end. In the admin API, every agent record lists the other agents that
share a signing key with it (`shares_key_with`, see [Admin API](#admin-api)).

An agent that comes back with a new key under a new agent id is a new agent: it has no grants, and a
person must approve it again. A new key under an agent id it used before is refused while that id is
blocked, so in an incident block every agent id involved, including those in `shares_key_with`.
`shares_key_with` goes one hop: it names the agents that share a key with this agent, not the agents
that share another key with those. Open each agent it names (`GET /agents/{id}`) and repeat until no
new agent id appears.

`DELETE /api/v2/system/aauth/agents/{id}` forgets an agent (its activity stays unless
`purge_activity=true`). It reappears on its next request.

## Activity

One row per signed request to the `/api/v2` APIs, and per refused request to the resource
authorization endpoint `/aauth/authorize` (blocked, no record of the token, or agent state
unavailable), newest first: **Time**, **Agent** (the agent the request belongs to, see
[Agents](#agents)), **Person** (the DreamFactory user's email when known, else `<sub>@<person server
host>`), **Scope**, **Request** (method and path, without the query) and **Result**. **Reason**
explains a refusal.

| Result | Means |
|---|---|
| Allowed | The request ran under the scope's role. The status is DreamFactory's response status. |
| Person token required | The agent presented only its agent token and was asked for a person token. |
| Auth token required | The agent was asked to get an auth token for a scope (also a step-up to a further scope). |
| Denied | Refused after verification: no scope allows it, untrusted person server, the person is inactive or lost the role, or the role is unavailable. |
| Blocked | The agent is blocked. |
| Error | The signature or a token did not verify, or this DreamFactory has no record of issuing the token (`invalid_jwt: This DreamFactory has no record of issuing this token. Get a new one.`). **Reason** carries the protocol error, for example `invalid_signature: This signature was already used.` Also when DreamFactory could not read or record the agent's state, or read the token's record, in the system database (the row is written when the database takes it): status `503`, **Reason** `temporarily_unavailable: agent state unavailable`. |

The **Result** filter groups them as Allowed, Token required (the two challenges) and Rejected
(denied, blocked, error). Rows are kept for 30 days by default
(`DF_AAUTH_ACTIVITY_RETENTION_DAYS`). Other authorization endpoint requests (those that get a resource
token, and those refused for any other reason), and requests to the person server endpoints and
consent pages, are not listed here. API:
`GET /api/v2/system/aauth/activity?limit=100&before_id=&outcome=allowed,denied`.

## Grants

A grant is a person's "Always allow": when that agent next asks this DreamFactory's person server
for scopes the grant covers, on the same resource, it gets an auth token without asking the person. Columns:
**Person**, **Agent**, **Resource**, **Scopes**, **Created**. **Revoke** ends a grant; the agent must
ask the person again next time. People can see and revoke their own grants at
`<issuer>/aauth/grants` after signing in.

A grant does not replace the role check: a person who no longer holds the role cannot pass it on,
grant or no grant. A grant also does not skip the person's identity step (see
[building-agents.md](building-agents.md#how-long-tokens-last)).

## Try it

Try it runs a built-in agent (**DreamFactory Playground**, hosted by this DreamFactory's agent
provider) against this DreamFactory, through its public issuer URL, and shows each step: request,
response and decoded tokens.

1. Pick a method, enter a path such as `/api/v2/sales/_table/orders?limit=5` (and a JSON body for
   POST, PATCH and PUT), and press **Send**.
2. The agent is challenged for a person token. A card shows a **Code** and an **Approve** button.
   **Approve** opens the consent page in a new tab: sign in, then **Continue**.
3. The agent comes back for an auth token. The same tab shows the consent card with the scope DreamFactory
   asked for. **Allow** (optionally **Always allow**).
4. The run ends with the API response. Sending again reuses the tokens; **Forget tokens** clears them.
   When the API no longer accepts a reused token (`401` with a `Signature-Error`, for example after a
   key revoke), Try it forgets its tokens and starts over once with the agent token, which asks for
   approval again.

A request that needs another scope (for example a PATCH after a read) runs the step-up and asks for
consent again. Try it needs DreamFactory to reach its own https origin from the server.

## What people see

The person approving an agent opens `<issuer>/aauth/interact?code=XXXX-XXXX` (agents usually give
them the full link; the code can also be typed on `<issuer>/aauth/interact`).

1. **Sign in** with their DreamFactory email and password. When the instance has an active LDAP or
   Active Directory service, a **Sign in with** list offers the directory too (username and password,
   with the service's role mapping). When an OAuth, OpenID Connect or SAML login service is active
   (`DF_AAUTH_SSO=auto`, the default; `on` or `off` to force it), a single sign-on button sends the
   person through DreamFactory's login page and back. The card shows the agent's name and its
   agent id (`aauth:<name>@<provider host>`); the name is self-asserted, the id is verified.
   **Deny** is available without signing in.
2. **Continue as <name>** confirms who the agent will act for; **Not you?** signs out.
3. **Consent** lists the resource, each requested scope with its description (scopes the person cannot
   grant are disabled), and the agent's justification, if it sent one. **Always allow** saves a grant.
   **Allow** or **Deny**.
4. The page shows **Approved** or **Denied** with the agent's tile, nothing more. When the link carried
   the agent's registered callback (`&callback=`), the browser goes to it a second later; otherwise
   the page stays, and the person closes the tab.

Signing in is never consent: the person always chooses. A code is single-use: the first browser that
submits anything for it (signs in, starts single sign-on, presses any button on the card, such as
**Deny**, **Not you?**, **Continue** or **Allow**, or types the code) owns the request and its
outcome; the waiting card after **Continue** claims the agent's next request the same way. Every
other browser, also one that opened the link earlier, then gets `This code was already used in
another browser. Ask the agent for a new code.` Opening the link does not claim the code, so chat
link previews and mail scanners that fetch it first do not use it up. Until the person acts, anyone
holding the link can act first: deny the request, or, at the identity step, sign in with their own
account and continue as themselves. A scope request can be approved only by the person its presented
token names (anyone else is asked to sign in as that person). Agents should therefore show the code
to the person only, not in shared channels.

Every sign-in method identifies a DreamFactory user, so consent offers exactly the scopes that user's
roles allow, whatever the method. How the SSO handoff is protected: [sso-approval.md](sso-approval.md).

## Admin API

`/api/v2/system/aauth`, sys admins only, on an instance whose license level is Gold (403 otherwise).
JSON keys are snake_case.

| Request | |
|---|---|
| `GET /` | `{enabled, issuer, issuer_ok, urls, counts}` |
| `PATCH / {enabled}` | Switch AAuth on or off. `400` when the issuer is not configured. |
| `GET /scopes` | Every role with `role_id, role_name, scope, description, enabled` |
| `PATCH /scopes/{role_id} {enabled?, scope?, description?}` | Configure a role's scope |
| `GET /person_servers`, `POST /person_servers {issuer}` | List; add an external person server |
| `PATCH /person_servers/{id} {enabled?, scopes?, all_scopes?}`, `DELETE /person_servers/{id}` | Configure; remove (not the local one) |
| `GET /agents`, `GET /agents/{id}`, `PATCH /agents/{id} {status: allowed\|blocked}`, `DELETE /agents/{id}?purge_activity=` | List, read, block, forget. A record: `id, agent_id, issuer, name, status, first_seen_at, last_seen_at, request_count, shares_key_with, shares_key_with_truncated`; `shares_key_with` lists the other agents bound to one of its signing keys (and a key's `jkt:` row), each as `{id, agent_id, issuer, name, status}` sorted by `agent_id`, so they can be blocked by `id` (one hop, see [Agents](#agents)). In the list it names at most 20 per agent, and `shares_key_with_truncated` is `true` when there are more; `GET` and `PATCH /agents/{id}` name all of them (`false`) |
| `GET /activity?limit=&before_id=&outcome=` | Newest first; `limit` 1 to 500 (default 100); `outcome` comma-separated |
| `GET /grants`, `DELETE /grants/{id}` | List; revoke |
| `POST /playground {action: send\|advance\|reset, method?, path?, body?, run_id?}` | Try it |

The same operations are documented in the instance's API Docs under `system`.

## Responding to an incident

| To | Do |
|---|---|
| Stop one agent | Block it in **Agents**, and every agent id in its `shares_key_with` ([Admin API](#admin-api); repeat for each of those until no new id appears). |
| Stop everything from a person server | Switch it off or remove it in **Person Servers**. |
| Withdraw an "Always allow" | Revoke it in **Grants**. |
| Stop one person's agents | Deactivate the user, or remove the role from them. |
| Narrow what agents can do | Switch a scope off, or change its role. |
| Stop all agent access | Switch **Enabled** off. |

All of these take effect on the agent's next request.
