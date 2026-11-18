# AAuth for OAuth developers

AAuth reuses OAuth's vocabulary (scopes, consent, grants, issuers, tokens, a device-flow style code)
but changes two things: there are no bearer tokens, because every token is bound to the agent's key
and every request is signed, and there is no client registration, because agents carry a verifiable
identity from their agent provider. This table maps what you know from OAuth 2.0 and OpenID Connect
to AAuth and to what DreamFactory does.

| OAuth 2.0 / OIDC | AAuth | In DreamFactory |
|---|---|---|
| Client | Agent | Listed under **Agents** after its first signed request |
| Client registration, `client_id` | Agent id `aauth:<name>@<agent provider host>`, vouched for by the agent provider's metadata and JWKS | No registration. Admins can block an agent. |
| Client secret, `private_key_jwt` | Agent token (`aa-agent+jwt`) from the agent provider, bound to the agent's own key (`cnf.jwk`) | Verified through the agent provider's `/.well-known/aauth-agent.json` |
| Authorization server | Person server (PS): issues person and auth tokens after the person approves. AAuth also defines access servers, for policy across trust domains. | Built in (`/aauth/person`, `/aauth/token`), or trusted external person servers under **Person Servers**. Access servers are not supported. |
| `/.well-known/oauth-authorization-server`, RFC 9728 protected resource metadata | `/.well-known/aauth-person.json`, `/.well-known/aauth-resource.json`, `/.well-known/aauth-agent.json` (`issuer` instead of `resource`) | All three published on the issuer |
| Issuer (`iss`) | Server identifier: `https://host`, no port or path | `DF_AAUTH_ISSUER` |
| JWKS | JWKS per role (`jwks_uri` in each metadata document); every key has a fully specified `alg` | `/aauth/jwks/{resource,person,agent}.json`, Ed25519 |
| Scope | Scope | **A scope is a DreamFactory role.** Admins choose which roles are scopes under **Scopes**. |
| Resource indicator (RFC 8707), `aud` | `resource` in the person token request; `aud` of person and auth tokens | `aud` must be the issuer |
| Authorization request, redirect URI | `POST /aauth/person` and `POST /aauth/token` answered `202` with an interaction code; the agent's `callback_endpoint` is only where the browser goes afterwards | Codes `XXXX-XXXX`; the callback must match the agent provider's registered `callback_endpoint` |
| Authorization code | No equivalent. The interaction code is a correlation id, not a credential; tokens never pass through the browser. | Single-use, 10 minutes, rate limited |
| Device authorization grant (RFC 8628): user code, polling | Interaction code and polling of a pending URL (`202`, `Location`, `Retry-After`) | `/aauth/interact?code=...`, `/aauth/pending/{id}` |
| Consent screen | Interaction at the person server | DreamFactory sign-in, "Continue as", per-scope consent; a person can grant only roles they hold |
| ID token | Person token (`aa-person+jwt`): who the agent acts for, at one resource, bound to the agent key | Pairwise `sub` per resource |
| Access token (bearer) | Auth token (`aa-auth+jwt`), used only with an HTTP signature by the bound key | Sent in `Signature-Key: sig=jwt;jwt="..."`, never `Authorization: Bearer` |
| DPoP (RFC 9449) | Built in: every request is an RFC 9421 HTTP message signature by the key in `cnf.jwk` | Covers method, host, path, query, `Signature-Key`, and body digest |
| `WWW-Authenticate` challenge | `AAuth-Requirement` header (`requirement=person-token`, `requirement=auth-token; resource-token="..."`) | Sent on DreamFactory's AAuth challenges. Its own "no API key" errors are unchanged except for a `Link` to the resource metadata (and `requirement=agent-token` on a 401). |
| Request object, `authorization_details` | Resource token (`aa-resource+jwt`): the resource's signed statement of what it asks the person server for (`scope`, `agent_jkt`, `sub`) | Least privileged scope that allows the request; valid 5 minutes, single use |
| Incremental authorization | Step-up: `401 requirement=auth-token` with a resource token for the extra scope; the agent presents its current auth token | Automatic when a granted scope does not cover the request |
| Refresh token | None. Get a new resource token and ask the person server again. | "Always allow" grants make the auth token step immediate; person tokens need the person again |
| Offline access, remembered consent | Standing permission ("Always allow") | **Grants**: revocable by admins and by the person at `/aauth/grants` |
| Token revocation (RFC 7009) | Revocation endpoint (recommended by the spec) | Not in 0.1.0. Block the agent, revoke the grant, or remove the role; effective on the next request. |
| Token introspection (RFC 7662) | Tokens are JWTs verified with the issuer's JWKS | Not needed |
| UserInfo | `profile` and `email` identity scopes put `name` and `email` in the auth token | Supported by the built-in person server |
| OIDC pairwise subject | Pairwise `sub` per resource (required) | HMAC of user id and resource, keyed from `APP_KEY` |
| `client_credentials` (no user) | Not in three-party mode: a person always approves | Use DreamFactory API keys for unattended services |

## DreamFactory concepts

| DreamFactory | With AAuth |
|---|---|
| API key (app) | Not used. AAuth sessions run under a hidden app named `aauth`. Sending an API key and AAuth signatures together is refused. |
| Session token (JWT from `/user/session`) | Not used. The person signs in on the consent page only. |
| Role | The scope. Its service access, filters and limits apply unchanged. |
| User | On the built-in person server, the person who approved: the session carries their user (never as sys admin), so lookups, per-user limits and scripts see them. External person servers: no user. |
| Sys admin | Can approve any enabled scope; the agent still gets only that scope's role. |
| OAuth / OIDC / SAML services (df-oauth, df-oidc, df-saml) | Log users into DreamFactory; unrelated to agent authorization. |
| Data Masking | AAuth calls count as AI sessions. |
