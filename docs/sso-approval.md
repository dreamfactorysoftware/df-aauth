# Approving agents with SSO and directory accounts

The person who approves an agent signs in on DreamFactory's consent page (`/aauth/interact`) or on
the standing-grants page (`/aauth/grants`). Three sign-in methods are supported. Each one identifies
the person as a **DreamFactory user**, so consent offers exactly the scopes (roles) that user holds,
whatever the method.

| Method | Who it is for | Shown when |
|---|---|---|
| Email (or username) + password | local DreamFactory users | always |
| Directory account | users of an LDAP or Active Directory service (`ldap`, `adldap`) | at least one such service is active |
| Single sign-on | users of OAuth, OpenID Connect or SAML login services (also works for every other method) | `DF_AAUTH_SSO=auto` (default) and an OAuth/OIDC/SAML service is active, or `DF_AAUTH_SSO=on` |

Signing in is never consent. After any method the person sees the same "Continue as ..." card with
**Allow** and **Deny**. No method creates, changes or ends a DreamFactory session: the person is
signed in to the consent pages only (the `aauth_ps.uid` key of their consent session).

## Directory accounts (LDAP, Active Directory)

The sign-in card gets a **Sign in with** list: *DreamFactory account* plus every active service of
DreamFactory's LDAP group, as DreamFactory's own login page lists them. The login field then
accepts a username.

The check is DreamFactory's LDAP login (`df-adldap` `LDAP::handleLogin`) without the session token:

1. `getDriver()->authenticate(username, password)` binds to the directory (an empty password is
   refused before any bind, because many servers treat it as an anonymous bind).
2. `createShadowADLdapUser(driver->getUser())` creates or updates the directory user's shadow
   DreamFactory user and applies the service's default role and its group-to-role mapping, exactly
   as a DreamFactory login with that service would.
3. The shadow user must be active.

Failure limits are the same as for passwords (10 failures per client address per 10 minutes, 20
per account per 15 minutes, 5 per pending request), and a directory account is its own bucket:
`jdoe` at `corp-ldap` is not the local user `jdoe`.

## Single sign-on (OAuth, OpenID Connect, SAML)

These methods redirect the browser to an identity provider, so the consent page cannot check a
password itself. Instead it hands the person to **DreamFactory's own login page** and takes them
back, signed in. That page already supports every login method configured on the instance, and
returns to a caller with the person's session token: the handoff `df-mcp-server` uses.

```
consent page                     DreamFactory login (admin app)              identity provider
------------                     ------------------------------              -----------------
POST decision=sso  (CSRF)
  the request is claimed for this browser (single-use code) before it leaves
  state S -> this consent session
303 {issuer}/dreamfactory/dist/#/auth/login?redirect={issuer}/aauth/interact/sso%23state%3DS
                                 already signed in? -> back at once
                                 else: any login method  ----------------->  sign in
                                                         <-----------------
                                 same-origin redirect only:
                                 {issuer}/aauth/interact/sso#state=S?session_token=JWT
GET /aauth/interact/sso   (page + script; the fragment never reaches the server)
  script: copy state + token from the URL into a form, scrub the URL (history.replaceState)
POST /aauth/interact/sso  {_token, state, session_token}
  S is one of this session's states (single use; at most 15 min old)
  token: signature, expiry, logout blacklist, user exists and is active
  -> regenerate the session id, sign the person in to the consent session
303 /aauth/interact?code=XXXX-XXXX   ->  "Continue as ..."  ->  Allow / Deny
```

On the grants page the same flow ends at `/aauth/grants`.

### Why this is safe

- **The token never reaches a server log or a Referer.** Our return URL ends in a fragment
  (`#state=S`). The admin app (and DreamFactory's OAuth callback) append `?session_token=...` to
  that URL as plain text, so the token lands inside the fragment, which browsers never send. The
  landing page's script removes it from the address bar and the history entry before posting it.
  If a future admin app put the token in the query instead, the page still works (and still
  scrubs the URL), but the token would then appear in the access log of that one request.
- **Only the browser that started the sign-in can finish it.** The state is random (24 bytes), stored in the consent
  session of the browser that clicked the button (at most five outstanding, 15 minutes each, so
  two consent tabs do not cancel each other), compared in constant time, and consumed by the first
  attempt that presents it, whatever its outcome. A token posted without one of that browser's
  states signs nobody in.
- **The token is checked like any DreamFactory session**: signature (`JWT_SECRET` / `APP_KEY`),
  `exp`, the logout blacklist, `sub` = the user's email hash (`JWTUtilities::verifyUser`), and the
  user must be active. It is not stored: only the user id is kept in the consent session.
- **Same origin only.** The admin app follows a `redirect` only to its own origin, and our
  redirect is built from `DF_AAUTH_ISSUER`, never from the request `Host`. DreamFactory's OAuth
  `redirect` parameter is checked against `df.oauth.allowed_redirect_domains` (default: the
  `APP_URL` host); when it does not match, the admin app still returns the person from its own
  per-tab storage.
- **Signing in is not consent.** The person still sees the agent, the resource and the scopes, and
  must press Allow. An auth request bound to a person (`user_id`) accepts only that person.
- **Rate limited.** Failed completions count toward the per-address code limit, and completions
  are capped per address (30 per 10 minutes).

### What to know before relying on it

- **Session reuse.** If the person is already signed in to DreamFactory in that browser, the admin
  app returns at once, without asking for credentials again. This is the usual single sign-on
  behaviour; how long a DreamFactory session lasts is `DF_JWT_TTL` / `DF_JWT_REFRESH_TTL`. A
  "re-enter your password to approve" (max-age) rule is not offered, because the admin app has no
  way to force a fresh login.
- **The admin app must be served on the issuer origin**, at `/dreamfactory/dist/` by default
  (`DF_AAUTH_SSO_LOGIN_PATH` changes the path). The consent pages already load their fonts and logo
  from there.
- **Scopes follow DreamFactory roles.** An SSO user can approve a scope only when their shadow user
  holds the role (default role of the login service, or its role mapping).
- **JavaScript is required** on the landing page (it moves the token out of the fragment).

## Settings

| Variable | Default | Meaning |
|---|---|---|
| `DF_AAUTH_SSO` | `auto` | `auto`: offer single sign-on when an OAuth, OpenID Connect or SAML login service is active. `on`: always offer it (it also covers password and LDAP logins). `off`: never. |
| `DF_AAUTH_SSO_LOGIN_PATH` | `/dreamfactory/dist/#/auth/login` | The admin app's login route on the issuer origin. |

Directory sign-in has no setting: it follows the LDAP / Active Directory services that are active
in DreamFactory.

## Not supported

- Identity-provider-initiated SAML (the consent page must start the flow, so the state exists).
- Signing in with an API key or a DreamFactory session token pasted into the consent page.
- Approving from a different browser than the one that first acted on the code (codes are
  single-use per browser, as for every sign-in method; choosing single sign-on claims the code).
