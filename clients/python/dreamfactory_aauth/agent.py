"""The AAuth agent: signed requests plus the three-party flow (draft-hardt-oauth-aauth-protocol-11).

    call with agent token        -> 401 AAuth-Requirement: requirement=person-token
    PS person_token_endpoint     -> 200 person token, or 202 + interaction code -> poll Location
    call with person token       -> 401 requirement=auth-token; resource-token="..."
    PS auth_token_endpoint       -> 200 auth token (standing grant), or 202 + consent -> poll
    call with auth token         -> the API response (a later 401 auth-token is a step-up)

With ``scope=...`` the agent asks the resource's ``authorization_endpoint`` for a resource token
up front instead of waiting for the challenge.
"""

from __future__ import annotations

import json as _json
import os
import tempfile
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Tuple
from urllib.parse import quote, urljoin

import requests

from .discovery import Discovery, assert_server_id, origin_of
from .errors import AAuthError, Cancelled, InvalidToken, NotApproved
from .jose import Jwk, claims, generate_jwk, jwk_thumbprint, now, public_jwk, random_id, scopes_of, sign_jwt
from .sf import parse_requirement, parse_signature_error
from .signing import SignedRequest, encode_body, sign_request

NOT_APPROVED = {"denied", "abandoned", "expired", "invalid_code", "access_denied", "user_unreachable", "timeout"}
REFRESH_MARGIN = 300  # tokens closer than this to exp are not reused


# ---------------------------------------------------------------------------
# Token caches: key = f"{issuer}|{agent_id}|{jkt}|{resource}|{ps}", value = {"person": jwt, "auth": jwt}
# (the same format the Node CLI uses, so both can share a tokens.json)
# ---------------------------------------------------------------------------

class MemoryTokenCache:
    def __init__(self) -> None:
        self._d: Dict[str, dict] = {}

    def get(self, key: str) -> Optional[dict]:
        return self._d.get(key)

    def set(self, key: str, value: dict) -> None:
        self._d[key] = value

    def delete(self, key: str) -> None:
        self._d.pop(key, None)

    def all(self) -> Dict[str, dict]:
        return dict(self._d)


class FileTokenCache(MemoryTokenCache):
    """A JSON file, written atomically with mode 600. Tokens are bound to the agent key (cnf)."""

    def __init__(self, path: str) -> None:
        super().__init__()
        self.path = os.path.expanduser(path)

    def _read(self) -> Dict[str, dict]:
        try:
            with open(self.path, encoding="utf-8") as f:
                data = _json.load(f)
            return data if isinstance(data, dict) else {}
        except (OSError, ValueError):
            return {}

    def _write(self, data: Dict[str, dict]) -> None:
        d = os.path.dirname(os.path.abspath(self.path))
        os.makedirs(d, mode=0o700, exist_ok=True)
        fd, tmp = tempfile.mkstemp(prefix=".tokens.", dir=d)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                _json.dump(data, f, indent=2)
            os.chmod(tmp, 0o600)
            os.replace(tmp, self.path)
        except BaseException:
            try:
                os.unlink(tmp)
            except OSError:
                pass
            raise

    def get(self, key: str) -> Optional[dict]:
        return self._read().get(key)

    def set(self, key: str, value: dict) -> None:
        data = self._read()
        data[key] = value
        self._write(data)

    def delete(self, key: str) -> None:
        data = self._read()
        if data.pop(key, None) is not None:
            self._write(data)

    def all(self) -> Dict[str, dict]:
        return self._read()


# ---------------------------------------------------------------------------
# Flow records
# ---------------------------------------------------------------------------

@dataclass
class Interaction:
    """The person has to act. Show ``user_url`` (or ``url`` + ``code``) to them."""

    purpose: str  # "person" (identify / sign in) or "auth" (consent to a scope)
    code: Optional[str]
    url: Optional[str]  # the Person Server's interaction page
    user_url: Optional[str]  # url?code=...[&callback=...]
    location: str  # the pending URL the agent polls
    requirement: Optional[str]
    scope: Optional[str] = None


@dataclass
class Step:
    kind: str  # discover, call, reuse, person_token, auth_token, authorize, poll
    title: str
    status: int
    request: Optional[SignedRequest] = None
    response: Optional[requests.Response] = None
    tokens: List[str] = field(default_factory=list)

    @property
    def requirement(self) -> Dict[str, Any]:
        return parse_requirement(self.response.headers.get("AAuth-Requirement", "")) if self.response is not None else {}


@dataclass
class Flow:
    steps: List[Step] = field(default_factory=list)
    interactions: List[Interaction] = field(default_factory=list)


@dataclass
class _Ctx:
    flow: Flow
    ps: str
    ps_meta: dict
    resource: str
    agent_token: str
    justification: Optional[str]
    on_interaction: Optional[Callable[[Interaction], Any]]
    on_step: Optional[Callable[[Step], Any]]
    poll_timeout: float


def _body(r: requests.Response) -> Any:
    try:
        return r.json()
    except ValueError:
        return None


def _retry_after(r: requests.Response, default: float) -> float:
    v = r.headers.get("Retry-After")
    try:
        n = float(v) if v is not None else default
    except ValueError:
        return default
    return n if n >= 0 else default


# ---------------------------------------------------------------------------
# The agent
# ---------------------------------------------------------------------------

class Agent:
    """An AAuth agent.

    issuer         your Agent Provider: the https origin serving /.well-known/aauth-agent.json + JWKS
    agent_id       aauth:<name>@<issuer host> (default aauth:agent@<host>)
    provider_key   private JWK that signs agent tokens (published in the AP's JWKS), or ...
    agent_token    ... a callable ps -> aa-agent+jwt that your AP minted for agent_key
    agent_key      private JWK that signs every request; generated when omitted
    token_cache    MemoryTokenCache() (default) or FileTokenCache(path)
    callback       True (= {issuer}/callback), a URL, or None: appended to the approval URL
    insecure       allow http:// servers (local testing only)
    """

    def __init__(
        self,
        issuer: str,
        *,
        agent_id: Optional[str] = None,
        provider_key: Optional[Jwk] = None,
        agent_token: Optional[Callable[[Optional[str]], str]] = None,
        agent_key: Optional[Jwk] = None,
        token_cache: Optional[MemoryTokenCache] = None,
        callback: Any = None,
        insecure: bool = False,
        session: Optional[requests.Session] = None,
        discovery: Optional[Discovery] = None,
        timeout: float = 30.0,
        max_step_ups: int = 2,
    ):
        if not provider_key and not callable(agent_token):
            raise ValueError("provider_key (or an agent_token(ps) callable) is required")
        self.issuer = issuer.rstrip("/")
        assert_server_id(self.issuer, insecure)
        self.provider_key = provider_key
        self._token_source = agent_token
        self.agent_key = agent_key or generate_jwk()
        self.agent_id = agent_id or f"aauth:agent@{self.issuer.split('://', 1)[1]}"
        self.jkt = jwk_thumbprint(self.agent_key)
        self.cache = token_cache if token_cache is not None else MemoryTokenCache()
        self.callback = callback
        self.insecure = insecure
        self.session = session or requests.Session()
        self.discovery = discovery or Discovery(self.session, insecure=insecure)
        self.timeout = timeout
        self.max_step_ups = max_step_ups

    # -- identity -----------------------------------------------------------
    @property
    def callback_url(self) -> Optional[str]:
        if not self.callback:
            return None
        return f"{self.issuer}/callback" if self.callback is True else str(self.callback)

    def agent_token(self, ps: Optional[str] = None, ttl: int = 3600) -> str:
        """A fresh aa-agent+jwt for agent_key, signed with provider_key (or from the agent_token callable)."""
        if self._token_source is not None:
            tok = self._token_source(ps)
            if jwk_thumbprint((claims(tok).get("cnf") or {}).get("jwk") or {"kty": "OKP", "crv": "Ed25519", "x": ""}) != self.jkt:
                raise InvalidToken("invalid_agent_token", "agent_token(ps) returned a token for a different agent_key")
            return tok
        t = now()
        payload: Dict[str, Any] = {"iss": self.issuer, "dwk": "aauth-agent.json", "sub": self.agent_id, "cnf": {"jwk": public_jwk(self.agent_key)}, "jti": random_id(), "iat": t, "exp": t + ttl}
        if ps:
            payload["ps"] = ps
        return sign_jwt("aa-agent+jwt", payload, self.provider_key)

    def cache_key(self, resource: str, ps: str) -> str:
        return f"{self.issuer}|{self.agent_id}|{self.jkt}|{resource}|{ps}"

    def forget(self, resource: Optional[str] = None) -> int:
        """Drop cached tokens for one resource origin (or all). Returns how many entries went."""
        prefix = f"{self.issuer}|{self.agent_id}|{self.jkt}|"
        gone = 0
        for k in list(self.cache.all()):
            if k.startswith(prefix) and (resource is None or k.split("|")[3] == origin_of(resource)):
                self.cache.delete(k)
                gone += 1
        return gone

    # -- HTTP -----------------------------------------------------------------
    def get(self, url: str, **kw: Any) -> requests.Response:
        return self.request("GET", url, **kw)

    def post(self, url: str, **kw: Any) -> requests.Response:
        return self.request("POST", url, **kw)

    def put(self, url: str, **kw: Any) -> requests.Response:
        return self.request("PUT", url, **kw)

    def patch(self, url: str, **kw: Any) -> requests.Response:
        return self.request("PATCH", url, **kw)

    def delete(self, url: str, **kw: Any) -> requests.Response:
        return self.request("DELETE", url, **kw)

    def _send(self, ctx: _Ctx, kind: str, title: str, method: str, url: str, token: str, body: Optional[bytes] = None, headers: Optional[dict] = None, additional: Any = ()) -> requests.Response:
        signed = sign_request(method, url, token=token, key=self.agent_key, body=body, headers=headers, additional=additional or ())
        r = self.session.request(signed.method, signed.url, headers=signed.headers, data=signed.body, allow_redirects=False, timeout=self.timeout)
        step = Step(kind, title, r.status_code, signed, r)
        ctx.flow.steps.append(step)
        if ctx.on_step:
            ctx.on_step(step)
        return r

    def _note(self, ctx: _Ctx, step: Step) -> None:
        ctx.flow.steps.append(step)
        if ctx.on_step:
            ctx.on_step(step)

    def request(
        self,
        method: str,
        url: str,
        *,
        params: Any = None,
        json: Any = None,
        data: Any = None,
        headers: Optional[Dict[str, str]] = None,
        scope: Any = None,
        ps: Optional[str] = None,
        justification: Optional[str] = None,
        on_interaction: Optional[Callable[[Interaction], Any]] = None,
        on_step: Optional[Callable[[Step], Any]] = None,
        fresh: bool = False,
        poll_timeout: float = 600.0,
        _retried: bool = False,
    ) -> requests.Response:
        """Call ``url`` as this agent and return the API's ``requests.Response``.

        The person is involved only when the resource asks for it: ``on_interaction(Interaction)``
        is called with the approval URL and code (return "cancel" to withdraw the request), then the
        agent polls. ``response.aauth`` is the Flow (steps and interactions). AAuth failures raise
        NotApproved (denied/expired/timeout), Cancelled, InvalidToken or AAuthError; API errors
        (403, 404, ...) are returned as responses, like requests does.
        """
        method = method.upper()
        prepared = requests.models.PreparedRequest()
        prepared.prepare_url(url, params)
        final_url = prepared.url
        hdrs = {k.lower(): v for k, v in (headers or {}).items()}
        if json is not None and data is not None:
            raise ValueError("pass json= or data=, not both")
        body = encode_body(json) if json is not None else encode_body(data)
        if json is not None:
            hdrs.setdefault("content-type", "application/json")

        flow = Flow()
        resource = origin_of(final_url)
        assert_server_id(resource, self.insecure)
        rmeta = self.discovery.metadata(resource, "aauth-resource.json")
        ps_id, ps_meta = self._resolve_ps(resource, ps)
        ctx = _Ctx(flow, ps_id, ps_meta, resource, self.agent_token(ps_id), justification, on_interaction, on_step, poll_timeout)
        self._note(ctx, Step("discover", "Resource metadata", 200))
        self._note(ctx, Step("discover", "Person Server metadata", 200))
        additional = rmeta.get("additional_signature_components") or ()
        key = self.cache_key(resource, ps_id)
        if fresh:
            self.cache.delete(key)
        saved = self.cache.get(key) or {}

        def valid(tok: Optional[str]) -> Optional[str]:
            try:
                return tok if tok and int(claims(tok).get("exp", 0)) > now() + REFRESH_MARGIN else None
            except AAuthError:
                return None

        person, auth = valid(saved.get("person")), valid(saved.get("auth"))

        def call(kind: str, title: str, token: str) -> requests.Response:
            return self._send(ctx, kind, title, method, final_url, token, body, hdrs, additional)

        def again() -> requests.Response:
            return self.request(method, url, params=params, json=json, data=data, headers=headers, scope=scope, ps=ps, justification=justification, on_interaction=on_interaction, on_step=on_step, fresh=True, poll_timeout=poll_timeout, _retried=True)

        def finish(r: requests.Response) -> requests.Response:
            r.aauth = flow  # type: ignore[attr-defined]
            return r

        def req_of(r: requests.Response) -> Optional[str]:
            return parse_requirement(r.headers.get("AAuth-Requirement", "")).get("requirement")

        reuse = ("reuse", "Call with cached auth token")

        # Up-front scope (§6.6): resource token from the authorization endpoint, then the PS.
        wanted = scopes_of(scope)
        if wanted and not (auth and all(s in scopes_of(auth) for s in wanted)):
            endpoint = rmeta.get("authorization_endpoint")
            if not endpoint:
                self._note(ctx, Step("authorize", "No authorization_endpoint: the scope comes from the resource challenge", 0))
            else:
                if not person and not auth:
                    person = self._person_token(ctx)
                    self.cache.set(key, {"person": person})
                presented = auth or person
                ask = " ".join(dict.fromkeys((scopes_of(auth) if auth else []) + wanted))
                r = self._send(ctx, "authorize", f"Ask the resource for {ask}", "POST", endpoint, presented, encode_body({"scope": ask}), {"content-type": "application/json"})
                rb = _body(r)
                if r.status_code != 200 or not isinstance(rb, dict) or not isinstance(rb.get("resource_token"), str):
                    if r.status_code == 401 and not _retried and presented in (saved.get("person"), saved.get("auth")):
                        self.cache.delete(key)
                        return again()
                    raise self._error(r, flow)
                rt = rb["resource_token"]
                rtc = self._check_resource_token(rt, resource, ps_id, presented)
                flow.steps[-1].tokens.append(rt)
                auth = self._auth_token(ctx, rt, presented, rtc)
                self.cache.set(key, {"person": person, "auth": auth} if person else {"auth": auth})
                reuse = ("call", "Call with auth token")

        r: Optional[requests.Response] = None
        if auth:
            r = call(reuse[0], reuse[1], auth)
            if req_of(r) != "auth-token" and r.status_code == 401:
                auth = person = None  # revoked, keys rotated, expired: start over
                self.cache.delete(key)
            elif req_of(r) != "auth-token":
                return finish(r)
        if r is None or (not auth and not person):
            if not person:
                r = call("call", "Call with agent token", ctx.agent_token)
                if req_of(r) != "person-token":
                    return finish(r)
                person = self._person_token(ctx)
                self.cache.set(key, {"person": person})
            r = call("call", "Call with person token", person)
            if r.status_code == 401 and req_of(r) != "auth-token" and saved.get("person") == person and not _retried:
                self.cache.delete(key)
                return again()

        presented = auth or person
        assert r is not None and presented is not None
        for rnd in range(self.max_step_ups + 1):
            reqm = parse_requirement(r.headers.get("AAuth-Requirement", ""))
            if r.status_code not in (401, 202, 402) or reqm.get("requirement") != "auth-token":
                return finish(r)
            if rnd == self.max_step_ups:
                raise AAuthError("step_up_loop", "The resource keeps asking for more scope", r.status_code, r, flow.steps)
            rt = reqm.get("resource-token")
            if not rt:
                raise AAuthError("no_resource_token", "auth-token challenge without a resource token", r.status_code, r, flow.steps)
            rtc = self._check_resource_token(rt, resource, ps_id, presented)
            flow.steps[-1].tokens.append(rt)
            auth = self._auth_token(ctx, rt, presented, rtc)
            self.cache.set(key, {"person": person, "auth": auth})
            presented = auth
            r = call("call", "Call with auth token", auth)
            if r.status_code == 401 and req_of(r) != "auth-token":
                self.cache.set(key, {"person": person})
        return finish(r)

    # -- pieces ---------------------------------------------------------------
    def _resolve_ps(self, resource: str, explicit: Optional[str]) -> Tuple[str, dict]:
        if explicit:
            ps = explicit.rstrip("/")
            assert_server_id(ps, self.insecure)
            return ps, self.discovery.metadata(ps, "aauth-person.json")
        try:
            return resource, self.discovery.metadata(resource, "aauth-person.json")
        except AAuthError as e:
            raise AAuthError("no_person_server", f"{resource} has no Person Server metadata; pass ps=<url> ({e})") from None

    def _error(self, r: requests.Response, flow: Flow) -> AAuthError:
        b = _body(r)
        err = b.get("error") if isinstance(b, dict) and isinstance(b.get("error"), str) else f"http_{r.status_code}"
        detail = b.get("detail", "") if isinstance(b, dict) else ""
        sig = parse_signature_error(r.headers.get("Signature-Error", ""))
        if sig.get("error") and err.startswith("http_"):
            err = str(sig["error"])
        cls = NotApproved if err in NOT_APPROVED else AAuthError
        return cls(err, str(detail or ""), r.status_code, r, flow.steps)

    def _check_resource_token(self, rt: str, resource: str, ps: str, presented: str) -> Dict[str, Any]:
        """§6.7.3: the challenge's resource token must be about this agent, this PS and the presented token."""
        try:
            c = self.discovery.verify_jwt(rt, "aa-resource+jwt", expect_iss=resource)
        except AAuthError as e:
            raise InvalidToken("invalid_resource_token", e.detail or e.error) from None
        p = claims(presented)
        problems = []
        if c.get("agent_jkt") != self.jkt:
            problems.append("agent_jkt is not this agent key")
        if c.get("aud") != ps:
            problems.append(f"aud {c.get('aud')} is not the person server {ps}")
        if "ps" in c and c["ps"] != ps:
            problems.append(f"ps {c['ps']} is not the person server {ps}")
        if c.get("sub") != p.get("sub"):
            problems.append("sub does not match the presented token")
        if c.get("presented_jti") != p.get("jti"):
            problems.append("presented_jti does not match the presented token")
        if problems:
            raise InvalidToken("invalid_resource_token", "; ".join(problems))
        return c

    def _person_token(self, ctx: _Ctx) -> str:
        endpoint = ctx.ps_meta.get("person_token_endpoint")
        if not endpoint:
            raise AAuthError("no_person_token_endpoint", f"{ctx.ps} publishes no person_token_endpoint")
        body: Dict[str, Any] = {"resource": ctx.resource, "capabilities": ["interaction"]}
        if ctx.justification:
            body["justification"] = ctx.justification
        r = self._send(ctx, "person_token", "Ask the PS for a person token", "POST", endpoint, ctx.agent_token, encode_body(body), {"content-type": "application/json"})
        tok = self._deferred(ctx, r, "person", endpoint)
        try:
            c = self.discovery.verify_jwt(tok, "aa-person+jwt", expect_iss=ctx.ps)
        except AAuthError as e:
            raise InvalidToken("invalid_person_token", e.detail or e.error) from None
        if c.get("aud") != ctx.resource:
            raise InvalidToken("invalid_person_token", f"aud {c.get('aud')} is not {ctx.resource}")
        if jwk_thumbprint((c.get("cnf") or {}).get("jwk") or {"kty": "OKP", "crv": "", "x": ""}) != self.jkt:
            raise InvalidToken("invalid_person_token", "cnf is not this agent key")
        return tok

    def _auth_token(self, ctx: _Ctx, rt: str, presented: str, rtc: Dict[str, Any]) -> str:
        endpoint = ctx.ps_meta.get("auth_token_endpoint")
        if not endpoint:
            raise AAuthError("no_auth_token_endpoint", f"{ctx.ps} publishes no auth_token_endpoint")
        body: Dict[str, Any] = {"resource_token": rt, "presented_token": presented}
        if ctx.justification:
            body["justification"] = ctx.justification
        r = self._send(ctx, "auth_token", f"Ask the PS for an auth token ({rtc.get('scope', '')})", "POST", endpoint, ctx.agent_token, encode_body(body), {"content-type": "application/json"})
        tok = self._deferred(ctx, r, "auth", endpoint, rtc.get("scope"))
        try:
            c = self.discovery.verify_jwt(tok, "aa-auth+jwt", expect_iss=rtc.get("aud"))
        except AAuthError as e:
            raise InvalidToken("invalid_auth_token", e.detail or e.error) from None
        if c.get("aud") != ctx.resource:
            raise InvalidToken("invalid_auth_token", f"aud {c.get('aud')} is not {ctx.resource}")
        if jwk_thumbprint((c.get("cnf") or {}).get("jwk") or {"kty": "OKP", "crv": "", "x": ""}) != self.jkt:
            raise InvalidToken("invalid_auth_token", "cnf is not this agent key")
        if c.get("sub") != claims(presented).get("sub"):
            raise InvalidToken("invalid_auth_token", "sub does not match the presented token")
        return tok

    def _deferred(self, ctx: _Ctx, r: requests.Response, purpose: str, endpoint: str, scope: Optional[str] = None) -> str:
        """A PS token endpoint answer: 200 with the token, or 202 + interaction, then polling."""
        name = "person_token" if purpose == "person" else "auth_token"
        b = _body(r)
        if r.status_code == 200 and isinstance(b, dict) and isinstance(b.get(name), str):
            return b[name]
        if r.status_code != 202:
            raise self._error(r, ctx.flow)
        reqm = parse_requirement(r.headers.get("AAuth-Requirement", ""))
        loc = r.headers.get("Location")
        if not loc:
            raise AAuthError("no_location", "202 without Location", 202, r, ctx.flow.steps)
        location = urljoin(endpoint, loc)
        if origin_of(location) != origin_of(endpoint):
            raise AAuthError("invalid_location", f"pending URL {location} is not on {origin_of(endpoint)}", 202, r, ctx.flow.steps)
        code = reqm.get("code") or (b.get("code") if isinstance(b, dict) else None)
        page = reqm.get("url")
        user_url = None
        if reqm.get("requirement") == "interaction" and code and page:
            user_url = f"{page}?code={quote(str(code), safe='')}"
            if self.callback_url:
                user_url += f"&callback={quote(self.callback_url, safe='')}"
        info = Interaction(purpose, code, page, user_url, location, reqm.get("requirement"), scope)
        ctx.flow.interactions.append(info)
        if ctx.on_interaction and ctx.on_interaction(info) == "cancel":
            self._cancel(ctx, location)
            raise Cancelled("cancelled", "The agent withdrew the request", 0, None, ctx.flow.steps)
        return self._poll(ctx, location, name, _retry_after(r, 0))

    def _cancel(self, ctx: _Ctx, location: str) -> None:
        self._send(ctx, "poll", "Cancel the pending request", "DELETE", location, ctx.agent_token)

    def _poll(self, ctx: _Ctx, location: str, name: str, wait: float) -> str:
        deadline = time.monotonic() + ctx.poll_timeout
        polls = 0
        try:
            while time.monotonic() < deadline:
                if wait > 0:
                    time.sleep(min(wait, max(0.0, deadline - time.monotonic())))
                signed = sign_request("GET", location, token=ctx.agent_token, key=self.agent_key)
                r = self.session.get(signed.url, headers=signed.headers, allow_redirects=False, timeout=self.timeout)
                polls += 1
                if r.status_code == 202:
                    wait = _retry_after(r, 5)
                    continue
                if r.status_code == 429:
                    wait += 5
                    continue
                self._note(ctx, Step("poll", f"Poll ({polls}x)", r.status_code, signed, r))
                b = _body(r)
                if r.status_code == 200 and isinstance(b, dict) and isinstance(b.get(name), str):
                    return b[name]
                raise self._error(r, ctx.flow)
        except KeyboardInterrupt:
            try:
                self._cancel(ctx, location)
            except Exception:
                pass
            raise
        raise NotApproved("timeout", "Gave up waiting for the person", 0, None, ctx.flow.steps)
