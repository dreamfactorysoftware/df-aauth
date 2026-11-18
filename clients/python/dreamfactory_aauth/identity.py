"""Agent identity: the Agent Provider keys, the agent id, and the public documents to publish.

The identity file is the same ``agent.json`` that ``aauth init`` (the Node CLI) writes::

    {"version": 1, "issuer": "https://agents.example.com", "agent_id": "aauth:reports@agents.example.com",
     "name": "Acme Reports", "ap": {<private JWK>}, "agent": {<private JWK>}, "created_at": "..."}

``ap`` signs agent tokens; publish its public half at {issuer}/jwks.json together with
{issuer}/.well-known/aauth-agent.json (``provider_documents()``). ``agent`` signs requests.
"""

from __future__ import annotations

import json
import os
import re
import time
from dataclasses import dataclass, field
from typing import Any, Dict, Optional

from .agent import Agent, FileTokenCache, MemoryTokenCache
from .discovery import assert_server_id
from .jose import Jwk, generate_jwk, now, public_jwk, random_id, sign_jwt

_LOCAL = re.compile(r"^[A-Za-z0-9._-][A-Za-z0-9._+-]{0,254}$")


def config_home(env: Optional[Dict[str, str]] = None) -> str:
    env = os.environ if env is None else env
    if env.get("AAUTH_HOME"):
        return env["AAUTH_HOME"]
    base = env.get("XDG_CONFIG_HOME") or os.path.join(os.path.expanduser("~"), ".config")
    return os.path.join(base, "aauth")


def default_identity_path(env: Optional[Dict[str, str]] = None) -> str:
    env = os.environ if env is None else env
    return env.get("AAUTH_CONFIG") or os.path.join(config_home(env), "agent.json")


def mint_agent_token(issuer: str, provider_key: Jwk, agent_id: str, agent_jwk: Jwk, ps: Optional[str] = None, ttl: int = 3600, extra: Optional[Dict[str, Any]] = None) -> str:
    """An aa-agent+jwt binding agent_id to agent_jwk (only its public half goes into cnf). At most 24 h.

    Use it in your Agent Provider when agent instances hold only their own request key.
    """
    if ttl > 86400:
        raise ValueError("agent tokens live at most 24 h")
    t = now()
    payload: Dict[str, Any] = {"iss": issuer.rstrip("/"), "dwk": "aauth-agent.json", "sub": agent_id, "cnf": {"jwk": public_jwk(agent_jwk)}, **(extra or {}), "jti": random_id(), "iat": t, "exp": t + ttl}
    if ps:
        payload["ps"] = ps
    return sign_jwt("aa-agent+jwt", payload, provider_key)


@dataclass
class AgentIdentity:
    issuer: str
    agent_id: str
    provider_key: Jwk
    agent_key: Jwk
    name: Optional[str] = None
    callback_endpoint: Optional[str] = None
    path: Optional[str] = field(default=None, compare=False)

    @classmethod
    def generate(cls, issuer: str, name: Optional[str] = None, local: Optional[str] = None, callback: Any = False, insecure: bool = False) -> "AgentIdentity":
        """New keys for an agent whose provider documents will be served from ``issuer``."""
        iss = issuer.rstrip("/")
        assert_server_id(iss, insecure)
        local = local or re.sub(r"[^a-z0-9._-]+", "-", (name or "agent").lower()).strip("-") or "agent"
        if not _LOCAL.match(local) or "+" in local:
            raise ValueError(f"agent id name must use letters, digits, . _ -: {local}")
        cb = f"{iss}/callback" if callback is True else (callback or None)
        return cls(iss, f"aauth:{local}@{iss.split('://', 1)[1]}", generate_jwk(), generate_jwk(), name or local, cb)

    @classmethod
    def from_dict(cls, d: Dict[str, Any], issuer: Optional[str] = None, agent_id: Optional[str] = None, path: Optional[str] = None) -> "AgentIdentity":
        """From an identity file's JSON, or a bare keys file ({ap, agent}) plus issuer/agent_id."""
        iss = (issuer or d.get("issuer") or "").rstrip("/")
        if not iss:
            raise ValueError("the identity has no issuer (pass issuer=...)")
        ap, ag = d.get("ap") or d.get("provider_key"), d.get("agent") or d.get("agent_key")
        if not (isinstance(ap, dict) and ap.get("d") and isinstance(ag, dict) and ag.get("d")):
            raise ValueError("the identity needs the private keys 'ap' and 'agent'")
        sub = agent_id or d.get("agent_id") or d.get("sub") or f"aauth:agent@{iss.split('://', 1)[1]}"
        return cls(iss, sub, ap, ag, d.get("name"), d.get("callback_endpoint"), path)

    @classmethod
    def load(cls, path: Optional[str] = None, issuer: Optional[str] = None, agent_id: Optional[str] = None) -> "AgentIdentity":
        """Load agent.json (default: $AAUTH_CONFIG, else ~/.config/aauth/agent.json)."""
        p = os.path.expanduser(path or default_identity_path())
        with open(p, encoding="utf-8") as f:
            d = json.load(f)
        return cls.from_dict(d, issuer=issuer or os.environ.get("AAUTH_AGENT_ISSUER"), agent_id=agent_id or os.environ.get("AAUTH_AGENT_ID"), path=p)

    def to_dict(self) -> Dict[str, Any]:
        d: Dict[str, Any] = {"version": 1, "issuer": self.issuer, "agent_id": self.agent_id, "name": self.name}
        if self.callback_endpoint:
            d["callback_endpoint"] = self.callback_endpoint
        d.update({"ap": self.provider_key, "agent": self.agent_key, "created_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())})
        return d

    def save(self, path: Optional[str] = None, overwrite: bool = False) -> str:
        """Write the identity with mode 600 (refuses to replace an existing file unless overwrite)."""
        p = os.path.expanduser(path or self.path or default_identity_path())
        os.makedirs(os.path.dirname(os.path.abspath(p)), mode=0o700, exist_ok=True)
        flags = os.O_WRONLY | os.O_CREAT | (os.O_TRUNC if overwrite else os.O_EXCL)
        fd = os.open(p, flags, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(self.to_dict(), f, indent=2)
            f.write("\n")
        self.path = p
        return p

    def provider_documents(self) -> Dict[str, Dict[str, Any]]:
        """The two public documents, keyed by path: serve them at {issuer}{path} over https."""
        meta: Dict[str, Any] = {"issuer": self.issuer, "jwks_uri": f"{self.issuer}/jwks.json"}
        if self.name:
            meta["name"] = self.name
        if self.callback_endpoint:
            meta["callback_endpoint"] = self.callback_endpoint
        return {"/.well-known/aauth-agent.json": meta, "/jwks.json": {"keys": [public_jwk(self.provider_key)]}}

    def tokens_path(self) -> str:
        if os.environ.get("AAUTH_TOKENS"):
            return os.environ["AAUTH_TOKENS"]
        base = os.path.dirname(self.path) if self.path else config_home()
        return os.path.join(base, "tokens.json")

    def agent(self, persist_tokens: bool = True, **kw: Any) -> Agent:
        """An Agent for this identity. Tokens are cached next to the identity file (tokens.json)."""
        cache = FileTokenCache(self.tokens_path()) if persist_tokens else MemoryTokenCache()
        kw.setdefault("callback", self.callback_endpoint)
        return Agent(self.issuer, agent_id=self.agent_id, provider_key=self.provider_key, agent_key=self.agent_key, token_cache=cache, **kw)
