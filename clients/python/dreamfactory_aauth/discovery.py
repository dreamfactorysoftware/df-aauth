"""AAuth discovery: {issuer}/.well-known/<doc>.json + its jwks_uri, and JWT verification with them."""

from __future__ import annotations

import time
from typing import Any, Dict, Optional, Tuple
from urllib.parse import urlsplit

import requests

from .errors import AAuthError
from .jose import Jwk, decode_jwt, now, verify_bytes

# Which well-known document holds the keys for each token type.
TOKEN_DWK = {
    "aa-agent+jwt": ("aauth-agent.json",),
    "aa-person+jwt": ("aauth-person.json",),
    "aa-auth+jwt": ("aauth-person.json",),  # PS-issued (an AS would use aauth-access.json)
    "aa-resource+jwt": ("aauth-resource.json",),
}


def _sig_error(code: str, detail: str) -> AAuthError:
    return AAuthError(code, detail, 401)


def assert_server_id(server_id: str, insecure: bool = False) -> str:
    """Server identifiers are bare https origins: lowercase host, no port, path, query or trailing slash.

    insecure=True also allows http:// and ports (local testing only).
    """
    try:
        u = urlsplit(server_id)
        port = u.port
    except ValueError:
        raise _sig_error("issuer_mismatch", f"Not a URL: {server_id}") from None
    if u.scheme != "https" and not (insecure and u.scheme == "http"):
        raise _sig_error("issuer_mismatch", f"Server identifiers must be https: {server_id}")
    if not u.hostname or u.path or u.query or u.fragment or u.username or server_id != server_id.lower() or server_id.endswith("/"):
        raise _sig_error("issuer_mismatch", f"Server identifier must be a bare lowercase origin: {server_id}")
    if port is not None and not insecure:
        raise _sig_error("issuer_mismatch", f"Server identifier must not carry a port: {server_id}")
    return server_id


def origin_of(url: str) -> str:
    u = urlsplit(url)
    host = (u.hostname or "").lower()
    if ":" in host:
        host = f"[{host}]"
    default = {"https": 443, "http": 80}.get(u.scheme)
    port = f":{u.port}" if u.port and u.port != default else ""
    return f"{u.scheme}://{host}{port}"


class Discovery:
    """Fetches and caches issuer metadata and JWKS. ``seed()`` pre-loads documents (tests, pinned keys)."""

    def __init__(self, session: Optional[requests.Session] = None, insecure: bool = False, ttl: int = 300, timeout: float = 10):
        self.session = session or requests.Session()
        self.insecure = insecure
        self.ttl = ttl
        self.timeout = timeout
        self._cache: Dict[str, Tuple[float, Any]] = {}
        self._seeded: Dict[Tuple[str, str], Tuple[dict, dict]] = {}

    def seed(self, iss: str, dwk: str, meta: dict, jwks: dict) -> None:
        self._seeded[(iss, dwk)] = (meta, jwks)

    def json(self, url: str, fresh: bool = False) -> Any:
        hit = self._cache.get(url)
        if hit and not fresh and hit[0] > time.monotonic():
            return hit[1]
        r = self.session.get(url, headers={"accept": "application/json"}, allow_redirects=False, timeout=self.timeout)
        if r.status_code != 200:
            raise _sig_error("unknown_key", f"GET {url} returned {r.status_code}")
        try:
            value = r.json()
        except ValueError:
            raise _sig_error("unknown_key", f"GET {url} did not return JSON") from None
        self._cache[url] = (time.monotonic() + self.ttl, value)
        return value

    def metadata(self, iss: str, dwk: str) -> dict:
        seeded = self._seeded.get((iss, dwk))
        if seeded:
            return seeded[0]
        assert_server_id(iss, self.insecure)
        meta = self.json(f"{iss}/.well-known/{dwk}")
        if not isinstance(meta, dict) or not isinstance(meta.get("issuer"), str):
            raise _sig_error("issuer_missing", f"{iss}/.well-known/{dwk} has no issuer")
        if meta["issuer"] != iss:
            raise _sig_error("issuer_mismatch", f"Metadata issuer {meta['issuer']} != {iss}")
        return meta

    def key(self, iss: str, dwk: str, kid: Optional[str]) -> Tuple[Jwk, dict]:
        meta = self.metadata(iss, dwk)
        seeded = self._seeded.get((iss, dwk))

        def pick(jwks: Any) -> Optional[Jwk]:
            for k in (jwks or {}).get("keys", []) if isinstance(jwks, dict) else []:
                if isinstance(k, dict) and k.get("kid") == kid:
                    return k
            return None

        if seeded:
            k = pick(seeded[1])
            if not k:
                raise _sig_error("unknown_key", f"No key {kid}")
            return k, meta
        uri = meta.get("jwks_uri")
        if not isinstance(uri, str):
            raise _sig_error("unknown_key", f"{iss} metadata has no jwks_uri")
        k = pick(self.json(uri)) or pick(self.json(uri, fresh=True))
        if not k:
            raise _sig_error("unknown_key", f"No key {kid} in {uri}")
        return k, meta

    def verify_jwt(self, token: str, typ: str, expect_iss: Optional[str] = None) -> Dict[str, Any]:
        """Verify typ (first), dwk, issuer discovery, signature, exp and iat. Returns the claims.

        expect_iss: refuse before any network call when the token names another issuer.
        """
        header, payload, signing_input, sig = decode_jwt(token)
        if header.get("typ") != typ:
            raise _sig_error("invalid_jwt", f"Expected typ {typ}, got {header.get('typ')}")
        if payload.get("dwk") not in TOKEN_DWK.get(typ, ()):
            raise _sig_error("invalid_jwt", f"Unexpected dwk {payload.get('dwk')} for {typ}")
        iss = payload.get("iss")
        if not isinstance(iss, str) or not iss:
            raise _sig_error("issuer_missing", "JWT has no iss")
        if expect_iss is not None and iss != expect_iss:
            raise _sig_error("invalid_jwt", f"iss {iss} is not {expect_iss}")
        if header.get("alg") in (None, "none", "EdDSA"):
            raise _sig_error("unsupported_algorithm", f"alg {header.get('alg')}")
        key, _ = self.key(iss, payload["dwk"], header.get("kid"))
        if header.get("alg") != key.get("alg"):
            raise _sig_error("unsupported_algorithm", "JWT alg does not match key alg")
        if not verify_bytes(signing_input, sig, key):
            raise _sig_error("invalid_jwt", "JWT signature is invalid")
        t = now()
        exp = payload.get("exp")
        if not isinstance(exp, int) or exp <= t:
            raise _sig_error("expired_jwt", "Token has expired")
        iat = payload.get("iat")
        if not isinstance(iat, int):
            raise _sig_error("invalid_jwt", "Token has no iat")
        if iat > t + 60:
            raise _sig_error("clock_skew", "Token iat is in the future")
        return payload
