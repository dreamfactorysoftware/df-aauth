"""RFC 9421 HTTP message signatures in the AAuth profile (draft-hardt-httpbis-signature-key-09).

Every AAuth request carries three headers with the label ``sig``::

    Signature-Key:   sig=jwt;jwt="<agent, person or auth token>"
    Signature-Input: sig=("@method" "@authority" "@path" "signature-key" ...);created=<unix time>
    Signature:       sig=:<base64 signature over the signature base>:

The key that signs is the one in the token's ``cnf.jwk``. A request with a body also covers
``content-type`` and ``content-digest`` (RFC 9530, sha-256). ``@query`` is covered whenever the URL
has a query string, or when the resource lists it in ``additional_signature_components``.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any, Callable, Dict, Iterable, List, Optional, Sequence
from urllib.parse import urlsplit

from .errors import AAuthError
from .jose import Jwk, b64std, decode_jwt, jwk_thumbprint, now, sha256, sign_bytes, verify_bytes
from .sf import ByteSeq, InnerList, Item, SfError, Token, parse_dictionary

BASE_COMPONENTS = ("@method", "@authority", "@path", "signature-key")
_DERIVED = ("@method", "@authority", "@path", "@target-uri")
_DEFAULT_PORTS = {"https": 443, "http": 80}


def _sig_error(code: str, detail: str) -> AAuthError:
    return AAuthError(code, detail, 401)


def content_digest(body: bytes) -> str:
    """RFC 9530 Content-Digest for the exact body bytes."""
    return f"sha-256=:{b64std(sha256(body))}:"


def authority(url: str) -> str:
    """host[:port] in lowercase, without userinfo, default port dropped (what the server sees as Host)."""
    u = urlsplit(url)
    host = (u.hostname or "").lower()
    if ":" in host:
        host = f"[{host}]"
    port = u.port
    if port and port != _DEFAULT_PORTS.get(u.scheme.lower()):
        return f"{host}:{port}"
    return host


def signature_base(components: Sequence[str], params: str, method: str, url: str, headers: Dict[str, str]) -> str:
    """The RFC 9421 signature base. ``headers`` must have lowercase names."""
    u = urlsplit(url)
    lines = []
    for c in components:
        if c == "@method":
            v = method.upper()
        elif c == "@authority":
            v = authority(url)
        elif c == "@path":
            v = u.path or "/"
        elif c == "@query":
            v = f"?{u.query}" if u.query else "?"
        elif c == "@target-uri":
            v = url
        elif c.startswith("@"):
            raise _sig_error("invalid_input", f"Unsupported derived component {c}")
        else:
            if c not in headers:
                raise _sig_error("invalid_input", f"Covered component {c} is missing")
            v = str(headers[c]).strip()
        lines.append(f'"{c}": {v}')
    lines.append(f'"@signature-params": {params}')
    return "\n".join(lines)


@dataclass
class SignedRequest:
    method: str
    url: str
    headers: Dict[str, str]
    body: Optional[bytes]
    base: str


def encode_body(body: Any) -> Optional[bytes]:
    if body is None:
        return None
    if isinstance(body, bytes):
        return body
    if isinstance(body, str):
        return body.encode("utf-8")
    return json.dumps(body, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def sign_request(
    method: str,
    url: str,
    *,
    token: str,
    key: Jwk,
    body: Any = None,
    headers: Optional[Dict[str, str]] = None,
    additional: Iterable[str] = (),
    created: Optional[int] = None,
    query: Optional[bool] = None,
    components: Optional[List[str]] = None,
) -> SignedRequest:
    """Sign a request. ``url`` must be final (already encoded, query included): it is signed as is.

    body: None, bytes, str, or a JSON-serializable object (sent as compact JSON).
    additional: the resource's ``additional_signature_components``; the ones present are covered.
    created / query / components: overrides for tests.
    """
    h = {k.lower(): str(v) for k, v in (headers or {}).items()}
    data = encode_body(body)
    if data is not None:
        h.setdefault("content-type", "application/json")
        h["content-digest"] = content_digest(data)
    h["signature-key"] = f'sig=jwt;jwt="{token}"'
    declared = [str(c).lower() for c in (additional or [])]
    if components is None:
        has_query = bool(urlsplit(url).query)
        covered = list(BASE_COMPONENTS)
        if (query if query is not None else (has_query or "@query" in declared)):
            covered.append("@query")
        if data is not None:
            covered += ["content-type", "content-digest"]
        for c in declared:
            if c in covered or c in ("signature-key", "signature", "signature-input"):
                continue
            if c.startswith("@"):
                if c in _DERIVED:
                    covered.append(c)
            elif c in h:
                covered.append(c)
    else:
        covered = list(components)
    params = "(" + " ".join(f'"{c}"' for c in covered) + f");created={created if created is not None else now()}"
    base = signature_base(covered, params, method, url, h)
    h["signature-input"] = f"sig={params}"
    h["signature"] = f"sig=:{b64std(sign_bytes(base.encode('utf-8'), key))}:"
    return SignedRequest(method.upper(), url, h, data, base)


TOKEN_TYPES = ("aa-agent+jwt", "aa-person+jwt", "aa-auth+jwt", "aa-resource+jwt")


def verify_request(
    method: str,
    url: str,
    headers: Dict[str, str],
    body: Optional[bytes],
    *,
    verify_token: Callable[[str, str], Dict[str, Any]],
    accept: Sequence[str] = ("aa-agent+jwt", "aa-person+jwt", "aa-auth+jwt"),
    window: int = 60,
    require_query: bool = False,
    replay: Optional[set] = None,
) -> Dict[str, Any]:
    """Verify an AAuth-signed request (what a resource does; used by the tests and mocks).

    verify_token(token, typ) must verify the JWT (signature, typ, exp) and return its claims.
    Returns {"token", "typ", "claims", "jwk", "jkt", "components", "created"}. Raises AAuthError.
    """
    h = {k.lower(): v for k, v in headers.items()}
    data = body or b""
    for name in ("signature-key", "signature-input", "signature"):
        if name not in h:
            raise _sig_error("invalid_signature", "Missing Signature, Signature-Input or Signature-Key")
    try:
        sk = parse_dictionary(h["signature-key"])
        si = parse_dictionary(h["signature-input"])
        sg = parse_dictionary(h["signature"])
    except SfError as e:
        raise _sig_error("invalid_signature", str(e)) from None
    label = next((k for k in si if k in sk and k in sg), None)
    if not label:
        raise _sig_error("invalid_signature", "No label present in all three signature headers")
    km = sk[label]
    if isinstance(km, InnerList) or not isinstance(km.value, Token) or km.value != "jwt":
        raise _sig_error("unsupported_scheme", "Use the jwt Signature-Key scheme")
    token = km.params.get("jwt")
    if not isinstance(token, str) or isinstance(token, Token):
        raise _sig_error("invalid_key", "jwt parameter missing")
    inp = si[label]
    if not isinstance(inp, InnerList):
        raise _sig_error("invalid_signature", "Signature-Input member is not an inner list")
    comps = [i.value for i in inp.items]
    if any(not isinstance(c, str) or isinstance(c, Token) for c in comps):
        raise _sig_error("invalid_signature", "Components must be strings")
    required = list(BASE_COMPONENTS)
    if data:
        required += ["content-type", "content-digest"]
    if require_query and urlsplit(url).query:
        required.append("@query")
    missing = [c for c in required if c not in comps]
    if missing:
        raise _sig_error("invalid_input", "Signature must cover: " + ", ".join(missing))
    created = inp.params.get("created")
    t = now()
    if not isinstance(created, int) or isinstance(created, bool):
        raise _sig_error("invalid_signature", "created missing")
    if created < t - window:
        raise _sig_error("invalid_signature", "Signature is older than the window")
    if created > t + window:
        raise _sig_error("clock_skew", "Signature created in the future")
    expires = inp.params.get("expires")
    if isinstance(expires, int) and expires < t:
        raise _sig_error("invalid_signature", "Signature expired")
    if data and h.get("content-digest") != content_digest(data):
        raise _sig_error("invalid_signature", "Content-Digest does not match the body")
    header = decode_jwt(token)[0]
    typ = header.get("typ")
    if typ not in accept:
        raise _sig_error("invalid_jwt", f"Unexpected token type {typ}")
    c = verify_token(token, typ)
    jwk = (c.get("cnf") or {}).get("jwk")
    if not jwk:
        raise _sig_error("invalid_jwt", "Token has no cnf.jwk")
    sv = sg[label]
    if not isinstance(sv, Item) or not isinstance(sv.value, ByteSeq):
        raise _sig_error("invalid_signature", "Malformed Signature")
    base = signature_base(comps, inp.raw, method, url, h)
    if not verify_bytes(base.encode("utf-8"), sv.value.value, jwk):
        raise _sig_error("invalid_signature", "HTTP message signature is invalid")
    jkt = jwk_thumbprint(jwk)
    if replay is not None:
        # keyed on what was signed (key + signature base), never on the signature's encoding: ES256
        # signatures are malleable ((r, s) and (r, n - s) both verify)
        k = sha256(jkt + "\n" + base).hex()
        if k in replay:
            raise _sig_error("invalid_signature", "Replayed signature")
        replay.add(k)
    return {"token": token, "typ": typ, "claims": c, "jwk": jwk, "jkt": jkt, "components": comps, "created": created}
