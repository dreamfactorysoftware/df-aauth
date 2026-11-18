"""Keys, JWK thumbprints and JWTs for AAuth (Ed25519 and ES256 only, as the protocol requires)."""

from __future__ import annotations

import base64
import hashlib
import json
import re
import secrets
import time
from typing import Any, Callable, Dict, Optional, Tuple

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature, encode_dss_signature

from .errors import AAuthError

Jwk = Dict[str, Any]

# Seconds since the epoch. Tests replace it with set_clock().
_clock: Callable[[], int] = lambda: int(time.time())


def now() -> int:
    return _clock()


def set_clock(fn: Optional[Callable[[], int]]) -> None:
    """Test hook: fix the clock (None restores it)."""
    global _clock
    _clock = fn or (lambda: int(time.time()))


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def b64url_decode(s: str) -> bytes:
    s = str(s)
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def b64std(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def sha256(data: Any) -> bytes:
    if isinstance(data, str):
        data = data.encode("utf-8")
    return hashlib.sha256(data).digest()


def random_id(nbytes: int = 16) -> str:
    return b64url(secrets.token_bytes(nbytes))


def _json(obj: Any) -> bytes:
    return json.dumps(obj, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def _sig_error(code: str, detail: str) -> AAuthError:
    return AAuthError(code, detail, 401)


# ---------------------------------------------------------------------------
# JWKs
# ---------------------------------------------------------------------------

def jwk_thumbprint(jwk: Jwk) -> str:
    """RFC 7638 thumbprint (base64url SHA-256 of the required members, sorted, no whitespace)."""
    if jwk.get("kty") == "EC":
        members = {"crv": jwk["crv"], "kty": "EC", "x": jwk["x"], "y": jwk["y"]}
    else:
        members = {"crv": jwk["crv"], "kty": jwk["kty"], "x": jwk["x"]}
    return b64url(sha256(json.dumps(members, separators=(",", ":"), sort_keys=True)))


def _int_bytes(n: int) -> bytes:
    return n.to_bytes(32, "big")


def generate_jwk(alg: str = "Ed25519") -> Jwk:
    """A new private JWK (Ed25519 by default, or ES256) with alg and kid (first 16 chars of the thumbprint)."""
    if alg == "Ed25519":
        k = Ed25519PrivateKey.generate()
        jwk = {
            "kty": "OKP",
            "crv": "Ed25519",
            "x": b64url(k.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)),
            "d": b64url(k.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption())),
            "alg": "Ed25519",
        }
    elif alg == "ES256":
        k = ec.generate_private_key(ec.SECP256R1())
        pub = k.public_key().public_numbers()
        jwk = {"kty": "EC", "crv": "P-256", "x": b64url(_int_bytes(pub.x)), "y": b64url(_int_bytes(pub.y)), "d": b64url(_int_bytes(k.private_numbers().private_value)), "alg": "ES256"}
    else:
        raise ValueError(f"unsupported alg {alg}")
    jwk["kid"] = jwk_thumbprint(jwk)[:16]
    return jwk


def public_jwk(jwk: Jwk) -> Jwk:
    """The public half (kty, crv, x, y, alg, kid). AAuth requires alg on every key."""
    out = {"kty": jwk["kty"], "crv": jwk["crv"], "x": jwk["x"]}
    if "y" in jwk:
        out["y"] = jwk["y"]
    out["alg"] = jwk.get("alg")
    if jwk.get("kid"):
        out["kid"] = jwk["kid"]
    return out


def alg_of(jwk: Any) -> str:
    if not isinstance(jwk, dict):
        raise _sig_error("invalid_key", "Missing JWK")
    alg = jwk.get("alg")
    if not alg:
        raise _sig_error("unsupported_algorithm", "JWK has no alg")
    if alg == "Ed25519":
        if jwk.get("kty") != "OKP" or jwk.get("crv") != "Ed25519" or not jwk.get("x"):
            raise _sig_error("invalid_key", "kty/crv do not match alg Ed25519")
        return alg
    if alg == "ES256":
        if jwk.get("kty") != "EC" or jwk.get("crv") != "P-256" or not jwk.get("x") or not jwk.get("y"):
            raise _sig_error("invalid_key", "kty/crv do not match alg ES256")
        return alg
    raise _sig_error("unsupported_algorithm", f"Unsupported alg {alg}")


def _ec_public(jwk: Jwk) -> ec.EllipticCurvePublicKey:
    x = int.from_bytes(b64url_decode(jwk["x"]), "big")
    y = int.from_bytes(b64url_decode(jwk["y"]), "big")
    return ec.EllipticCurvePublicNumbers(x, y, ec.SECP256R1()).public_key()


def sign_bytes(data: bytes, jwk: Jwk) -> bytes:
    """Raw signature: 64 bytes for Ed25519, R||S (64 bytes) for ES256."""
    alg = alg_of(jwk)
    if not jwk.get("d"):
        raise AAuthError("invalid_key", "signing needs a private JWK (with d)")
    if alg == "Ed25519":
        return Ed25519PrivateKey.from_private_bytes(b64url_decode(jwk["d"])).sign(data)
    key = ec.derive_private_key(int.from_bytes(b64url_decode(jwk["d"]), "big"), ec.SECP256R1())
    r, s = decode_dss_signature(key.sign(data, ec.ECDSA(hashes.SHA256())))
    return _int_bytes(r) + _int_bytes(s)


def verify_bytes(data: bytes, sig: bytes, jwk: Jwk) -> bool:
    alg = alg_of(jwk)
    try:
        if alg == "Ed25519":
            Ed25519PublicKey.from_public_bytes(b64url_decode(jwk["x"])).verify(sig, data)
        else:
            if len(sig) != 64:
                return False
            der = encode_dss_signature(int.from_bytes(sig[:32], "big"), int.from_bytes(sig[32:], "big"))
            _ec_public(jwk).verify(der, data, ec.ECDSA(hashes.SHA256()))
        return True
    except (InvalidSignature, ValueError):
        return False


# ---------------------------------------------------------------------------
# JWTs
# ---------------------------------------------------------------------------

def sign_jwt(typ: str, payload: Dict[str, Any], jwk: Jwk) -> str:
    header = {"alg": alg_of(jwk), "typ": typ, "kid": jwk.get("kid")}
    signing_input = f"{b64url(_json(header))}.{b64url(_json(payload))}"
    return f"{signing_input}.{b64url(sign_bytes(signing_input.encode('ascii'), jwk))}"


def decode_jwt(token: str) -> Tuple[Dict[str, Any], Dict[str, Any], bytes, bytes]:
    """(header, payload, signing_input, signature) without verifying anything."""
    parts = str(token or "").split(".")
    if len(parts) != 3:
        raise _sig_error("invalid_jwt", "Malformed JWT")
    try:
        header = json.loads(b64url_decode(parts[0]))
        payload = json.loads(b64url_decode(parts[1]))
        sig = b64url_decode(parts[2])
    except Exception:
        raise _sig_error("invalid_jwt", "Malformed JWT") from None
    if not isinstance(header, dict) or not isinstance(payload, dict):
        raise _sig_error("invalid_jwt", "Malformed JWT")
    return header, payload, f"{parts[0]}.{parts[1]}".encode("ascii"), sig


def claims(token: str) -> Dict[str, Any]:
    """The payload of a JWT, unverified."""
    return decode_jwt(token)[1]


_JWT_RE = re.compile(r"^eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*$")


def scopes_of(token_or_scope: Any) -> list:
    """The scopes of a token, a space/comma separated string, or a list."""
    if not token_or_scope:
        return []
    if isinstance(token_or_scope, (list, tuple, set)):
        out = []
        for s in token_or_scope:
            out.extend(scopes_of(str(s)))
        return out
    s = str(token_or_scope)
    if _JWT_RE.match(s):
        s = str(claims(s).get("scope") or "")
    return [x for x in s.replace(",", " ").split() if x]
