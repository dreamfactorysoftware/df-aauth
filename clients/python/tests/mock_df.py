"""A mock AAuth resource + Person Server on one origin (http://127.0.0.1:<port>) for offline tests.

    mock = MockDF(ap_key)            # ap_key: the agent provider key agents sign tokens with
    mock.decide(code, "allow"|"deny", always=False)   # plays the person
    mock.close()

Resource: GET /api/data needs scope "read", any other method "write"; POST /authorize (§6.6).
"""

import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit

from dreamfactory_aauth import jose
from dreamfactory_aauth.discovery import Discovery
from dreamfactory_aauth.errors import AAuthError
from dreamfactory_aauth.signing import verify_request

AP = "https://agent.example"


class MockDF:
    def __init__(self, ap_key, ap_issuer=AP, bad_resource_tokens=False):
        self.r_key = jose.generate_jwk()
        self.p_key = jose.generate_jwk()
        self.pending = {}
        self.grants = set()
        self.log = []
        self.bad_rt = bad_resource_tokens
        self.lock = threading.Lock()
        mock = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def do_GET(self):
                mock.handle(self)

            do_POST = do_PATCH = do_PUT = do_DELETE = do_GET

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.origin = f"http://127.0.0.1:{self.server.server_address[1]}"
        self.disc = Discovery(insecure=True)
        self.disc.seed(ap_issuer, "aauth-agent.json", {"issuer": ap_issuer, "jwks_uri": f"{ap_issuer}/jwks.json"}, {"keys": [jose.public_jwk(ap_key)]})
        self.disc.seed(self.origin, "aauth-resource.json", {"issuer": self.origin}, {"keys": [jose.public_jwk(self.r_key)]})
        self.disc.seed(self.origin, "aauth-person.json", {"issuer": self.origin}, {"keys": [jose.public_jwk(self.p_key)]})
        self.thread = threading.Thread(target=self.server.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True)
        self.thread.start()

    def close(self):
        self.server.shutdown()
        self.server.server_close()

    def decide(self, code, decision="allow", always=False):
        with self.lock:
            entry = next((e for e in self.pending.values() if e["code"] == code), None)
            assert entry, f"no pending request with code {code}"
            entry["status"] = "approved" if decision == "allow" else "denied"
            if entry["status"] == "approved" and always:
                self.grants.add(entry.get("grant"))

    def mint(self, typ, key, payload):
        t = jose.now()
        return jose.sign_jwt(typ, {"jti": jose.random_id(), "iat": t, "exp": t + 600, **payload}, key)

    def handle(self, h):
        u = urlsplit(h.path)
        p = u.path
        n = int(h.headers.get("content-length") or 0)
        body = h.rfile.read(n) if n else b""
        self.log.append(f"{h.command} {p}")
        o = self.origin

        def send(status, obj, headers=None):
            data = json.dumps(obj).encode()
            h.send_response(status)
            h.send_header("content-type", "application/problem+json" if status >= 400 else "application/json")
            h.send_header("content-length", str(len(data)))
            for k, v in (headers or {}).items():
                h.send_header(k, v)
            h.end_headers()
            h.wfile.write(data)

        def defer(kind, v, **extra):
            pid = jose.random_id(12)
            code = f"{jose.random_id(3).upper()[:4]}-{jose.random_id(3).upper()[:4]}"
            with self.lock:
                self.pending[pid] = {"kind": kind, "code": code, "status": "pending", "jkt": v["jkt"], **extra}
            send(202, {"status": "pending"}, {"location": f"/pending/{pid}", "retry-after": "0", "cache-control": "no-store", "aauth-requirement": f'requirement=interaction; url="{o}/interact"; code="{code}"'})

        def resource_token(v, scope):
            c = v["claims"]
            aud = c.get("ps") if v["typ"] == "aa-auth+jwt" else c.get("iss")
            jkt = "x" * 43 if self.bad_rt else v["jkt"]
            return self.mint("aa-resource+jwt", self.r_key, {"iss": o, "dwk": "aauth-resource.json", "aud": aud, "ps": o, "sub": c.get("sub"), "presented_jti": c.get("jti"), "agent_jkt": jkt, "scope": scope})

        try:
            if p == "/.well-known/aauth-resource.json":
                return send(200, {"issuer": o, "jwks_uri": f"{o}/jwks/r", "authorization_endpoint": f"{o}/authorize", "scope_descriptions": {"read": "Read", "write": "Write"}, "additional_signature_components": ["@query", "content-type", "content-digest"]})
            if p == "/.well-known/aauth-person.json":
                return send(200, {"issuer": o, "jwks_uri": f"{o}/jwks/p", "person_token_endpoint": f"{o}/person", "auth_token_endpoint": f"{o}/token", "interaction_endpoint": f"{o}/interact"})
            if p == "/jwks/r":
                return send(200, {"keys": [jose.public_jwk(self.r_key)]})
            if p == "/jwks/p":
                return send(200, {"keys": [jose.public_jwk(self.p_key)]})
            headers = {k.lower(): v for k, v in h.headers.items()}
            v = verify_request(h.command, f"{o}{h.path}", headers, body, verify_token=lambda t, typ: self.disc.verify_jwt(t, typ), require_query=True)
            c = v["claims"]
            if p.startswith("/pending/"):
                pid = p.split("/")[2]
                with self.lock:
                    e = self.pending.get(pid)
                    if not e or e["jkt"] != v["jkt"]:
                        return send(404, {"error": "not_found"})
                    if h.command == "DELETE":
                        del self.pending[pid]
                        return send(200, {"status": "cancelled"})
                    if e["status"] == "pending":
                        return send(202, {"status": "pending"}, {"retry-after": "0", "cache-control": "no-store"})
                    if e["status"] == "denied":
                        return send(403, {"error": "denied"})
                    if e["status"] == "delivered":
                        return send(410, {"error": "invalid_code"})
                    e["status"] = "delivered"
                    return send(200, {f"{e['kind']}_token": e["token"]})
            if p == "/person":
                b = json.loads(body)
                tok = self.mint("aa-person+jwt", self.p_key, {"iss": o, "dwk": "aauth-person.json", "aud": b["resource"], "sub": "pairwise-1", "cnf": {"jwk": v["jwk"]}})
                return defer("person", v, token=tok)
            if p == "/token":
                b = json.loads(body)
                rt = self.disc.verify_jwt(b["resource_token"], "aa-resource+jwt")
                presented = jose.claims(b["presented_token"])
                if rt["presented_jti"] != presented["jti"] or rt["agent_jkt"] != v["jkt"]:
                    return send(400, {"error": "invalid_resource_token"})
                tok = self.mint("aa-auth+jwt", self.p_key, {"iss": o, "dwk": "aauth-person.json", "aud": rt["iss"], "ps": o, "sub": rt["sub"], "scope": rt["scope"], "cnf": {"jwk": v["jwk"]}})
                grant = f"{rt['sub']}|{c['sub']}|{rt['scope']}"
                if grant in self.grants:
                    return send(200, {"auth_token": tok, "expires_in": 600})
                return defer("auth", v, token=tok, grant=grant)
            if p == "/authorize":
                if v["typ"] == "aa-agent+jwt":
                    return send(401, {"error": "person_token_required"}, {"aauth-requirement": "requirement=person-token"})
                scope = str(json.loads(body or b"{}").get("scope") or "").strip()
                unknown = [s for s in scope.split() if s not in ("read", "write")]
                if not scope or unknown:
                    return send(400, {"error": "invalid_scope", "detail": f"Unknown scope: {' '.join(unknown)}"})
                return send(200, {"resource_token": resource_token(v, scope)})
            if p == "/api/data":
                need = "read" if h.command == "GET" else "write"
                if v["typ"] == "aa-agent+jwt":
                    return send(401, {"error": "person_token_required"}, {"aauth-requirement": "requirement=person-token"})
                granted = (c.get("scope") or "").split() if v["typ"] == "aa-auth+jwt" else []
                if need in granted:
                    return send(200, {"ok": True, "method": h.command, "scope": need, "query": parse_qs(u.query), "body": json.loads(body) if body else None})
                scope = " ".join(dict.fromkeys(granted + [need]))
                return send(401, {"error": "auth_token_required"}, {"aauth-requirement": f'requirement=auth-token; resource-token="{resource_token(v, scope)}"'})
            return send(404, {"error": "not_found"})
        except AAuthError as e:
            return send(e.status or 500, {"error": e.error, "detail": e.detail}, {"signature-error": f"error={e.error}"} if e.status == 401 else {})
