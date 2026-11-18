"""Offline tests: JOSE primitives, structured fields, RFC 9421 signing, RFC vectors, demo fixtures.

    cd clients/python && python3 -m unittest discover -s tests -v
"""

import base64
import json
import os
import re
import unittest

from dreamfactory_aauth import jose, sf, signing
from dreamfactory_aauth.discovery import Discovery, assert_server_id
from dreamfactory_aauth.errors import AAuthError

HERE = os.path.dirname(os.path.abspath(__file__))
FIXTURES = os.path.normpath(os.path.join(HERE, "..", "..", "..", "tests", "fixtures"))
AP = "https://agent.example"

# RFC 9421 Appendix B.1.4 test-key-ed25519 (alg added, as AAuth requires)
RFC_KEY = {"kty": "OKP", "crv": "Ed25519", "kid": "test-key-ed25519", "d": "n4Ni-HpISpVObnQMW0wOhCKROaIKqKtW_2ZYb2p9KcU", "x": "JrQLj5P_89iXES9-vFgrIy29clF9CC_oPPsw3c5D0bs", "alg": "Ed25519"}


def seeded(ap_key):
    d = Discovery()
    d.seed(AP, "aauth-agent.json", {"issuer": AP, "jwks_uri": f"{AP}/jwks.json"}, {"keys": [jose.public_jwk(ap_key)]})
    return d


def agent_token(ap_key, agent_key, sub="aauth:x@agent.example", ttl=600):
    t = jose.now()
    return jose.sign_jwt("aa-agent+jwt", {"iss": AP, "dwk": "aauth-agent.json", "sub": sub, "cnf": {"jwk": jose.public_jwk(agent_key)}, "jti": jose.random_id(), "iat": t, "exp": t + ttl}, ap_key)


class Vectors(unittest.TestCase):
    def test_rfc8037_thumbprint(self):
        self.assertEqual(jose.jwk_thumbprint({"kty": "OKP", "crv": "Ed25519", "x": "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"}), "kPrK_qmxVWaYVA9wwBF6Iuo3vVzz7TxHCTwXBygrS4k")

    def test_rfc9530_digest(self):
        self.assertEqual(signing.content_digest(b'{"hello": "world"}'), "sha-256=:X48E9qOokqqrvdts8nOJRJN3OWDUoyWxBf7kbu9DBPE=:")

    def test_rfc9421_b26_ed25519(self):
        params = '("date" "@method" "@path" "@authority" "content-type" "content-length");created=1618884473;keyid="test-key-ed25519"'
        member = sf.parse_dictionary(f"sig-b26={params}")["sig-b26"]
        self.assertEqual(member.raw, params)
        comps = [i.value for i in member.items]
        headers = {"date": "Tue, 20 Apr 2021 02:07:55 GMT", "content-type": "application/json", "content-length": "18"}
        base = signing.signature_base(comps, member.raw, "POST", "https://example.com/foo?param=Value&Pet=dog", headers)
        self.assertEqual(
            base,
            "\n".join(
                [
                    '"date": Tue, 20 Apr 2021 02:07:55 GMT',
                    '"@method": POST',
                    '"@path": /foo',
                    '"@authority": example.com',
                    '"content-type": application/json',
                    '"content-length": 18',
                    f'"@signature-params": {params}',
                ]
            ),
        )
        sig = jose.sign_bytes(base.encode(), RFC_KEY)
        self.assertEqual(base64.b64encode(sig).decode(), "wqcAqbmYJ2ji2glfAMaRy4gruYYnx2nEFN2HN6jrnDnQCK1u02Gb04v9EDgwUPiu4A0w6vuQv5lIp5WPpBKRCw==")
        self.assertTrue(jose.verify_bytes(base.encode(), sig, jose.public_jwk(RFC_KEY)))


class Keys(unittest.TestCase):
    def test_generate_public_thumbprint(self):
        for alg in ("Ed25519", "ES256"):
            k = jose.generate_jwk(alg)
            self.assertEqual(k["alg"], alg)
            self.assertEqual(k["kid"], jose.jwk_thumbprint(k)[:16])
            pub = jose.public_jwk(k)
            self.assertNotIn("d", pub)
            sig = jose.sign_bytes(b"hello", k)
            self.assertEqual(len(sig), 64)
            self.assertTrue(jose.verify_bytes(b"hello", sig, pub))
            self.assertFalse(jose.verify_bytes(b"hellO", sig, pub))

    def test_alg_rules(self):
        k = jose.generate_jwk()
        with self.assertRaises(AAuthError):
            jose.alg_of({**k, "alg": None})
        with self.assertRaises(AAuthError):
            jose.alg_of({**k, "alg": "ES256"})
        with self.assertRaises(AAuthError):
            jose.sign_bytes(b"x", jose.public_jwk(k))

    def test_scopes_of(self):
        self.assertEqual(jose.scopes_of("a b,c"), ["a", "b", "c"])
        self.assertEqual(jose.scopes_of("org.sales.read"), ["org.sales.read"])
        self.assertEqual(jose.scopes_of(["a b", "c"]), ["a", "b", "c"])
        t = jose.sign_jwt("x", {"scope": "x.y.z w"}, jose.generate_jwk())
        self.assertEqual(jose.scopes_of(t), ["x.y.z", "w"])

    def test_server_ids(self):
        self.assertEqual(assert_server_id("https://df.example"), "https://df.example")
        for bad in ["http://df.example", "https://df.example/", "https://DF.example", "https://df.example:8443", "https://df.example/x", "https://df.example?q"]:
            with self.assertRaises(AAuthError, msg=bad):
                assert_server_id(bad)
        self.assertTrue(assert_server_id("http://127.0.0.1:8080", insecure=True))


class Jwts(unittest.TestCase):
    def tearDown(self):
        jose.set_clock(None)

    def test_round_trip_typ_first_tamper_expired_alg(self):
        ap = jose.generate_jwk()
        d = seeded(ap)
        tok = agent_token(ap, jose.generate_jwk())
        header = jose.decode_jwt(tok)[0]
        self.assertEqual(list(header), ["alg", "typ", "kid"])
        self.assertEqual(d.verify_jwt(tok, "aa-agent+jwt")["sub"], "aauth:x@agent.example")
        with self.assertRaisesRegex(AAuthError, "invalid_jwt"):
            d.verify_jwt(tok, "aa-person+jwt")
        h, p, s = tok.split(".")
        evil = jose.b64url(json.dumps({**jose.claims(tok), "sub": "evil"}).encode())
        with self.assertRaisesRegex(AAuthError, "invalid_jwt"):
            d.verify_jwt(f"{h}.{evil}.{s}", "aa-agent+jwt")
        with self.assertRaisesRegex(AAuthError, "expired_jwt"):
            d.verify_jwt(agent_token(ap, jose.generate_jwk(), ttl=-1), "aa-agent+jwt")
        eddsa = jose.b64url(json.dumps({"alg": "EdDSA", "typ": "aa-agent+jwt", "kid": ap["kid"]}).encode())
        with self.assertRaisesRegex(AAuthError, "unsupported_algorithm"):
            d.verify_jwt(f"{eddsa}.{p}.{s}", "aa-agent+jwt")
        with self.assertRaisesRegex(AAuthError, "invalid_jwt"):
            d.verify_jwt(tok, "aa-agent+jwt", expect_iss="https://other.example")

    def test_es256(self):
        es = jose.generate_jwk("ES256")
        d = Discovery()
        d.seed("https://ps.example", "aauth-person.json", {"issuer": "https://ps.example"}, {"keys": [jose.public_jwk(es)]})
        t = jose.now()
        tok = jose.sign_jwt("aa-person+jwt", {"iss": "https://ps.example", "dwk": "aauth-person.json", "jti": "j", "iat": t, "exp": t + 60}, es)
        self.assertEqual(jose.decode_jwt(tok)[0]["alg"], "ES256")
        self.assertEqual(len(jose.decode_jwt(tok)[3]), 64)
        self.assertEqual(d.verify_jwt(tok, "aa-person+jwt")["iss"], "https://ps.example")

    def test_demo_jwt_fixture(self):
        path = os.path.join(FIXTURES, "demo-jwt.json")
        if not os.path.exists(path):
            self.skipTest("tests/fixtures/demo-jwt.json not present")
        with open(path, encoding="utf-8") as f:
            fx = json.load(f)
        jose.set_clock(lambda: fx["now"])
        d = Discovery()
        d.seed(fx["issuer"], fx["dwk"], fx["metadata"], fx["jwks"])
        c = d.verify_jwt(fx["jwt"], fx["typ"])
        self.assertEqual(c, fx["payload"])
        self.assertEqual(jose.jwk_thumbprint(c["cnf"]["jwk"]), fx["cnf_jkt"])


class StructuredFields(unittest.TestCase):
    def test_requirement_and_errors(self):
        self.assertEqual(sf.parse_requirement('requirement=auth-token; resource-token="eyJ.a.b"'), {"requirement": "auth-token", "resource-token": "eyJ.a.b"})
        self.assertEqual(
            sf.parse_requirement('requirement=interaction;url="https://ps.example/interact";code="A1B2-C3D4"'),
            {"requirement": "interaction", "url": "https://ps.example/interact", "code": "A1B2-C3D4"},
        )
        self.assertEqual(sf.parse_requirement("garbage ;;"), {})
        self.assertEqual(sf.parse_requirement(""), {})
        self.assertEqual(
            sf.parse_signature_error('error=invalid_input, required_input=("@method" "content-digest")'),
            {"error": "invalid_input", "required_input": ["@method", "content-digest"]},
        )

    def test_dictionary(self):
        d = sf.parse_dictionary('sig=("@method" "@path");created=1730217600;expires=1730217660, other=:aGk=:, f=?1')
        self.assertEqual([i.value for i in d["sig"].items], ["@method", "@path"])
        self.assertEqual(d["sig"].params, {"created": 1730217600, "expires": 1730217660})
        self.assertEqual(d["sig"].raw, '("@method" "@path");created=1730217600;expires=1730217660')
        self.assertEqual(d["other"].value.value, b"hi")
        self.assertIs(d["f"].value, True)
        k = sf.parse_dictionary('sig=jwt;jwt="a.b.c"')["sig"]
        self.assertIsInstance(k.value, sf.Token)
        self.assertEqual(k.params["jwt"], "a.b.c")
        self.assertEqual(sf.serialize_string('a"b\\c'), '"a\\"b\\\\c"')
        for bad in ['sig=("a"', 'sig="unterminated', "sig=:@@:", "Sig=1"]:
            with self.assertRaises(sf.SfError, msg=bad):
                sf.parse_dictionary(bad)


class Signing(unittest.TestCase):
    def setUp(self):
        self.ap = jose.generate_jwk()
        self.key = jose.generate_jwk()
        self.d = seeded(self.ap)
        self.token = agent_token(self.ap, self.key)
        self.vt = lambda t, typ: self.d.verify_jwt(t, typ)

    def tearDown(self):
        jose.set_clock(None)

    def verify(self, s, **kw):
        return signing.verify_request(s.method, s.url, s.headers, s.body, verify_token=self.vt, **kw)

    def test_wire_form_and_round_trip(self):
        s = signing.sign_request("PATCH", "https://df.example/api/v2/sales/_table/orders?limit=5&filter=a%20b", token=self.token, key=self.key, body={"status": "x"})
        self.assertEqual(s.headers["signature-key"], f'sig=jwt;jwt="{self.token}"')
        self.assertRegex(s.headers["signature-input"], r'^sig=\("@method" "@authority" "@path" "signature-key" "@query" "content-type" "content-digest"\);created=\d+$')
        self.assertRegex(s.headers["signature"], r"^sig=:[A-Za-z0-9+/]+=*:$")
        self.assertIn('"@query": ?limit=5&filter=a%20b', s.base)
        self.assertIn('"@authority": df.example', s.base)
        self.assertEqual(s.body, b'{"status":"x"}')
        self.assertEqual(s.headers["content-type"], "application/json")
        v = self.verify(s, require_query=True)
        self.assertEqual(v["jkt"], jose.jwk_thumbprint(self.key))
        self.assertEqual(v["typ"], "aa-agent+jwt")

    def test_declared_components(self):
        s = signing.sign_request("GET", "https://df.example/x", token=self.token, key=self.key, additional=["@query", "content-type", "content-digest", "x-missing"])
        self.assertIn('"@query" ', s.headers["signature-input"].replace(")", " )"))
        self.assertIn('"@query": ?', s.base)
        self.assertNotIn("content-type", s.headers["signature-input"])
        self.verify(s)
        p = signing.sign_request("GET", "https://DF.example:443/x", token=self.token, key=self.key)
        self.assertIn('"@authority": df.example\n', p.base)
        q = signing.sign_request("GET", "http://127.0.0.1:8080/x", token=self.token, key=self.key)
        self.assertIn('"@authority": 127.0.0.1:8080\n', q.base)

    def test_tampering(self):
        s = signing.sign_request("POST", "https://df.example/api?a=1", token=self.token, key=self.key, body={"a": 1})
        cases = {
            "body": dict(body=b'{"a":2}'),
            "query": dict(url="https://df.example/api?a=2"),
            "authority": dict(url="https://df2.example/api?a=1"),
            "path": dict(url="https://df.example/apix?a=1"),
            "method": dict(method="PUT"),
        }
        for name, change in cases.items():
            with self.assertRaisesRegex(AAuthError, "invalid_signature", msg=name):
                signing.verify_request(change.get("method", s.method), change.get("url", s.url), s.headers, change.get("body", s.body), verify_token=self.vt)
        other = signing.sign_request("GET", "https://df.example/x", token=self.token, key=jose.generate_jwk())
        with self.assertRaisesRegex(AAuthError, "invalid_signature"):
            self.verify(other)
        stale = signing.sign_request("GET", "https://df.example/x", token=self.token, key=self.key, created=jose.now() - 120)
        with self.assertRaisesRegex(AAuthError, "invalid_signature"):
            self.verify(stale)
        future = signing.sign_request("GET", "https://df.example/x", token=self.token, key=self.key, created=jose.now() + 120)
        with self.assertRaisesRegex(AAuthError, "clock_skew"):
            self.verify(future)
        noq = signing.sign_request("GET", "https://df.example/x?a=1", token=self.token, key=self.key, query=False)
        with self.assertRaisesRegex(AAuthError, "invalid_input"):
            self.verify(noq, require_query=True)
        seen = set()
        self.verify(s, replay=seen)
        with self.assertRaisesRegex(AAuthError, "Replayed"):
            self.verify(s, replay=seen)
        bad_scheme = dict(s.headers, **{"signature-key": "sig=hwk;kty=OKP"})
        with self.assertRaisesRegex(AAuthError, "unsupported_scheme"):
            signing.verify_request(s.method, s.url, bad_scheme, s.body, verify_token=self.vt)

    def test_replay_set_keys_on_what_was_signed(self):
        """A malleated ES256 twin (r, n - s) over the same request is a replay, not a new request."""
        n = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
        key = jose.generate_jwk("ES256")
        token = agent_token(self.ap, key)
        s = signing.sign_request("POST", "https://df.example/api/v2/x", token=token, key=key, body={"a": 1})
        raw = base64.b64decode(re.match(r"sig=:([^:]+):", s.headers["signature"]).group(1))
        twin = raw[:32] + (n - int.from_bytes(raw[32:], "big")).to_bytes(32, "big")
        self.assertNotEqual(twin, raw)
        changed = dict(s.headers, signature=f"sig=:{base64.b64encode(twin).decode()}:")
        signing.verify_request(s.method, s.url, changed, s.body, verify_token=self.vt)  # valid on its own
        seen = set()
        self.verify(s, replay=seen)
        with self.assertRaisesRegex(AAuthError, "Replayed"):
            signing.verify_request(s.method, s.url, changed, s.body, verify_token=self.vt, replay=seen)

    def test_demo_signed_request_fixture(self):
        """Requests signed by the AAuth reference demo's own code verify here, and every tampered variant fails."""
        path = os.path.join(FIXTURES, "demo-signed-request.json")
        if not os.path.exists(path):
            self.skipTest("tests/fixtures/demo-signed-request.json not present")
        with open(path, encoding="utf-8") as f:
            fx = json.load(f)
        ap = fx["agent_provider"]
        d = Discovery()
        d.seed(ap["issuer"], ap["dwk"], ap["metadata"], ap["jwks"])

        def check(target, change, at, **kw):
            r = dict(fx[target])
            jose.set_clock(lambda: at)
            method = change.get("method", r["method"])
            authority = change.get("authority", r["authority"])
            path_ = change.get("path", r["path"])
            query = change.get("query", r.get("query"))
            url = f"https://{authority}{path_}" + (f"?{query}" if query else "")
            body = change.get("body", r.get("body"))
            return signing.verify_request(method, url, r["headers"], body.encode() if isinstance(body, str) else None, verify_token=lambda t, typ: d.verify_jwt(t, typ), **kw)

        v = check("request", {}, fx["now"])
        self.assertEqual(v["components"], fx["expect"]["components"])
        self.assertEqual(v["jkt"], fx["agent_jkt"])
        self.assertEqual(check("get_request", {}, fx["now"])["components"], fx["expect"]["get_components"])
        for n in fx["negative"]:
            with self.assertRaisesRegex(AAuthError, n["error"], msg=n["name"]):
                check(n["target"], n.get("change", {}), n.get("now", fx["now"]), require_query=n.get("require_query", False))


if __name__ == "__main__":
    unittest.main()
