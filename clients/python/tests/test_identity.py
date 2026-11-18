"""Offline tests: identity files, provider documents, agent token minting, and interop with the
Node library (agent/aauth.mjs; skipped when node or the agent directory is missing)."""

import json
import os
import shutil
import stat
import subprocess
import tempfile
import unittest

from dreamfactory_aauth import AgentIdentity, jose, mint_agent_token, sign_request, verify_request
from dreamfactory_aauth.discovery import Discovery

HERE = os.path.dirname(os.path.abspath(__file__))
NODE_LIB = os.path.normpath(os.path.join(HERE, "..", "..", "..", "agent", "aauth.mjs"))
NODE_CONFIG = os.path.normpath(os.path.join(HERE, "..", "..", "..", "agent", "config.mjs"))
NODE = shutil.which("node")


class Identity(unittest.TestCase):
    def test_generate_save_load_documents(self):
        with tempfile.TemporaryDirectory() as d:
            ident = AgentIdentity.generate("https://agents.example.com", name="Acme Reports")
            self.assertEqual(ident.agent_id, "aauth:acme-reports@agents.example.com")
            path = ident.save(os.path.join(d, "cfg", "agent.json"))
            self.assertEqual(stat.S_IMODE(os.stat(path).st_mode), 0o600)
            with self.assertRaises(FileExistsError):
                ident.save(path)
            back = AgentIdentity.load(path)
            self.assertEqual(back, ident)
            docs = back.provider_documents()
            self.assertEqual(docs["/.well-known/aauth-agent.json"], {"issuer": "https://agents.example.com", "jwks_uri": "https://agents.example.com/jwks.json", "name": "Acme Reports"})
            self.assertEqual(docs["/jwks.json"]["keys"][0], jose.public_jwk(ident.provider_key))
            self.assertNotIn("d", docs["/jwks.json"]["keys"][0])
            a = back.agent()
            self.assertEqual(a.cache.path, os.path.join(d, "cfg", "tokens.json"))
            c = jose.claims(a.agent_token("https://df.example.com"))
            self.assertEqual((c["iss"], c["sub"], c["ps"]), ("https://agents.example.com", "aauth:acme-reports@agents.example.com", "https://df.example.com"))

    def test_validation_and_legacy_keys(self):
        for bad in ("http://agents.example.com", "https://agents.example.com/x", "https://agents.example.com:8443"):
            with self.assertRaises(Exception, msg=bad):
                AgentIdentity.generate(bad)
        with self.assertRaises(ValueError):
            AgentIdentity.generate("https://a.example", local="has space")
        keys = {"ap": jose.generate_jwk(), "agent": jose.generate_jwk()}
        with self.assertRaises(ValueError):
            AgentIdentity.from_dict(keys)
        legacy = AgentIdentity.from_dict(keys, issuer="https://legacy.example", agent_id="aauth:reports@legacy.example")
        self.assertEqual(legacy.agent_id, "aauth:reports@legacy.example")
        with self.assertRaises(ValueError):
            AgentIdentity.from_dict({"issuer": "https://x.example", "ap": jose.public_jwk(keys["ap"]), "agent": keys["agent"]})

    def test_mint_agent_token(self):
        ap, key = jose.generate_jwk(), jose.generate_jwk()
        tok = mint_agent_token("https://agents.example.com", ap, "aauth:bot@agents.example.com", key, ps="https://df.example.com")
        d = Discovery()
        d.seed("https://agents.example.com", "aauth-agent.json", {"issuer": "https://agents.example.com"}, {"keys": [jose.public_jwk(ap)]})
        c = d.verify_jwt(tok, "aa-agent+jwt")
        self.assertEqual(c["cnf"]["jwk"], jose.public_jwk(key))
        self.assertLessEqual(c["exp"] - c["iat"], 3600)
        with self.assertRaises(ValueError):
            mint_agent_token("https://a.example", ap, "aauth:x@a.example", key, ttl=90000)


def node(script, *args):
    r = subprocess.run([NODE, "--input-type=module", "-e", script, *args], capture_output=True, text=True, timeout=60)
    if r.returncode != 0:
        raise AssertionError(f"node failed: {r.stderr}")
    return r.stdout


@unittest.skipUnless(NODE and os.path.exists(NODE_LIB), "node or agent/aauth.mjs not available")
class NodeInterop(unittest.TestCase):
    def test_python_signed_request_verifies_in_node(self):
        ap, key = jose.generate_jwk(), jose.generate_jwk()
        tok = mint_agent_token("https://agent.example", ap, "aauth:py@agent.example", key, ps="https://df.example")
        s = sign_request("PATCH", "https://df.example/api/v2/sales/_table/orders/7?fields=id%2Cstatus", token=tok, key=key, body={"status": "refunded", "note": "naïve \"quote\""}, additional=["@query", "content-type", "content-digest"])
        msg = {"method": s.method, "url": s.url, "headers": s.headers, "body": s.body.decode(), "ap": jose.public_jwk(ap)}
        out = node(
            """
            const { Discovery, verifySignedRequest } = await import(process.argv[1]);
            const m = JSON.parse(process.argv[2]);
            const d = new Discovery();
            d.seed('https://agent.example', 'aauth-agent.json', { issuer: 'https://agent.example', jwks_uri: 'https://agent.example/jwks.json' }, { keys: [m.ap] });
            const v = await verifySignedRequest(m, { discovery: d, requireQuery: true });
            console.log(JSON.stringify({ jkt: v.jkt, sub: v.payload.sub, components: v.components }));
            """,
            "file://" + NODE_LIB,
            json.dumps(msg),
        )
        v = json.loads(out)
        self.assertEqual(v["jkt"], jose.jwk_thumbprint(key))
        self.assertEqual(v["sub"], "aauth:py@agent.example")
        self.assertEqual(v["components"], ["@method", "@authority", "@path", "signature-key", "@query", "content-type", "content-digest"])

    def test_node_signed_request_verifies_in_python(self):
        out = node(
            """
            const a = await import(process.argv[1]);
            const ap = a.generateJwk(), key = a.generateJwk(), t = a.now();
            const token = a.signJwt({ typ: 'aa-agent+jwt', jwk: ap, payload: { iss: 'https://agent.example', dwk: 'aauth-agent.json', sub: 'aauth:node@agent.example', cnf: { jwk: a.publicJwk(key) }, jti: a.randomId(), iat: t, exp: t + 600 } });
            const s = a.signRequest('https://df.example/api/v2/x?limit=5&filter=a%20b', { method: 'POST', token, jwk: key, body: { z: [1, 2], s: 'ü' } });
            console.log(JSON.stringify({ ...s, ap: a.publicJwk(ap), jkt: a.jwkThumbprint(key) }));
            """,
            "file://" + NODE_LIB,
        )
        m = json.loads(out)
        d = Discovery()
        d.seed("https://agent.example", "aauth-agent.json", {"issuer": "https://agent.example"}, {"keys": [m["ap"]]})
        v = verify_request(m["method"], m["url"], m["headers"], m["body"].encode(), verify_token=lambda t, typ: d.verify_jwt(t, typ), require_query=True)
        self.assertEqual(v["jkt"], m["jkt"])
        self.assertEqual(v["claims"]["sub"], "aauth:node@agent.example")

    @unittest.skipUnless(os.path.exists(NODE_CONFIG), "agent/config.mjs not available")
    def test_identity_from_aauth_init(self):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "agent.json")
            node(
                "const { initIdentity } = await import(process.argv[1]); initIdentity({ issuer: 'https://agents.example.com', name: 'Shared', file: process.argv[2] });",
                "file://" + NODE_CONFIG,
                path,
            )
            ident = AgentIdentity.load(path)
            self.assertEqual(ident.agent_id, "aauth:shared@agents.example.com")
            with open(os.path.join(d, "public", "jwks.json"), encoding="utf-8") as f:
                published = json.load(f)
            self.assertEqual(published, ident.provider_documents()["/jwks.json"])
            with open(os.path.join(d, "public", ".well-known", "aauth-agent.json"), encoding="utf-8") as f:
                self.assertEqual(json.load(f), ident.provider_documents()["/.well-known/aauth-agent.json"])


if __name__ == "__main__":
    unittest.main()
