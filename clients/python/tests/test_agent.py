"""Offline tests of the Agent flow against an in-process mock resource + Person Server."""

import os
import stat
import tempfile
import unittest

from dreamfactory_aauth import Agent, Cancelled, FileTokenCache, InvalidToken, NotApproved, AAuthError, jose, mint_agent_token
from dreamfactory_aauth.discovery import Discovery

from mock_df import AP, MockDF


def approve(mock, decision="allow", always=False, log=None):
    def on_interaction(i):
        if log is not None:
            log.append(i)
        mock.decide(i.code, decision, always)

    return on_interaction


class AgentFlow(unittest.TestCase):
    def setUp(self):
        self.ap = jose.generate_jwk()
        self.mock = MockDF(self.ap)
        self.url = f"{self.mock.origin}/api/data"

    def tearDown(self):
        self.mock.close()

    def agent(self, sub="aauth:t@agent.example", **kw):
        kw.setdefault("provider_key", self.ap)
        return Agent(AP, agent_id=sub, insecure=True, **kw)

    def test_full_flow_reuse_step_up(self):
        a = self.agent()
        seen = []
        r = a.get(self.url, params={"limit": 3}, on_interaction=approve(self.mock, log=seen))
        self.assertEqual(r.status_code, 200, r.text)
        self.assertEqual(r.json()["query"], {"limit": ["3"]})
        self.assertEqual([i.purpose for i in seen], ["person", "auth"])
        self.assertEqual(seen[1].scope, "read")
        self.assertTrue(seen[0].user_url.startswith(f"{self.mock.origin}/interact?code="))
        kinds = [s.kind for s in r.aauth.steps]
        self.assertEqual(kinds[:3], ["discover", "discover", "call"])
        self.assertIn("person_token", kinds)
        self.assertIn("auth_token", kinds)
        first = next(s for s in r.aauth.steps if s.kind == "call")
        self.assertEqual(first.status, 401)
        self.assertEqual(first.requirement["requirement"], "person-token")
        self.assertIn('"@query"', first.request.headers["signature-input"])

        r2 = a.get(self.url, params={"limit": 3}, on_interaction=lambda i: self.fail("no interaction expected"))
        self.assertEqual(r2.status_code, 200)
        self.assertEqual([s.kind for s in r2.aauth.steps if s.kind not in ("discover",)], ["reuse"])

        seen.clear()
        r3 = a.patch(self.url, json={"status": "refunded"}, on_interaction=approve(self.mock, log=seen))
        self.assertEqual(r3.status_code, 200, r3.text)
        self.assertEqual(r3.json()["body"], {"status": "refunded"})
        self.assertEqual([i.purpose for i in seen], ["auth"])
        auth = a.cache.get(a.cache_key(self.mock.origin, self.mock.origin))["auth"]
        self.assertEqual(sorted(jose.scopes_of(auth)), ["read", "write"])
        step = next(s for s in r3.aauth.steps if s.kind == "auth_token")
        self.assertEqual(jose.decode_jwt(__import__("json").loads(step.request.body)["presented_token"])[0]["typ"], "aa-auth+jwt")

    def test_deny_always_cancel_timeout(self):
        with self.assertRaises(NotApproved) as e:
            self.agent("aauth:deny@agent.example").get(self.url, on_interaction=lambda i: self.mock.decide(i.code, "deny" if i.purpose == "auth" else "allow"))
        self.assertEqual(e.exception.error, "denied")
        self.assertEqual(e.exception.status, 403)

        a = self.agent("aauth:always@agent.example")
        self.assertEqual(a.get(self.url, on_interaction=approve(self.mock, always=True)).status_code, 200)
        key = a.cache_key(self.mock.origin, self.mock.origin)
        a.cache.set(key, {"person": a.cache.get(key)["person"]})
        r = a.get(self.url, on_interaction=lambda i: self.fail("standing grant expected"))
        self.assertEqual(r.status_code, 200)
        self.assertEqual(next(s for s in r.aauth.steps if s.kind == "auth_token").status, 200)

        with self.assertRaises(Cancelled):
            self.agent("aauth:cancel@agent.example").get(self.url, on_interaction=lambda i: "cancel")
        self.assertTrue(any(line.startswith("DELETE /pending/") for line in self.mock.log))

        with self.assertRaises(NotApproved) as t:
            self.agent("aauth:slow@agent.example").get(self.url, on_interaction=lambda i: None, poll_timeout=0.3)
        self.assertEqual(t.exception.error, "timeout")

    def test_scope_up_front(self):
        a = self.agent("aauth:scope@agent.example")
        r = a.get(self.url, scope="read", on_interaction=approve(self.mock))
        self.assertEqual(r.status_code, 200, r.text)
        kinds = [s.kind for s in r.aauth.steps]
        self.assertIn("authorize", kinds)
        self.assertFalse(any(s.kind == "call" and s.title == "Call with agent token" for s in r.aauth.steps))
        r2 = a.patch(self.url, json={"a": 1}, scope="write", on_interaction=approve(self.mock))
        self.assertEqual(r2.status_code, 200, r2.text)
        az = next(s for s in r2.aauth.steps if s.kind == "authorize")
        self.assertEqual(__import__("json").loads(az.request.body), {"scope": "read write"})
        with self.assertRaises(AAuthError) as e:
            a.get(self.url, scope="nope")
        self.assertEqual(e.exception.error, "invalid_scope")
        self.assertEqual(e.exception.status, 400)

    def test_agent_token_callable_generated_key_callback(self):
        key = jose.generate_jwk()
        a = Agent(AP, agent_id="aauth:remote@agent.example", agent_key=key, insecure=True, callback="https://agent.example/done", agent_token=lambda ps: mint_agent_token(AP, self.ap, "aauth:remote@agent.example", key, ps=ps, ttl=600))
        seen = []
        self.assertEqual(a.get(self.url, on_interaction=approve(self.mock, log=seen)).status_code, 200)
        self.assertTrue(seen[0].user_url.endswith("&callback=https%3A%2F%2Fagent.example%2Fdone"), seen[0].user_url)
        wrong = Agent(AP, agent_id="aauth:remote@agent.example", insecure=True, agent_token=lambda ps: mint_agent_token(AP, self.ap, "aauth:remote@agent.example", jose.generate_jwk(), ps=ps))
        with self.assertRaises(InvalidToken):
            wrong.get(self.url)
        g = Agent(AP, provider_key=self.ap)
        self.assertEqual(g.agent_id, "aauth:agent@agent.example")
        self.assertEqual(jose.claims(g.agent_token())["cnf"]["jwk"]["x"], g.agent_key["x"])
        self.assertEqual(Agent(AP, provider_key=self.ap, callback=True).callback_url, f"{AP}/callback")
        with self.assertRaises(ValueError):
            Agent(AP)

    def test_rejects_a_resource_token_for_another_key(self):
        self.mock.close()
        self.mock = MockDF(self.ap, bad_resource_tokens=True)
        with self.assertRaises(InvalidToken) as e:
            self.agent("aauth:rt@agent.example").get(f"{self.mock.origin}/api/data", on_interaction=approve(self.mock))
        self.assertIn("agent_jkt", e.exception.detail)

    def test_file_cache_shared_across_instances(self):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "sub", "tokens.json")
            key = jose.generate_jwk()
            a = self.agent("aauth:file@agent.example", agent_key=key, token_cache=FileTokenCache(path))
            self.assertEqual(a.get(self.url, on_interaction=approve(self.mock)).status_code, 200)
            self.assertEqual(stat.S_IMODE(os.stat(path).st_mode), 0o600)
            b = self.agent("aauth:file@agent.example", agent_key=key, token_cache=FileTokenCache(path))
            r = b.get(self.url, on_interaction=lambda i: self.fail("cached tokens expected"))
            self.assertEqual(r.status_code, 200)
            self.assertEqual(b.forget(self.mock.origin), 1)
            self.assertEqual(FileTokenCache(path).all(), {})

    def test_untrusted_metadata_issuer(self):
        d = Discovery(insecure=True)
        # metadata whose issuer is not the URL it came from is refused
        d.json = lambda url, fresh=False: {"issuer": "https://evil.example"}  # type: ignore[assignment]
        with self.assertRaisesRegex(AAuthError, "issuer_mismatch"):
            d.metadata(self.mock.origin, "aauth-resource.json")


if __name__ == "__main__":
    unittest.main()
