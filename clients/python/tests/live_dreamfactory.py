#!/usr/bin/env python3
"""Live end-to-end check of the Python client against a real DreamFactory with AAuth enabled.

Not collected by unittest discovery (the name does not start with test_). It needs the demo seed
(bin/demo-seed.sh: the `sales` service, scopes sales.read / sales.refund), an Agent Provider whose
keys you hold (the agent tokens it mints must verify against the provider's published JWKS),
node (to play the person through agent/person.mjs) and admin credentials for cleanup.

    cat keys.json | python3 tests/live_dreamfactory.py --df https://df.example.com --keys - \\
        --issuer https://agent.example.com --person-email admin@example.com \\
        --person-password-file ~/pw --admin-password-file ~/pw

Each scenario uses a fresh request key and an agent id <prefix>-<name>@<issuer host>; every agent
row, its activity and its grants are deleted at the end. Exit 0 when every scenario passes.
"""

import argparse
import json
import os
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, ".."))

import requests  # noqa: E402

from dreamfactory_aauth import Agent, AgentIdentity, NotApproved, claims, generate_jwk, scopes_of  # noqa: E402

PERSON_JS = os.path.normpath(os.path.join(HERE, "..", "..", "..", "agent", "person.mjs"))


def read_secret(path):
    with open(os.path.expanduser(path), encoding="utf-8") as f:
        return f.read().strip()


class Live:
    def __init__(self, a):
        self.a = a
        self.df = a.df.rstrip("/")
        self.results = []
        raw = sys.stdin.read() if a.keys == "-" else read_secret(a.keys)
        self.base = AgentIdentity.from_dict(json.loads(raw), issuer=a.issuer)
        self.host = self.base.issuer.split("://", 1)[1]
        self.person_pw = read_secret(a.person_password_file)
        self.admin_pw = read_secret(a.admin_password_file)
        self.session = None
        self.orders = f"{self.df}{a.path}"

    # -- helpers ---------------------------------------------------------
    def admin(self, method, path, body=None):
        if not self.session:
            r = requests.post(f"{self.df}/api/v2/system/admin/session", data={"email": self.a.admin_email, "password": self.admin_pw}, headers={"accept": "application/json"}, timeout=30)
            self.session = r.json().get("session_token")
            if not self.session:
                raise SystemExit(f"admin login failed (HTTP {r.status_code})")
        r = requests.request(method, f"{self.df}/api/v2{path}", json=body, headers={"x-dreamfactory-session-token": self.session, "accept": "application/json"}, timeout=30)
        try:
            return r.status_code, r.json()
        except ValueError:
            return r.status_code, r.text

    def agent(self, name):
        return Agent(self.base.issuer, agent_id=f"{self.a.prefix}-{name}@{self.host}", provider_key=self.base.provider_key, agent_key=generate_jwk())

    def person(self, decision="allow", always=False, log=None):
        def act(i):
            if log is not None:
                log.append(i)
            cmd = ["node", PERSON_JS, "approve", i.url, i.code, "--email", self.a.person_email]
            if decision == "deny" and i.purpose == "auth":
                cmd.append("--deny")
            if always:
                cmd.append("--always")
            out = subprocess.run(cmd, env={**os.environ, "AAUTH_PERSON_PASSWORD": self.person_pw}, capture_output=True, text=True, timeout=60)
            if out.returncode != 0:
                raise RuntimeError(f"person helper failed: {out.stdout.strip()} {out.stderr.strip()}")

        return act

    def check(self, cond, label, detail=""):
        print(f"    {'ok  ' if cond else 'FAIL'} {label}{'' if cond or not detail else f'  -> {detail}'}")
        self.current.append(bool(cond))
        return cond

    def scenario(self, n, title, fn):
        print(f"\n[{n}] {title}")
        self.current = []
        try:
            fn()
        except Exception as e:  # noqa: BLE001
            self.check(False, "threw", f"{type(e).__name__}: {e}")
        ok = bool(self.current) and all(self.current)
        self.results.append((n, ok))
        print(f"{'PASS' if ok else 'FAIL'} {n}. {title}")

    # -- scenarios -------------------------------------------------------
    def run(self):
        st, info = self.admin("GET", "/system/aauth")
        if st != 200 or not info.get("enabled"):
            raise SystemExit(f"AAuth is not enabled on {self.df} (GET /system/aauth -> {st})")
        main = self.agent("main")
        state = {}

        def s1():
            seen = []
            r = main.get(self.orders, params={"limit": 3}, on_interaction=self.person(log=seen), justification="Python client live check")
            rows = r.json().get("resource") if r.ok else None
            self.check(r.status_code == 200, "GET orders -> 200", f"{r.status_code} {r.text[:200]}")
            self.check(isinstance(rows, list) and rows, "orders returned")
            self.check([i.purpose for i in seen] == ["person", "auth"], "person approved identity, then consent", [i.purpose for i in seen])
            self.check(r.headers.get("AAuth-Scope") == self.a.read_scope, f"served under {self.a.read_scope}", r.headers.get("AAuth-Scope"))
            kinds = [s.kind for s in r.aauth.steps]
            self.check(kinds.count("call") == 3 and "person_token" in kinds and "auth_token" in kinds, "agent token -> person token -> auth token", kinds)
            if rows:
                state["id"], state["status"] = rows[0]["id"], rows[0]["status"]

        def s2():
            r = main.get(self.orders, params={"limit": 1}, on_interaction=lambda i: self.check(False, "unexpected interaction"))
            self.check(r.status_code == 200, "status 200", r.status_code)
            self.check([s.kind for s in r.aauth.steps if s.kind != "discover"] == ["reuse"], "one signed call with the cached auth token")

        def s3():
            if not self.check("id" in state, "have an order from scenario 1"):
                return
            seen = []
            url = f"{self.orders}/{state['id']}"
            r = main.patch(url, json={"status": "refunded"}, scope=self.a.write_scope, on_interaction=self.person(log=seen))
            self.check(r.status_code == 200, f"PATCH with {self.a.write_scope} up front -> 200", f"{r.status_code} {r.text[:200]}")
            self.check(any(s.kind == "authorize" and s.status == 200 for s in r.aauth.steps), "resource token from the authorization endpoint")
            self.check([i.purpose for i in seen] == ["auth"], "one consent, no new sign-in", [i.purpose for i in seen])
            auth = main.cache.get(main.cache_key(self.df, self.df))["auth"]
            self.check(set(scopes_of(auth)) >= {self.a.read_scope, self.a.write_scope}, "auth token kept the earlier scope (union)", claims(auth).get("scope"))
            back = main.patch(url, json={"status": state["status"]}, on_interaction=lambda i: self.check(False, "unexpected interaction"))
            self.check(back.status_code == 200 and all(s.kind != "auth_token" for s in back.aauth.steps), "restored the order status with the same token", back.status_code)

        def s4():
            try:
                self.agent("deny").get(self.orders, params={"limit": 1}, on_interaction=self.person(decision="deny"))
                self.check(False, "expected NotApproved")
            except NotApproved as e:
                self.check(e.error == "denied" and e.status == 403, "consent denied -> NotApproved(denied) from the poll", f"{e.error} {e.status}")

        def s5():
            a = self.agent("always")
            r = a.get(self.orders, params={"limit": 1}, on_interaction=self.person(always=True))
            self.check(r.status_code == 200, "first call approved with Always allow", r.status_code)
            key = a.cache_key(self.df, self.df)
            a.cache.set(key, {"person": a.cache.get(key)["person"]})
            r2 = a.get(self.orders, params={"limit": 1}, on_interaction=lambda i: self.check(False, "unexpected interaction"))
            at = next((s for s in r2.aauth.steps if s.kind == "auth_token"), None)
            self.check(r2.status_code == 200 and at is not None and at.status == 200, "standing grant: auth token endpoint answers 200 at once", at.status if at else None)
            _, grants = self.admin("GET", "/system/aauth/grants")
            mine = [g for g in grants.get("resource", []) if g.get("agent_sub") == a.agent_id]
            self.check(len(mine) == 1, "grant listed in the admin API", len(mine))

        def s6():
            a = self.agent("tamper")
            tok = a.agent_token(self.df)
            from dreamfactory_aauth.signing import sign_request

            s = sign_request("POST", self.orders, token=tok, key=a.agent_key, body={"resource": []}, additional=["@query", "content-type", "content-digest"])
            r = requests.post(s.url, headers=s.headers, data=b'{"resource":[{"x":1}]}', allow_redirects=False, timeout=30)
            self.check(r.status_code == 401 and "invalid_signature" in r.headers.get("Signature-Error", ""), "body changed after signing -> 401 invalid_signature", f"{r.status_code} {r.headers.get('Signature-Error')}")
            ok = requests.post(s.url, headers=s.headers, data=s.body, allow_redirects=False, timeout=30)
            self.check(ok.status_code == 401 and "person-token" in ok.headers.get("AAuth-Requirement", ""), "the untouched request -> 401 person-token", ok.status_code)

        self.scenario(1, "Full three-party flow: GET orders -> 200", s1)
        self.scenario(2, "Second call reuses the auth token", s2)
        self.scenario(3, "Up-front scope via authorization_endpoint: PATCH -> 200, then restore", s3)
        self.scenario(4, "Deny -> NotApproved", s4)
        self.scenario(5, "Always allow -> standing grant", s5)
        self.scenario(6, "Tampered body is rejected by DreamFactory", s6)

    def cleanup(self):
        prefix = f"{self.a.prefix}-"
        _, grants = self.admin("GET", "/system/aauth/grants")
        g = [x for x in grants.get("resource", []) if str(x.get("agent_sub", "")).startswith(prefix)]
        for x in g:
            self.admin("DELETE", f"/system/aauth/grants/{x['id']}")
        _, agents = self.admin("GET", "/system/aauth/agents")
        ag = [x for x in agents.get("resource", []) if str(x.get("agent_id", "")).startswith(prefix)]
        for x in ag:
            self.admin("DELETE", f"/system/aauth/agents/{x['id']}?purge_activity=true")
        time.sleep(0.2)
        _, after = self.admin("GET", "/system/aauth/agents")
        left = [x for x in after.get("resource", []) if str(x.get("agent_id", "")).startswith(prefix)]
        print(f"\ncleanup: deleted {len(g)} grant(s), {len(ag)} agent(s); {len(left)} {prefix}* agents left")


def main():
    p = argparse.ArgumentParser(description="Live end-to-end check of the Python AAuth client.")
    p.add_argument("--df", default=os.environ.get("DF_URL"), help="DreamFactory AAuth issuer, e.g. https://df.example.com")
    p.add_argument("--keys", required=True, help="identity or keys file with the Agent Provider key ('-' = stdin)")
    p.add_argument("--issuer", default=os.environ.get("AAUTH_AGENT_ISSUER"), help="Agent Provider issuer (when the keys file has none)")
    p.add_argument("--prefix", default="aauth:e2e-py", help="agent id prefix (default aauth:e2e-py)")
    p.add_argument("--person-email", required=True)
    p.add_argument("--person-password-file", required=True)
    p.add_argument("--admin-email", default=None, help="default: --person-email")
    p.add_argument("--admin-password-file", required=True)
    p.add_argument("--path", default="/api/v2/sales/_table/orders")
    p.add_argument("--read-scope", default="sales.read")
    p.add_argument("--write-scope", default="sales.refund")
    a = p.parse_args()
    if not a.df:
        p.error("--df (or DF_URL) is required")
    a.admin_email = a.admin_email or a.person_email
    live = Live(a)
    try:
        live.run()
    finally:
        live.cleanup()
    failed = [n for n, ok in live.results if not ok]
    print(f"{len(live.results) - len(failed)}/{len(live.results)} scenarios passed{'; failed: ' + ', '.join(map(str, failed)) if failed else ''}")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
