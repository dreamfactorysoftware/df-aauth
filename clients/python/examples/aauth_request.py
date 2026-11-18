#!/usr/bin/env python3
"""Call a DreamFactory API as an AAuth agent, from Python.

    python3 examples/aauth_request.py GET 'https://df.example.com/api/v2/sales/_table/orders?limit=5'
    python3 examples/aauth_request.py PATCH https://df.example.com/api/v2/sales/_table/orders/7 \\
        --data '{"status": "refunded"}' --why "Customer asked for a refund"

The agent identity is ~/.config/aauth/agent.json ($AAUTH_CONFIG, or --identity FILE): create it
with `aauth init` (Node CLI) or examples/create_identity.py, and publish its two provider files.
When DreamFactory needs the person's approval the script prints a link and a code, then waits.
Exit status: 0 success, 1 error response, 3 not approved.
"""

import argparse
import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))

from dreamfactory_aauth import AAuthError, AgentIdentity, Cancelled, NotApproved, default_identity_path  # noqa: E402


def main() -> int:
    ap = argparse.ArgumentParser(description="Call an AAuth-protected API as an agent.")
    ap.add_argument("method")
    ap.add_argument("url")
    ap.add_argument("-d", "--data", help="JSON body")
    ap.add_argument("-s", "--scope", help='ask for these scopes up front, e.g. "sales.read sales.refund"')
    ap.add_argument("-w", "--why", help="justification shown on the approval screen")
    ap.add_argument("--identity", help=f"identity file (default {default_identity_path()})")
    ap.add_argument("--fresh", action="store_true", help="ignore cached tokens")
    ap.add_argument("--insecure", action="store_true", help="allow http:// servers (local testing only)")
    ap.add_argument("-v", "--verbose", action="store_true", help="print every protocol step")
    args = ap.parse_args()

    try:
        identity = AgentIdentity.load(args.identity)
    except FileNotFoundError:
        print(f"No agent identity at {args.identity or default_identity_path()}. Create one with `aauth init` or examples/create_identity.py.", file=sys.stderr)
        return 1
    agent = identity.agent(insecure=args.insecure)
    body = json.loads(args.data) if args.data else None

    def on_interaction(i):
        what = "sign in to identify the person" if i.purpose == "person" else f"allow {i.scope or 'access'}"
        print(f"  ! approval needed: {what}", file=sys.stderr)
        print(f"      open  {i.url}?code={i.code}", file=sys.stderr)
        print(f"      code  {i.code}", file=sys.stderr)
        print("    waiting...", file=sys.stderr)

    def on_step(s):
        if args.verbose and s.request is not None:
            req = s.requirement.get("requirement")
            print(f"  . {s.request.method} {s.request.url} -> {s.status}{f'  ({req})' if req else ''}", file=sys.stderr)

    print(f"{args.method.upper()} {args.url}\n  as {agent.agent_id}", file=sys.stderr)
    try:
        r = agent.request(args.method, args.url, json=body, scope=args.scope, justification=args.why, fresh=args.fresh, on_interaction=on_interaction, on_step=on_step)
    except (NotApproved, Cancelled) as e:
        print(f"  x not approved: {e.error}", file=sys.stderr)
        return 3
    except AAuthError as e:
        print(f"  x {e.error}: {e.detail} [HTTP {e.status}]", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print("  x interrupted; the pending request was withdrawn", file=sys.stderr)
        return 130
    scope = r.headers.get("AAuth-Scope")
    print(f"  {'ok' if r.ok else 'x'} {r.status_code}{f'  scope {scope}' if scope else ''}\n", file=sys.stderr)
    try:
        print(json.dumps(r.json(), indent=2))
    except ValueError:
        print(r.text)
    return 0 if r.ok else 1


if __name__ == "__main__":
    sys.exit(main())
