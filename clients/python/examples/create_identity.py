#!/usr/bin/env python3
"""Create an agent identity and the two public files of its Agent Provider.

    python3 examples/create_identity.py --issuer https://agents.example.com --name "Acme Reports"

Writes ~/.config/aauth/agent.json (mode 600; $AAUTH_CONFIG or --identity to choose) and
<identity dir>/public/{.well-known/aauth-agent.json, jwks.json}. Serve the public files at
https://agents.example.com/.well-known/aauth-agent.json and https://agents.example.com/jwks.json.
The same identity works with the Node `aauth` CLI.
"""

import argparse
import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))

from dreamfactory_aauth import AgentIdentity, default_identity_path  # noqa: E402


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[1])
    ap.add_argument("--issuer", required=True, help="https origin that will serve the provider files")
    ap.add_argument("--name", required=True, help="agent name shown to people on the approval screen")
    ap.add_argument("--id", help="agent id local part (default: from --name)")
    ap.add_argument("--identity", default=default_identity_path(), help="where to write the identity")
    args = ap.parse_args()

    if os.path.exists(args.identity):
        identity = AgentIdentity.load(args.identity)
        print(f"using {args.identity}")
    else:
        identity = AgentIdentity.generate(args.issuer, name=args.name, local=args.id)
        identity.save(args.identity)
        print(f"created {args.identity}")
    public = os.path.join(os.path.dirname(os.path.abspath(args.identity)), "public")
    for path, doc in identity.provider_documents().items():
        local = os.path.join(public, path.lstrip("/"))
        os.makedirs(os.path.dirname(local), exist_ok=True)
        with open(local, "w", encoding="utf-8") as f:
            json.dump(doc, f, indent=2)
            f.write("\n")
        print(f"  {identity.issuer}{path}  <-  {local}")
    print(f"agent id {identity.agent_id}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
