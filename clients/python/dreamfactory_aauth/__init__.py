"""dreamfactory-aauth: call AAuth-protected APIs (such as DreamFactory) from Python agents.

    from dreamfactory_aauth import AgentIdentity

    agent = AgentIdentity.load().agent()            # ~/.config/aauth/agent.json (`aauth init`)
    r = agent.get("https://df.example.com/api/v2/sales/_table/orders",
                  params={"limit": 5},
                  on_interaction=lambda i: print("Approve at", i.user_url))
    print(r.status_code, r.json())

Implements draft-hardt-oauth-aauth-protocol-11 and draft-hardt-httpbis-signature-key-09.
"""

from .agent import Agent, FileTokenCache, Flow, Interaction, MemoryTokenCache, Step
from .discovery import Discovery, assert_server_id
from .errors import AAuthError, Cancelled, InvalidToken, NotApproved
from .identity import AgentIdentity, default_identity_path, mint_agent_token
from .jose import claims, decode_jwt, generate_jwk, jwk_thumbprint, public_jwk, scopes_of, sign_jwt
from .signing import content_digest, sign_request, verify_request

__version__ = "0.1.0"

__all__ = [
    "AAuthError",
    "Agent",
    "AgentIdentity",
    "Cancelled",
    "Discovery",
    "FileTokenCache",
    "Flow",
    "Interaction",
    "InvalidToken",
    "MemoryTokenCache",
    "NotApproved",
    "Step",
    "assert_server_id",
    "claims",
    "content_digest",
    "decode_jwt",
    "default_identity_path",
    "generate_jwk",
    "jwk_thumbprint",
    "mint_agent_token",
    "public_jwk",
    "scopes_of",
    "sign_jwt",
    "sign_request",
    "verify_request",
]
