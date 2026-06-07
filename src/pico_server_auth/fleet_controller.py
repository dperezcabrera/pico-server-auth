"""Fleet session-token mint endpoint.

Exposed at ``POST /api/v1/auth/fleet/sessions``. Restricted via a
shared secret in the ``X-Fleet-Secret`` header — pico-server-auth
treats fleet-runtime as the only legitimate caller. The secret is
configured via ``server_auth.fleet_mint_secret`` (env:
``SERVER_AUTH_FLEET_MINT_SECRET``); empty value disables the
endpoint entirely so a fresh deploy can't accidentally mint
tokens for arbitrary subjects.

Tokens emitted here are regular RS256 access tokens — pico-client-
auth (and any other JWKS-validating consumer) accepts them
transparently. Claims:

    sub           = session_id
    role          = "agent"          (overridable via body.role)
    session_id    = <body.session_id>
    agent_id      = <body.agent_id>
    scope         = <body.scope>     (optional)
    iat / exp     = standard
"""

import hmac
from typing import Any

from fastapi import Header, HTTPException
from pico_client_auth import allow_anonymous
from pico_fastapi import controller, post
from pydantic import BaseModel

from pico_server_auth.config import ServerAuthSettings
from pico_server_auth.token_issuer import TokenIssuer


class FleetSessionMintBody(BaseModel):
    session_id: str
    agent_id: str
    role: str = "agent"
    ttl: int | None = None  # seconds; clamped to fleet_max_ttl_seconds
    scope: str | None = None


@controller(prefix="/api/v1/auth/fleet", tags=["FleetAuth"])
class FleetAuthController:
    def __init__(
        self,
        settings: ServerAuthSettings,
        issuer: TokenIssuer,
    ):
        self._settings = settings
        self._issuer = issuer

    @allow_anonymous
    @post("/sessions")
    async def mint_session(
        self,
        body: FleetSessionMintBody,
        x_fleet_secret: str | None = Header(default=None, alias="X-Fleet-Secret"),
    ):
        expected = self._settings.fleet_mint_secret
        if not expected:
            raise HTTPException(
                status_code=404,
                detail="fleet mint endpoint disabled (server_auth.fleet_mint_secret unset)",
            )
        if not x_fleet_secret or not hmac.compare_digest(
            x_fleet_secret,
            expected,
        ):
            raise HTTPException(
                status_code=401,
                detail="invalid X-Fleet-Secret",
            )

        if not body.session_id or not body.agent_id:
            raise HTTPException(
                status_code=400,
                detail="session_id and agent_id required",
            )

        ttl = body.ttl or self._settings.fleet_session_ttl_seconds
        max_ttl = self._settings.fleet_max_ttl_seconds
        ttl = min(max(ttl, 60), max_ttl)

        # Bypass TokenIssuer.access_token_expire_minutes so callers
        # can choose a longer TTL up to the configured ceiling.
        import time

        now = int(time.time())
        extra_claims: dict[str, Any] = {
            "session_id": body.session_id,
            "agent_id": body.agent_id,
        }
        if body.scope:
            extra_claims["scope"] = body.scope

        payload = {
            "sub": body.session_id,
            "iss": self._settings.issuer,
            "aud": self._settings.audience,
            "iat": now,
            "exp": now + ttl,
            "role": body.role,
            **extra_claims,
        }
        token = self._issuer.sign(payload)
        return {"session_token": token, "exp": payload["exp"]}
