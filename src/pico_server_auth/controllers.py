from typing import Any

from fastapi import HTTPException
from pico_client_auth import (
    SecurityContext,
    allow_anonymous,
    requires_role,
)
from pico_fastapi import controller, get, post
from pydantic import BaseModel

from pico_server_auth.challenge_store import ChallengeStore
from pico_server_auth.config import ServerAuthSettings
from pico_server_auth.mint_audit_store import MintAuditStore
from pico_server_auth.revocation_store import RevocationStore
from pico_server_auth.token_issuer import TokenIssuer
from pico_server_auth.wallet_verifier import WalletVerifier


class RevokeBody(BaseModel):
    jti: str
    reason: str = ""


@controller(prefix="/api/v1/auth", tags=["Auth"])
class AuthController:
    """Auth endpoints — compatible with pico-client-auth validation.

    JWKS endpoint allows pico-client-auth to validate tokens whether
    this module runs in the same process or as a separate service.
    """

    def __init__(
        self,
        settings: ServerAuthSettings,
        challenges: ChallengeStore,
        verifier: WalletVerifier,
        issuer: TokenIssuer,
        revocations: RevocationStore,
        mint_audit: MintAuditStore,
    ):
        self._settings = settings
        self._challenges = challenges
        self._verifier = verifier
        self._issuer = issuer
        self._revocations = revocations
        self._mint_audit = mint_audit

    @allow_anonymous
    @get("/jwks")
    async def jwks(self):
        """JWKS endpoint — pico-client-auth fetches this to validate tokens."""
        return self._issuer.jwks()

    @allow_anonymous
    @post("/challenge")
    async def challenge(self, body: dict[str, Any]):
        """Request a challenge nonce for wallet auth.

        Body: { "address": "0x..." }
        Returns: { "challenge": "<nonce>", "ttl": 60 }
        """
        address = body.get("address")
        if not address:
            raise HTTPException(status_code=400, detail="address required")
        nonce = self._challenges.create(str(address))
        return {
            "challenge": nonce,
            "ttl": self._settings.challenge_ttl_seconds,
        }

    @allow_anonymous
    @post("/sign-in")
    async def sign_in(self, body: dict[str, Any]):
        """Verify wallet signature and issue JWT.

        Body: {
            "address": "0x...",
            "public_key": "<hex>",
            "signature": "<hex>",
            "challenge": "<nonce>",
            "algorithm": "ML-DSA-65" | "Ed25519" | "secp256k1"
        }
        Returns: { "access_token": "...", "refresh_token": "...", "address": "..." }
        """
        address = str(body.get("address", ""))
        public_key_hex = str(body.get("public_key", ""))
        signature_hex = str(body.get("signature", ""))
        challenge_nonce = str(body.get("challenge", ""))
        algorithm = str(body.get("algorithm", "ML-DSA-65"))

        if not all([address, public_key_hex, signature_hex, challenge_nonce]):
            raise HTTPException(status_code=400, detail="address, public_key, signature, and challenge required")

        if not self._challenges.validate(address, challenge_nonce):
            raise HTTPException(status_code=401, detail="invalid or expired challenge")

        try:
            public_key = bytes.fromhex(public_key_hex)
            signature = bytes.fromhex(signature_hex)
            message = challenge_nonce.encode("utf-8")
        except ValueError:
            raise HTTPException(status_code=400, detail="invalid hex encoding")

        if not self._verifier.verify(algorithm, public_key, message, signature):
            raise HTTPException(status_code=401, detail="signature verification failed")

        # SECURITY: the authenticated identity MUST derive from the
        # VERIFIED public key, never from the client-supplied ``address``
        # (which is attacker-controlled and only used to look up the
        # challenge). Canonical wallet id = hex of the verified public
        # key bytes. If the client also sent an ``address`` we require it
        # to equal this derived value — a derived id, so a plain ``==``
        # comparison is sufficient (no secret involved).
        wallet_id = public_key.hex()
        if address and address != wallet_id:
            raise HTTPException(
                status_code=400,
                detail="address does not match verified public key",
            )

        access_token = self._issuer.issue_access_token(
            subject=wallet_id,
            role="wallet",
            extra_claims={"algorithm": algorithm, "wallet_address": wallet_id},
        )
        refresh_token = self._issuer.issue_refresh_token(subject=wallet_id, role="wallet")

        return {
            "access_token": access_token,
            "refresh_token": refresh_token,
            "address": wallet_id,
            "algorithm": algorithm,
        }

    @allow_anonymous
    @post("/refresh")
    async def refresh(self, body: dict[str, Any]):
        """Exchange a valid refresh token for a fresh access (and a
        rotated refresh) token. Both bind to the same subject.

        Body:    { "refresh_token": "..." }
        Returns: { "access_token": "...", "refresh_token": "..." }
        """
        from jwt import ExpiredSignatureError, PyJWTError

        token = str(body.get("refresh_token", ""))
        if not token:
            raise HTTPException(
                status_code=400,
                detail="refresh_token required",
            )
        try:
            claims = self._issuer.verify_refresh(token)
        except ExpiredSignatureError:
            raise HTTPException(status_code=401, detail="refresh expired")
        except (PyJWTError, ValueError) as exc:
            raise HTTPException(
                status_code=401,
                detail=f"refresh invalid: {exc}",
            )
        subject = str(claims.get("sub") or "")
        if not subject:
            raise HTTPException(status_code=401, detail="missing sub")
        # SECURITY: carry the ORIGINAL role forward — never hard-code
        # admin/operator here, or a low-privilege refresh token could be
        # exchanged for a privileged access token (role escalation).
        # Default to the least-privileged "user" if the original token
        # carried no role.
        original_role = str(claims.get("role") or "user")
        access_token = self._issuer.issue_access_token(
            subject=subject,
            role=original_role,
        )
        # Rotate the refresh token preserving the same role so the bound
        # privilege level survives across refreshes.
        refresh_token = self._issuer.issue_refresh_token(subject=subject, role=original_role)
        return {
            "access_token": access_token,
            "refresh_token": refresh_token,
        }

    @allow_anonymous
    @post("/login")
    async def password_login(self, body: dict[str, Any]):
        """Password-based login (for admin bootstrap).

        Body: { "email": "...", "password": "..." }
        Returns: { "access_token": "...", "refresh_token": "..." }
        """
        email = str(body.get("email", ""))
        password = str(body.get("password", ""))

        if not self._settings.auto_create_admin:
            raise HTTPException(status_code=403, detail="password login disabled")

        if email != self._settings.admin_email or password != self._settings.admin_password:
            raise HTTPException(status_code=401, detail="invalid credentials")

        access_token = self._issuer.issue_access_token(
            subject=email,
            role=self._settings.admin_role,
        )
        refresh_token = self._issuer.issue_refresh_token(subject=email, role=self._settings.admin_role)

        return {
            "access_token": access_token,
            "refresh_token": refresh_token,
        }

    # ── Revocation (jti denylist) ────────────────────────────────
    #
    # Backs the no-time-expiry policy (memory:
    # feedback_no_time_expiry.md). Tokens are valid until JWKS
    # rotation or until their ``jti`` is added here.
    #
    # The revoke endpoint is operator-gated. The list endpoint is
    # service-gated and used by validators (pico-client-auth) to
    # cache the denylist locally for fast rejection — without
    # round-tripping the auth server on every request.

    @requires_role("operator")
    @post("/revoke")
    async def revoke(self, body: dict[str, Any]):
        """Add a ``jti`` to the denylist. Idempotent — re-revoking
        keeps the original revoked_at + reason.

        The operator typically gets here via the SPA's "Revoke"
        button in a future Live-Tokens panel. Validators pick up
        the new entry on their next denylist refresh (default
        15s). For instant fleet-wide invalidation use JWKS
        rotation instead.
        """
        parsed = RevokeBody.model_validate(body or {})
        if not parsed.jti:
            raise HTTPException(400, "jti required")
        # ``SecurityContext.require`` raises when auth middleware
        # didn't run (e.g. ``auth_client.enabled=false`` in
        # pico-server-auth's own runner config — the issuer
        # doesn't validate JWTs aimed at itself by default).
        # Audit with whatever subject we have; "unknown" is fine
        # for dev. Production deployments enable auth_client and
        # the real ``sub`` shows up.
        try:
            ctx = SecurityContext.require()
            actor = ctx.sub or "operator"
        except Exception:  # noqa: BLE001
            actor = "unknown"
        entry = self._revocations.revoke(
            parsed.jti,
            reason=parsed.reason,
            revoked_by=actor,
        )
        return {"revoked": entry}

    @requires_role("service")
    @get("/revoked-jtis")
    async def revoked_jtis(self):
        """Validators poll this to refresh their local denylist
        cache. Returns the full list — small enough that a delta
        protocol isn't justified yet."""
        return {"items": self._revocations.list_all()}

    @requires_role("operator")
    @get("/mints")
    async def list_mints(self, limit: int = 200):
        """Recent token mints — backs the SPA's "live tokens"
        panel. Each entry carries ``revoked: bool`` computed
        on-the-fly so the operator sees which tokens are
        currently valid + a Revoke button per row.

        Pre-filtered server-side: ephemeral mints (TTL <
        ``mint_audit_min_ttl_seconds``) are dropped at issue
        time so this list focuses on tokens that survive long
        enough to be worth managing.
        """
        items = self._mint_audit.list_recent(limit=limit)
        # Decorate with revocation status — O(N × is_revoked)
        # which is O(N) for the in-memory dict-backed store.
        out = []
        for it in items:
            jti = str(it.get("jti", ""))
            out.append(
                {
                    **it,
                    "revoked": (self._revocations.is_revoked(jti) if jti else False),
                }
            )
        return {"items": out}
