from typing import Any

from fastapi import HTTPException
from pico_client_auth import allow_anonymous
from pico_fastapi import controller, get, post

from pico_server_auth.challenge_store import ChallengeStore
from pico_server_auth.config import ServerAuthSettings
from pico_server_auth.token_issuer import TokenIssuer
from pico_server_auth.wallet_verifier import WalletVerifier


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
    ):
        self._settings = settings
        self._challenges = challenges
        self._verifier = verifier
        self._issuer = issuer

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

        access_token = self._issuer.issue_access_token(
            subject=address,
            role="wallet",
            extra_claims={"algorithm": algorithm, "wallet_address": address},
        )
        refresh_token = self._issuer.issue_refresh_token(subject=address)

        return {
            "access_token": access_token,
            "refresh_token": refresh_token,
            "address": address,
            "algorithm": algorithm,
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

        access_token = self._issuer.issue_access_token(subject=email, role="admin")
        refresh_token = self._issuer.issue_refresh_token(subject=email)

        return {
            "access_token": access_token,
            "refresh_token": refresh_token,
        }
