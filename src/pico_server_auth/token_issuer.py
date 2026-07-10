import time
import uuid
from typing import Any

from cryptography.hazmat.primitives import serialization
from pico_ioc import component

from pico_server_auth.config import ServerAuthSettings
from pico_server_auth.mint_audit_store import MintAuditStore


def _new_jti() -> str:
    """Fresh UUIDv4 for the JWT ID claim. Every token we issue
    gets one so the operator can revoke individual tokens via
    the planned denylist (memory: feedback_no_time_expiry.md).
    """
    return uuid.uuid4().hex


@component
class TokenIssuer:
    """Issues JWT tokens compatible with pico-client-auth validation.

    Tokens use the same issuer/audience as configured in pico-client-auth,
    so they are accepted transparently whether issued in-process or remotely.
    """

    def __init__(
        self,
        settings: ServerAuthSettings,
        audit: MintAuditStore,
    ):
        self._settings = settings
        self._audit = audit
        self._private_key: Any = None
        self._public_key: Any = None
        self._jwk: dict | None = None
        self._kid: str = "pico-server-auth-1"
        self._init_keys()

    def _audit_mint(
        self,
        payload: dict,
        kind: str,
    ) -> None:
        """Append to the mint audit log when the token's lifetime
        is meaningful enough to track. Pre-filters ephemeral
        mints (e.g. 60s per-dispatch agent tokens) so the log
        stays focused on tokens an operator might want to
        revoke. See ``mint_audit_min_ttl_seconds`` setting.
        """
        iat = int(payload.get("iat", 0) or 0)
        exp = int(payload.get("exp", 0) or 0)
        ttl = max(0, exp - iat)
        threshold = max(0, int(self._settings.mint_audit_min_ttl_seconds))
        if ttl < threshold:
            return
        entry = {
            "jti": payload.get("jti", ""),
            "sub": payload.get("sub", ""),
            "role": payload.get("role", ""),
            "iat": iat,
            "exp": exp,
            "kind": kind,
            "scope": payload.get("scope", ""),
            "agent_id": payload.get("agent_id", ""),
            "session_id": payload.get("session_id", ""),
        }
        try:
            self._audit.append(entry)
        except Exception:  # noqa: BLE001
            # Audit failure must never block a mint. The operator
            # gets a log line; the token itself is still valid.
            import logging as _logging

            _logging.getLogger(__name__).warning(
                "mint audit append failed",
                exc_info=True,
            )

    def _init_keys(self) -> None:
        alg = self._settings.algorithm
        if alg == "RS256":
            from cryptography.hazmat.primitives.asymmetric import rsa

            self._private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
            self._public_key = self._private_key.public_key()
        elif alg in ("ML-DSA-65", "ML-DSA-87"):
            pass  # TODO: post-quantum key generation
        else:
            raise ValueError(f"unsupported token algorithm: {alg}")

    def issue_access_token(self, subject: str, role: str = "user", extra_claims: dict | None = None) -> str:
        import jwt

        now = int(time.time())
        payload = {
            "sub": subject,
            "iss": self._settings.issuer,
            "aud": self._settings.audience,
            "iat": now,
            "exp": now + self._settings.access_token_expire_minutes * 60,
            "jti": _new_jti(),
            "role": role,
            **(extra_claims or {}),
        }

        pem = self._private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
        token = jwt.encode(payload, pem, algorithm="RS256", headers={"kid": self._kid})
        self._audit_mint(payload, kind="access")
        return token

    def sign(self, payload: dict[str, Any]) -> str:
        """Sign an arbitrary claims payload with the issuer key.

        Used by fleet session minting (and anywhere else that
        needs a one-off token with non-default claims/TTL). Caller
        is responsible for ``iss`` / ``aud`` / ``iat`` / ``exp`` —
        we don't second-guess the payload here.

        We DO inject a fresh ``jti`` if the caller didn't supply
        one, so every token in the system carries a unique ID and
        becomes individually revocable via the denylist."""
        import jwt

        if "jti" not in payload:
            payload = {**payload, "jti": _new_jti()}
        pem = self._private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
        token = jwt.encode(
            payload,
            pem,
            algorithm="RS256",
            headers={"kid": self._kid},
        )
        self._audit_mint(payload, kind="sign")
        return token

    def verify_refresh(self, token: str) -> dict[str, Any]:
        """Decode + verify a refresh token previously issued by us.

        Validates signature, issuer, audience and expiry. Also
        enforces that the token's ``type`` claim is ``refresh`` so
        a stolen access token can't be exchanged at the refresh
        endpoint. Raises ``jwt.PyJWTError`` /
        ``ExpiredSignatureError`` on failure — caller maps to 401.
        """
        import jwt

        pub_pem = self._public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        payload = jwt.decode(
            token,
            pub_pem,
            algorithms=["RS256"],
            audience=self._settings.audience,
            issuer=self._settings.issuer,
        )
        if payload.get("type") != "refresh":
            raise ValueError("not a refresh token")
        return payload

    def issue_refresh_token(self, subject: str, role: str | None = None) -> str:
        import jwt

        now = int(time.time())
        payload = {
            "sub": subject,
            "iss": self._settings.issuer,
            "aud": self._settings.audience,
            "iat": now,
            "exp": now + self._settings.refresh_token_expire_days * 86400,
            "jti": _new_jti(),
            "type": "refresh",
        }
        # Bind the role onto the refresh token so /refresh can mint a new
        # access token with the SAME role (no escalation, no downgrade).
        # Optional/back-compat: legacy refresh tokens without a role fall
        # back to "user" at the /refresh endpoint.
        if role is not None:
            payload["role"] = role

        pem = self._private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
        token = jwt.encode(payload, pem, algorithm="RS256", headers={"kid": self._kid})
        self._audit_mint(payload, kind="refresh")
        return token

    def jwks(self) -> dict:
        """Returns JWKS for pico-client-auth to validate tokens.

        When running in the same process, pico-client-auth can fetch
        this from the /api/v1/auth/jwks endpoint or directly from this component.
        """
        if self._jwk is None:
            pub_numbers = self._public_key.public_numbers()
            import base64

            def _b64url(n: int, length: int) -> str:
                return base64.urlsafe_b64encode(n.to_bytes(length, "big")).rstrip(b"=").decode()

            self._jwk = {
                "kty": "RSA",
                "kid": self._kid,
                "alg": "RS256",
                "use": "sig",
                "n": _b64url(pub_numbers.n, 256),
                "e": _b64url(pub_numbers.e, 3),
            }
        return {"keys": [self._jwk]}
