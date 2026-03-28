import time
from typing import Any

from cryptography.hazmat.primitives import serialization
from pico_ioc import component

from pico_server_auth.config import ServerAuthSettings


@component
class TokenIssuer:
    """Issues JWT tokens compatible with pico-client-auth validation.

    Tokens use the same issuer/audience as configured in pico-client-auth,
    so they are accepted transparently whether issued in-process or remotely.
    """

    def __init__(self, settings: ServerAuthSettings):
        self._settings = settings
        self._private_key: Any = None
        self._public_key: Any = None
        self._jwk: dict | None = None
        self._kid: str = "pico-server-auth-1"
        self._init_keys()

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
        from jose import jwt

        now = int(time.time())
        payload = {
            "sub": subject,
            "iss": self._settings.issuer,
            "aud": self._settings.audience,
            "iat": now,
            "exp": now + self._settings.access_token_expire_minutes * 60,
            "role": role,
            **(extra_claims or {}),
        }

        pem = self._private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
        return jwt.encode(payload, pem, algorithm="RS256", headers={"kid": self._kid})

    def issue_refresh_token(self, subject: str) -> str:
        from jose import jwt

        now = int(time.time())
        payload = {
            "sub": subject,
            "iss": self._settings.issuer,
            "aud": self._settings.audience,
            "iat": now,
            "exp": now + self._settings.refresh_token_expire_days * 86400,
            "type": "refresh",
        }

        pem = self._private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
        return jwt.encode(payload, pem, algorithm="RS256", headers={"kid": self._kid})

    def jwks(self) -> dict:
        """Returns JWKS for pico-client-auth to validate tokens.

        When running in the same process, pico-client-auth can fetch
        this from the /auth/jwks endpoint or directly from this component.
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
