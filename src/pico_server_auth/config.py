from dataclasses import dataclass, field

from pico_ioc import configured


@configured(target="self", prefix="server_auth", mapping="tree")
@dataclass
class ServerAuthSettings:
    """Configuration for pico-server-auth.

    When embedded alongside pico-client-auth, set ``issuer`` and ``audience``
    to the same values so tokens issued here are accepted by the client middleware.
    """

    issuer: str = "http://localhost:8100"
    audience: str = "pico"
    algorithm: str = "RS256"
    access_token_expire_minutes: int = 15
    refresh_token_expire_days: int = 7
    challenge_ttl_seconds: int = 60
    auto_create_admin: bool = False
    admin_email: str = "admin@pico.local"
    admin_password: str = "admin"
    supported_wallet_algorithms: list[str] = field(default_factory=lambda: ["ML-DSA-65", "Ed25519", "secp256k1"])
