# Configuration Reference

`ServerAuthSettings` is configured via pico-ioc's `@configured` decorator with prefix `server_auth` and `mapping="tree"`.

```python
from dataclasses import dataclass, field
from pico_ioc import configured

@configured(target="self", prefix="server_auth", mapping="tree")
@dataclass
class ServerAuthSettings:
    issuer: str = "http://localhost:8100"
    audience: str = "pico"
    algorithm: str = "RS256"
    access_token_expire_minutes: int = 15
    refresh_token_expire_days: int = 7
    challenge_ttl_seconds: int = 60
    auto_create_admin: bool = False
    admin_email: str = "admin@pico.local"
    admin_password: str = "admin"
    supported_wallet_algorithms: list[str] = field(
        default_factory=lambda: ["ML-DSA-65", "Ed25519", "secp256k1"]
    )
```

## Fields

| Field | Type | Default | Description |
|---|---|---|---|
| `issuer` | `str` | `"http://localhost:8100"` | JWT `iss` claim. Must match pico-client-auth's `issuer` setting. |
| `audience` | `str` | `"pico"` | JWT `aud` claim. Must match pico-client-auth's `audience` setting. |
| `algorithm` | `str` | `"RS256"` | JWT signing algorithm. Currently only `RS256` is fully implemented. |
| `access_token_expire_minutes` | `int` | `15` | Access token lifetime in minutes. |
| `refresh_token_expire_days` | `int` | `7` | Refresh token lifetime in days. |
| `challenge_ttl_seconds` | `int` | `60` | How long a wallet challenge nonce remains valid. |
| `auto_create_admin` | `bool` | `False` | Enable the `POST /api/v1/auth/login` password endpoint. |
| `admin_email` | `str` | `"admin@pico.local"` | Email for admin password login. |
| `admin_password` | `str` | `"admin"` | Password for admin password login. |
| `supported_wallet_algorithms` | `list[str]` | `["ML-DSA-65", "Ed25519", "secp256k1"]` | Algorithms accepted by `WalletVerifier`. |

## Configuration via pico-boot

Pass settings as a nested dict under the `server_auth` key:

```python
from pico_boot import Application

app = Application(
    module_names=["pico_server_auth"],
    config={
        "server_auth": {
            "issuer": "https://auth.example.com",
            "audience": "my-platform",
            "access_token_expire_minutes": 30,
            "refresh_token_expire_days": 14,
            "challenge_ttl_seconds": 120,
            "auto_create_admin": False,
            "supported_wallet_algorithms": ["ML-DSA-65", "Ed25519"],
        },
    },
)
```

## Important Notes

!!! warning "Match issuer and audience with pico-client-auth"
    If `server_auth.issuer` does not match `auth_client.issuer` (and likewise for `audience`), tokens issued by pico-server-auth will be rejected by pico-client-auth.

!!! warning "Change default admin credentials"
    The default `admin_email` and `admin_password` are insecure. Always override them when enabling `auto_create_admin`.

!!! info "Supported algorithms"
    The `supported_wallet_algorithms` list controls which algorithms `WalletVerifier` accepts. Removing an algorithm from this list will cause wallet login requests using that algorithm to fail with a `ValueError`.
