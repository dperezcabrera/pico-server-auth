# Getting Started

## Prerequisites

- Python 3.11+
- [pico-boot](https://github.com/dperezcabrera/pico-boot) for application bootstrapping
- [pico-client-auth](https://github.com/dperezcabrera/pico-client-auth) for JWT validation middleware

## Installation

```bash
pip install pico-server-auth
```

This installs pico-server-auth along with its dependencies: `pico-ioc`, `pico-fastapi`, `pico-client-auth`, `cryptography`, and `python-jose`.

## Key Concepts

| Concept | Description |
|---|---|
| `ServerAuthSettings` | Configuration dataclass with `@configured(prefix="server_auth")`. Controls issuer, audience, token expiry, challenge TTL, and admin credentials. |
| `AuthController` | FastAPI controller at `/auth` with endpoints for JWKS, challenge, wallet login, and password login. |
| `TokenIssuer` | Generates RSA-2048 keypair at startup. Signs access and refresh JWTs. Exports JWKS. |
| `WalletVerifier` | Verifies wallet signatures for ML-DSA-65, Ed25519, and secp256k1. |
| `ChallengeStore` | Protocol for challenge nonce storage. Default `InMemoryChallengeStore` uses TTL-based expiry. |
| Embedded mode | pico-server-auth runs inside the same pico-boot process as your app. |
| Standalone mode | pico-server-auth runs as a dedicated service; others fetch JWKS remotely. |

## Basic Setup — Embedded Mode

The most common setup: embed pico-server-auth in your pico-boot application so auth endpoints and your business logic share the same process.

```python
from pico_boot import Application

app = Application(
    module_names=[
        "pico_server_auth",   # Provides /auth/* endpoints
        "pico_client_auth",   # Validates JWTs on incoming requests
        "my_app",             # Your controllers
    ],
    config={
        "server_auth": {
            "issuer": "http://localhost:8100",
            "audience": "my-app",
            "access_token_expire_minutes": 15,
            "refresh_token_expire_days": 7,
            "challenge_ttl_seconds": 60,
        },
        "auth_client": {
            "issuer": "http://localhost:8100",
            "audience": "my-app",
            "jwks_url": "http://localhost:8100/api/v1/auth/jwks",
        },
    },
)

app.run()
```

!!! tip "Matching issuer and audience"
    Set `server_auth.issuer` and `auth_client.issuer` to the same value (and likewise for `audience`) so tokens issued by pico-server-auth are accepted by pico-client-auth.

## Basic Setup — Standalone Mode

Run pico-server-auth as a dedicated auth microservice:

```python
from pico_boot import Application

app = Application(
    module_names=["pico_server_auth"],
    config={
        "server_auth": {
            "issuer": "https://auth.example.com",
            "audience": "my-platform",
        },
    },
)

app.run()
```

Other services configure their pico-client-auth to point at this service's JWKS:

```python
# In each downstream service
config = {
    "auth_client": {
        "issuer": "https://auth.example.com",
        "audience": "my-platform",
        "jwks_url": "https://auth.example.com/api/v1/auth/jwks",
    },
}
```

## Next Steps

- [Wallet Auth](user-guide/wallet-auth.md) — Full challenge/verify flow
- [Password Auth](user-guide/password-auth.md) — Admin login
- [Configuration Reference](reference/config.md) — All settings
