# Pico-Server-Auth

**Embeddable auth server module for pico-boot applications.**

pico-server-auth provides JWT issuance, wallet-based challenge/verify authentication, password login, and a JWKS endpoint — all as auto-discovered FastAPI controllers that plug into any pico-boot app.

Tokens issued by pico-server-auth are validated by [pico-client-auth](https://github.com/dperezcabrera/pico-client-auth), whether running in the same process or across services.

## Quick Install

```bash
pip install pico-server-auth
```

## 30-Second Example — Embedded Mode

Run pico-server-auth inside your pico-boot application alongside your own controllers:

```python
from pico_boot import Application

app = Application(
    module_names=[
        "pico_server_auth",   # Auth server endpoints
        "pico_client_auth",   # JWT validation middleware
        "my_app",             # Your controllers
    ],
    config={
        "server_auth": {
            "issuer": "http://localhost:8100",
            "audience": "my-app",
            "challenge_ttl_seconds": 60,
        },
        "auth_client": {
            "issuer": "http://localhost:8100",
            "audience": "my-app",
            "jwks_url": "http://localhost:8100/auth/jwks",
        },
    },
)

app.run()
```

This gives you:

| Endpoint | Description |
|---|---|
| `POST /auth/challenge` | Request a challenge nonce for wallet auth |
| `POST /auth/wallet` | Verify wallet signature and receive JWT |
| `POST /auth/login` | Password login (admin bootstrap) |
| `GET /auth/jwks` | JWKS public keys for token validation |

## Supported Wallet Algorithms

- **ML-DSA-65** — Post-quantum (NIST FIPS 204)
- **Ed25519** — Edwards-curve Digital Signature Algorithm
- **secp256k1** — Elliptic curve used by Bitcoin/Ethereum

## Next Steps

- [Getting Started](getting-started.md) — Installation and setup
- [Wallet Auth Guide](user-guide/wallet-auth.md) — Full challenge/verify flow
- [Embed in App](how-to/embed-in-app.md) — Embed alongside your controllers
- [Configuration Reference](reference/config.md) — All settings
