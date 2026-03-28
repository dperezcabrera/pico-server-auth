# pico-server-auth

[![PyPI](https://img.shields.io/pypi/v/pico-server-auth.svg)](https://pypi.org/project/pico-server-auth/)
[![Ask DeepWiki](https://deepwiki.com/badge.svg)](https://deepwiki.com/dperezcabrera/pico-server-auth)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)
![CI](https://github.com/dperezcabrera/pico-server-auth/actions/workflows/ci.yml/badge.svg)
[![codecov](https://codecov.io/gh/dperezcabrera/pico-server-auth/branch/main/graph/badge.svg)](https://codecov.io/gh/dperezcabrera/pico-server-auth)
[![Quality Gate Status](https://sonarcloud.io/api/project_badges/measure?project=dperezcabrera_pico-server-auth&metric=alert_status)](https://sonarcloud.io/summary/new_code?id=dperezcabrera_pico-server-auth)
[![Duplicated Lines (%)](https://sonarcloud.io/api/project_badges/measure?project=dperezcabrera_pico-server-auth&metric=duplicated_lines_density)](https://sonarcloud.io/summary/new_code?id=dperezcabrera_pico-server-auth)
[![Maintainability Rating](https://sonarcloud.io/api/project_badges/measure?project=dperezcabrera_pico-server-auth&metric=sqale_rating)](https://sonarcloud.io/summary/new_code?id=dperezcabrera_pico-server-auth)
[![PyPI Downloads](https://static.pepy.tech/personalized-badge/pico-server-auth?period=monthly&units=INTERNATIONAL_SYSTEM&left_color=BLACK&right_color=GREEN&left_text=Monthly+downloads)](https://pepy.tech/projects/pico-server-auth)
[![Docs](https://img.shields.io/badge/Docs-pico--server--auth-blue?style=flat&logo=readthedocs&logoColor=white)](https://dperezcabrera.github.io/pico-server-auth/)
[![Interactive Lab](https://img.shields.io/badge/Learn-online-green?style=flat&logo=python&logoColor=white)](https://dperezcabrera.github.io/pico-learn/)

Embeddable auth server module for the [pico-boot](https://github.com/dperezcabrera/pico-boot) ecosystem.

Issues JWT tokens, handles wallet challenge-response login, and exposes JWKS — all compatible with [pico-client-auth](https://github.com/dperezcabrera/pico-client-auth) validation.

## Two deployment modes

**Embedded** — add to any pico-boot app, auth runs in the same process:

```python
container = init(modules=["myapp", "pico_server_auth"], config=config)
# /auth/jwks, /auth/challenge, /auth/wallet, /auth/login — all available
# pico-client-auth validates tokens from the same JWKS
```

**Standalone** — deploy as a separate auth service (like pico-auth):

```python
container = init(modules=["pico_server_auth"], config=config)
app = container.get(FastAPI)
# Other services point pico-client-auth JWKS to this service's /auth/jwks
```

## Endpoints

```
GET  /auth/jwks           JWKS public keys (pico-client-auth fetches this)
POST /auth/challenge      Request nonce for wallet login
POST /auth/wallet         Verify wallet signature, issue JWT
POST /auth/login          Password login (admin bootstrap)
```

## Wallet login flow

```
Client                    pico-server-auth
  │                            │
  │ POST /auth/challenge       │
  │ { address: "0x..." }       │
  │───────────────────────────>│
  │ { challenge: "<nonce>" }   │
  │<───────────────────────────│
  │                            │
  │ sign(nonce) with wallet    │
  │                            │
  │ POST /auth/wallet          │
  │ { address, public_key,     │
  │   signature, challenge,    │
  │   algorithm: "ML-DSA-65" } │
  │───────────────────────────>│
  │ { access_token, address }  │
  │<───────────────────────────│
```

## Supported wallet algorithms

| Algorithm | Chain | Library |
|-----------|-------|---------|
| ML-DSA-65 | Dilithia (post-quantum) | `cryptography` |
| Ed25519 | Solana | `cryptography` |
| secp256k1 | Ethereum | `cryptography` |

## Compatibility with pico-client-auth

Tokens issued by pico-server-auth are standard JWT (RS256). pico-client-auth validates them by fetching JWKS from the `/auth/jwks` endpoint.

**Same process**: pico-client-auth discovers the JWKS endpoint automatically (same FastAPI app).

**Separate processes**: configure pico-client-auth to point to the server:

```yaml
auth_client:
  issuer: "http://auth-server:8100"
  audience: "pico"
  # JWKS fetched from http://auth-server:8100/auth/jwks
```

## Challenge store

By default, challenges are stored in memory with TTL expiry. For multi-instance deployments, register a custom `ChallengeStore` component:

```python
@component
class RedisChallengeStore:
    async def create(self, address: str) -> str: ...
    async def validate(self, address: str, nonce: str) -> bool: ...
    async def cleanup(self) -> int: ...
```

The in-memory default is replaced automatically via `on_missing_selector`.

## Configuration

```yaml
server_auth:
  issuer: "http://localhost:8100"
  audience: "pico"
  algorithm: "RS256"
  access_token_expire_minutes: 15
  challenge_ttl_seconds: 60
  supported_wallet_algorithms:
    - "ML-DSA-65"
    - "Ed25519"
    - "secp256k1"
```

## Stack

- [pico-ioc](https://github.com/dperezcabrera/pico-ioc) — dependency injection
- [pico-boot](https://github.com/dperezcabrera/pico-boot) — auto-discovery
- [pico-fastapi](https://github.com/dperezcabrera/pico-fastapi) — controllers
- [pico-client-auth](https://github.com/dperezcabrera/pico-client-auth) — token validation

## License

MIT
