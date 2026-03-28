# FAQ

## What is the difference between embedded and standalone mode?

**Embedded mode**: pico-server-auth runs in the same pico-boot process as your application controllers and pico-client-auth. The JWKS endpoint is available locally. This is the simplest setup for single-service applications.

**Standalone mode**: pico-server-auth runs as a dedicated auth microservice. Other services configure their pico-client-auth to fetch JWKS remotely via HTTP. This suits multi-service architectures where you want centralized auth.

## What is the challenge TTL?

The challenge TTL (`challenge_ttl_seconds`, default: 60) controls how long a challenge nonce remains valid after creation. If the wallet client does not sign and submit the challenge within this window, the nonce expires and the client must request a new one.

Expired challenges are cleaned up automatically on each `create()` call.

## How do I replace the in-memory challenge store?

Implement the `ChallengeStore` protocol and register your implementation as a pico-ioc component:

```python
from pico_ioc import component
from pico_server_auth import ChallengeStore

@component(on_missing_selector=ChallengeStore)
class RedisChallengeStore:
    def create(self, address: str) -> str: ...
    def validate(self, address: str, nonce: str) -> bool: ...
    def cleanup(self) -> int: ...
```

See [Custom Challenge Store](how-to/custom-challenge-store.md) for a full example.

## Which wallet algorithms are supported?

pico-server-auth supports three signature algorithms out of the box:

| Algorithm | Description | Library |
|---|---|---|
| **ML-DSA-65** | Post-quantum lattice-based (NIST FIPS 204) | `cryptography.hazmat.primitives.asymmetric.mldsa` |
| **Ed25519** | Edwards-curve Digital Signature Algorithm | `cryptography.hazmat.primitives.asymmetric.ed25519` |
| **secp256k1** | Elliptic curve (ECDSA) | `cryptography.hazmat.primitives.asymmetric.ec` |

The set of accepted algorithms is controlled by `ServerAuthSettings.supported_wallet_algorithms`.

## Is pico-server-auth compatible with pico-client-auth?

Yes. Tokens issued by pico-server-auth are designed to be validated by pico-client-auth. Ensure the `issuer` and `audience` settings match between the two. pico-client-auth fetches the public keys from the `/auth/jwks` endpoint to verify token signatures.

## What signing algorithm does pico-server-auth use for JWTs?

RS256 (RSA with SHA-256). A fresh RSA-2048 keypair is generated on each startup. The public key is exposed via the JWKS endpoint with key ID `pico-server-auth-1`.

## Is password login enabled by default?

No. The `POST /auth/login` endpoint requires `auto_create_admin: true` in `ServerAuthSettings`. When disabled (the default), the endpoint returns `403 Forbidden`.

## Can I use pico-server-auth without pico-boot?

pico-server-auth is designed around pico-boot's auto-discovery and dependency injection. While the individual components (`TokenIssuer`, `WalletVerifier`, etc.) can be instantiated manually, the recommended approach is to use pico-boot.

## Why does TokenIssuer generate a new keypair on every startup?

This is the default behavior for simplicity. In production, you may want to persist keys or use a key management service. The current design ensures zero-config startup at the cost of invalidating existing tokens on restart.
