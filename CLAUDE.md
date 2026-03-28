Read and follow ./AGENTS.md for project conventions.

## Pico Ecosystem Context

pico-server-auth is an embeddable auth server module for pico-boot applications. It provides:
- JWT issuance (RS256) via `TokenIssuer`
- Wallet challenge/verify login (ML-DSA-65, Ed25519, secp256k1) via `WalletVerifier`
- Password-based admin login via `AuthController`
- JWKS endpoint for pico-client-auth token validation
- In-memory `ChallengeStore` with TTL expiry (replaceable via protocol)

It uses:
- `@component`, `@configured` from pico-ioc
- `@controller`, `@get`, `@post` from pico-fastapi
- `@allow_anonymous` from pico-client-auth
- Auto-discovered via `pico_boot.modules` entry point

## Key Components

- **`ServerAuthSettings`**: `@configured(prefix="server_auth")` — issuer, audience, algorithm, TTLs, admin credentials, supported wallet algorithms
- **`AuthController`**: `@controller(prefix="/auth")` — endpoints: `/auth/jwks`, `/auth/challenge`, `/auth/wallet`, `/auth/login`
- **`TokenIssuer`**: `@component` — RSA key generation, JWT signing, JWKS export
- **`WalletVerifier`**: `@component` — signature verification for ML-DSA-65, Ed25519, secp256k1
- **`ChallengeStore`**: Protocol with `InMemoryChallengeStore` default (`@component(on_missing_selector=ChallengeStore)`)

## Key Reminders

- **NEVER change `version_scheme`** in pyproject.toml. It MUST remain `"post-release"`.
- requires-python >= 3.11
- Commit messages: one line only
- Tokens issued here are compatible with pico-client-auth validation (same issuer/audience)
- `ChallengeStore` is a Protocol — users can replace with Redis/DB by registering their own `@component`
- `WalletVerifier` lazy-loads crypto backends to avoid hard dependencies
- `TokenIssuer` generates a fresh RSA keypair on startup (key ID: `pico-server-auth-1`)
