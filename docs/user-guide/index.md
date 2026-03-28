# User Guide

pico-server-auth provides three authentication modes, each suited to different use cases.

## Authentication Modes

### Wallet Authentication

Challenge/verify flow for cryptographic wallet login. The client requests a challenge nonce, signs it with their private key, and submits the signature for verification. On success, the server issues a JWT.

Supported algorithms: **ML-DSA-65**, **Ed25519**, **secp256k1**.

[Wallet Auth Guide](wallet-auth.md){ .md-button }

### Password Authentication

Simple email/password login for admin bootstrap. Disabled by default — enable with `auto_create_admin: true`. Intended for initial setup, not production user management.

[Password Auth Guide](password-auth.md){ .md-button }

### JWKS (JSON Web Key Set)

The `/api/v1/auth/jwks` endpoint exposes the public key set used to sign JWTs. pico-client-auth fetches this endpoint to validate tokens, whether running in the same process or remotely.

[JWKS Guide](jwks.md){ .md-button }

## Choosing a Mode

| Mode | Use Case | Endpoint |
|---|---|---|
| Wallet | Decentralized identity, Web3, post-quantum auth | `POST /api/v1/auth/challenge` + `POST /api/v1/auth/sign-in` |
| Password | Admin bootstrap, development | `POST /api/v1/auth/login` |
| JWKS | Token validation by pico-client-auth | `GET /api/v1/auth/jwks` |
