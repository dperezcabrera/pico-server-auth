# Architecture

## Component Overview

```mermaid
graph TB
    subgraph "pico-server-auth"
        AC[AuthController<br/>/auth/*]
        TI[TokenIssuer<br/>RS256 JWT signing]
        WV[WalletVerifier<br/>ML-DSA-65, Ed25519, secp256k1]
        CS[ChallengeStore<br/>Nonce storage + TTL]
        SAS[ServerAuthSettings<br/>Configuration]
    end

    AC --> TI
    AC --> WV
    AC --> CS
    TI --> SAS
    WV --> SAS
    CS --> SAS

    Client([Client / Wallet]) -->|POST /auth/challenge| AC
    Client -->|POST /auth/wallet| AC
    Client -->|POST /auth/login| AC

    subgraph "pico-client-auth"
        TV[TokenValidator]
        JC[JWKSClient]
    end

    JC -->|GET /auth/jwks| AC
    TV --> JC
```

## How It Fits with pico-client-auth

pico-server-auth **issues** tokens. pico-client-auth **validates** them. They connect via the JWKS endpoint.

**Embedded mode** (same process):

```mermaid
graph LR
    subgraph "pico-boot Application"
        SA[pico-server-auth<br/>Issues JWTs]
        CA[pico-client-auth<br/>Validates JWTs]
        APP[Your Controllers]
    end

    SA -->|JWKS via /auth/jwks| CA
    CA -->|SecurityContext| APP
```

**Standalone mode** (separate services):

```mermaid
graph LR
    subgraph "Auth Service"
        SA[pico-server-auth]
    end

    subgraph "API Service"
        CA[pico-client-auth]
        APP[Your Controllers]
    end

    SA -->|JWKS via HTTPS| CA
    CA -->|SecurityContext| APP
```

## Wallet Challenge/Verify Flow

```mermaid
sequenceDiagram
    participant W as Wallet Client
    participant A as AuthController
    participant CS as ChallengeStore
    participant WV as WalletVerifier
    participant TI as TokenIssuer

    W->>A: POST /auth/challenge {"address": "0x..."}
    A->>CS: create(address) -> nonce
    A-->>W: {"challenge": "<nonce>", "ttl": 60}

    Note over W: Sign nonce with private key

    W->>A: POST /auth/wallet {"address", "public_key", "signature", "challenge", "algorithm"}
    A->>CS: validate(address, nonce)
    CS-->>A: true (nonce consumed)
    A->>WV: verify(algorithm, public_key, message, signature)
    WV-->>A: true
    A->>TI: issue_access_token(subject=address, role="wallet")
    A->>TI: issue_refresh_token(subject=address)
    TI-->>A: access_token, refresh_token
    A-->>W: {"access_token", "refresh_token", "address", "algorithm"}
```

## Token Issuance

`TokenIssuer` generates a fresh RSA-2048 keypair on startup (key ID: `pico-server-auth-1`). Access tokens include:

| Claim | Source |
|---|---|
| `sub` | Wallet address or email |
| `iss` | `ServerAuthSettings.issuer` |
| `aud` | `ServerAuthSettings.audience` |
| `iat` | Current timestamp |
| `exp` | `iat + access_token_expire_minutes * 60` |
| `role` | `"wallet"` or `"admin"` |
| `algorithm` | Wallet algorithm (wallet login only) |
| `wallet_address` | Wallet address (wallet login only) |

Refresh tokens include `sub`, `iss`, `aud`, `iat`, `exp`, and `"type": "refresh"`.

## Challenge Store

The `ChallengeStore` protocol defines three methods:

- `create(address) -> str` — Generate and store a nonce for the given address.
- `validate(address, nonce) -> bool` — Consume and verify a nonce (one-time use).
- `cleanup() -> int` — Remove expired entries, return count removed.

The default `InMemoryChallengeStore` stores challenges in a dict with timestamps. Each `create()` call triggers `cleanup()` to prune expired entries. Challenges are single-use: `validate()` removes the entry on lookup.

## Dependency Graph

```
pico-server-auth
  +-- pico-ioc >= 2.2.0        (DI container, @component, @configured)
  +-- pico-fastapi              (@controller, @get, @post)
  +-- pico-client-auth          (@allow_anonymous decorator)
  +-- cryptography              (RSA keys, ML-DSA-65, Ed25519, secp256k1)
  +-- python-jose               (JWT encoding)
```
