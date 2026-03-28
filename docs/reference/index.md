# Reference

API reference for pico-server-auth components.

## Sections

- [Configuration](config.md) — All `ServerAuthSettings` fields and their defaults.
- [Endpoints](endpoints.md) — HTTP endpoints with request/response examples.

## Public API

The following are exported from `pico_server_auth`:

| Symbol | Type | Description |
|---|---|---|
| `ServerAuthSettings` | Dataclass | Configuration with `@configured(prefix="server_auth")` |
| `ChallengeStore` | Protocol | Interface for challenge nonce storage |
| `InMemoryChallengeStore` | Class | Default in-memory implementation of `ChallengeStore` |
| `TokenIssuer` | Class | JWT signing and JWKS export |
| `WalletVerifier` | Class | Signature verification for wallet algorithms |
