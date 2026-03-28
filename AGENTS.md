# pico-server-auth

Embeddable auth server module for pico-boot. JWT issuance, wallet challenge/verify login, password login, and JWKS endpoint as FastAPI controllers.

## Commands

```bash
pip install -e ".[test]"          # Install in dev mode
pytest tests/ -v                  # Run tests
pytest --cov=pico_server_auth --cov-report=term-missing tests/  # Coverage
tox                               # Full matrix (3.11-3.14)
```

## Project Structure

```
src/pico_server_auth/
  __init__.py          # Public API exports (ChallengeStore, InMemoryChallengeStore, ServerAuthSettings, TokenIssuer, WalletVerifier)
  config.py            # ServerAuthSettings (@configured, prefix="server_auth", mapping="tree")
  controllers.py       # AuthController (@controller, prefix="/auth") — jwks, challenge, wallet_login, password_login
  challenge_store.py   # ChallengeStore protocol + InMemoryChallengeStore (@component)
  wallet_verifier.py   # WalletVerifier (@component) — ML-DSA-65, Ed25519, secp256k1
  token_issuer.py      # TokenIssuer (@component) — RS256 JWT signing + JWKS export
```

## Key Concepts

- **`AuthController`**: FastAPI controller with `prefix="/auth"`. All endpoints are `@allow_anonymous` (public auth API).
- **`ServerAuthSettings`**: Configured via `@configured(prefix="server_auth")`. Fields: issuer, audience, algorithm, access_token_expire_minutes, refresh_token_expire_days, challenge_ttl_seconds, auto_create_admin, admin_email, admin_password, supported_wallet_algorithms.
- **`ChallengeStore`**: Protocol for challenge nonce storage. Default `InMemoryChallengeStore` uses dict with TTL. Replace with Redis/DB by registering a `@component` that implements the protocol.
- **`WalletVerifier`**: Verifies wallet signatures. Lazy-loads crypto backends (`cryptography` library) on first use.
- **`TokenIssuer`**: Generates RSA-2048 keypair at startup. Issues access tokens (configurable expiry) and refresh tokens. Exports JWKS for pico-client-auth.
- **Embedded mode**: pico-server-auth runs inside the same pico-boot process as your app controllers.
- **Standalone mode**: pico-server-auth runs as a dedicated auth service; other services fetch JWKS remotely.

## Code Style

- Python 3.11+
- Async endpoints in controller, sync internals for crypto operations
- Use pico-ioc's `@component`, `@configured` decorators
- Use pico-fastapi's `@controller`, `@get`, `@post` decorators
- Error responses: JSON `{"detail": "..."}` via FastAPI `HTTPException`

## Testing

- pytest + pytest-asyncio (mode=auto)
- RSA keypair fixture for token signing
- Mock ChallengeStore for controller tests
- httpx AsyncClient with ASGITransport for e2e tests

## Boundaries

- Do not modify `_version.py`
- Public API is defined in `__init__.py` — ChallengeStore, InMemoryChallengeStore, ServerAuthSettings, TokenIssuer, WalletVerifier
- No direct dependency on pico-boot (uses entry point for auto-discovery)
- Depends on pico-client-auth only for `@allow_anonymous` decorator
