# Changelog

All notable changes to pico-server-auth will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- `__all__` declares the public API and `tests/test_exports.py` pins it, per the ecosystem stability policy (ADR-014 in pico-ioc).

### Documentation
- `docs/architecture.md` links the ADR-014 stability and deprecation policy.

## [0.2.1] - 2026-07-12

### Fixed

- **Configuring `algorithm: ML-DSA-65` or `ML-DSA-87` now fails fast at startup** with `NotImplementedError` and a clear message. Post-quantum token ISSUING was never implemented: the issuer silently booted with no keys and crashed with an opaque `AttributeError` on the first login or JWKS request. Wallet VERIFICATION of ML-DSA signatures is unaffected and keeps working.

## [0.2.0] - 2026-07-10

### Changed

- JWT backend migrated from python-jose (unmaintained: no release in 14 months) to PyJWT (`PyJWT[crypto] >= 2.8`). Token format, claims and JWKS are unchanged — tokens issued before the migration keep validating. Exception mapping: `jose.JWTError` -> `jwt.PyJWTError`.

## [0.1.2] - 2026-06-07

### Added
- **Fleet session-token mint** — `POST /api/v1/auth/fleet/sessions`, gated by a shared secret in the `X-Fleet-Secret` header (config `server_auth.fleet_mint_secret`; empty disables the endpoint). Intended caller is fleet-runtime.
- **`jti` revocation** — `POST /api/v1/auth/revoke` (operator-gated) and `GET /api/v1/auth/revoked-jtis` (polled by pico-client-auth). Backed by a `RevocationStore` (in-memory or JSONL via `revocation_store_path`).
- **Mint audit log** — `GET /api/v1/auth/mints` lists currently-valid long-lived tokens for the operator's "live tokens" view. Backed by a `MintAuditStore` (in-memory or JSONL via `mint_audit_path`); ephemeral mints below `mint_audit_min_ttl_seconds` are filtered out.
- New config: `admin_role` (default `"operator"`), `fleet_mint_secret`, `fleet_session_ttl_seconds`, `fleet_max_ttl_seconds`, `revocation_store_path`, `mint_audit_path`, `mint_audit_min_ttl_seconds`, `mint_audit_max_in_memory`.

### Changed
- Password-login tokens are now stamped with the configurable `admin_role` (default `"operator"`) instead of a hardcoded `"admin"`.
- Declared the `pico-client-auth` dependency explicitly in `pyproject.toml` (was imported by `controllers.py` but undeclared).

## [0.1.1] - 2026-03-28

### Changed
- Standardized API routes under `/api/v1/auth/` prefix.
- Renamed sign-in endpoint for consistency.
- Docs reference algorithms only, no chain-specific naming.

### Fixed
- CI coverage merge with tox path normalization in `.coveragerc`.
- MkDocs strict mode failure due to missing `CHANGELOG.md` symlink.
- Python 3.14 added to test matrix.
- Removed redundant `pico_server_auth` from `modules=[]` examples.

## [0.1.0] - 2026-03-28

### Added

- `AuthController` with `/api/v1/auth/jwks`, `/api/v1/auth/challenge`, `/api/v1/auth/sign-in`, and `/api/v1/auth/login` endpoints.
- `ServerAuthSettings` configuration with `@configured(prefix="server_auth")`.
- `TokenIssuer` for RS256 JWT access and refresh token issuance.
- `WalletVerifier` with support for ML-DSA-65, Ed25519, and secp256k1 signature verification.
- `ChallengeStore` protocol with `InMemoryChallengeStore` default implementation.
- JWKS endpoint compatible with pico-client-auth token validation.
- Password-based admin login with configurable credentials.
- Auto-discovery via `pico_boot.modules` entry point.

[0.1.1]: https://github.com/dperezcabrera/pico-server-auth/releases/tag/v0.1.1
[0.1.0]: https://github.com/dperezcabrera/pico-server-auth/releases/tag/v0.1.0
