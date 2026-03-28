# Changelog

All notable changes to pico-server-auth will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
