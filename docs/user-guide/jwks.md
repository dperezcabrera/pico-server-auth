# JWKS Endpoint

The JWKS (JSON Web Key Set) endpoint at `GET /auth/jwks` exposes the public keys used by `TokenIssuer` to sign JWTs. This is the bridge between pico-server-auth (token issuer) and pico-client-auth (token validator).

## How It Works

1. `TokenIssuer` generates an RSA-2048 keypair on startup.
2. The public key is served as a JWKS at `/auth/jwks`.
3. pico-client-auth's `JWKSClient` fetches this endpoint to obtain the public key.
4. Incoming JWTs are validated using the fetched public key.

## Response Format

```json
{
  "keys": [
    {
      "kty": "RSA",
      "kid": "pico-server-auth-1",
      "alg": "RS256",
      "use": "sig",
      "n": "<base64url-encoded RSA modulus>",
      "e": "AQAB"
    }
  ]
}
```

## Fetching JWKS

```python
import httpx

async def fetch_jwks(base_url: str) -> dict:
    async with httpx.AsyncClient() as client:
        resp = await client.get(f"{base_url}/auth/jwks")
        resp.raise_for_status()
        return resp.json()
```

## pico-client-auth Configuration

Point pico-client-auth's `jwks_url` at the JWKS endpoint:

**Embedded mode** (same process):

```python
config = {
    "auth_client": {
        "issuer": "http://localhost:8100",
        "audience": "my-app",
        "jwks_url": "http://localhost:8100/auth/jwks",
    },
}
```

**Standalone mode** (remote auth service):

```python
config = {
    "auth_client": {
        "issuer": "https://auth.example.com",
        "audience": "my-platform",
        "jwks_url": "https://auth.example.com/auth/jwks",
    },
}
```

## Key Rotation

The current implementation generates a new keypair on each startup with a fixed key ID (`pico-server-auth-1`). This means:

- Tokens issued before a restart become invalid after restart.
- pico-client-auth's `JWKSClient` will force-refresh its cache when it encounters an unknown `kid` in a JWT header.

!!! tip "Production key management"
    For production deployments where tokens must survive restarts, consider persisting the RSA keypair externally and loading it into `TokenIssuer` at startup.

## Direct Access (In-Process)

When running in embedded mode, you can also access the JWKS directly from the `TokenIssuer` component without an HTTP call:

```python
from pico_server_auth import TokenIssuer

# Via dependency injection in your own component
class MyComponent:
    def __init__(self, issuer: TokenIssuer):
        jwks = issuer.jwks()
        # {"keys": [{"kty": "RSA", ...}]}
```
