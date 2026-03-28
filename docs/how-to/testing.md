# Testing with pico-server-auth

How to test your application that uses pico-server-auth in pytest.

## Setup

Install test dependencies:

```bash
pip install pico-server-auth[test]
pip install httpx pytest pytest-asyncio
```

## End-to-End Test with AsyncClient

Use httpx `AsyncClient` with `ASGITransport` to test the full auth flow without a running server.

```python
import pytest
from httpx import ASGITransport, AsyncClient
from pico_boot import Application


@pytest.fixture
def app():
    return Application(
        module_names=["pico_server_auth", "pico_client_auth", "my_app"],
        config={
            "server_auth": {
                "issuer": "http://testserver",
                "audience": "test",
                "auto_create_admin": True,
                "admin_email": "test@test.com",
                "admin_password": "test123",
                "challenge_ttl_seconds": 300,
            },
            "auth_client": {
                "issuer": "http://testserver",
                "audience": "test",
                "jwks_url": "http://testserver/api/v1/auth/jwks",
            },
        },
    )


@pytest.fixture
async def client(app):
    transport = ASGITransport(app=app.fastapi_app)
    async with AsyncClient(transport=transport, base_url="http://testserver") as c:
        yield c


@pytest.mark.asyncio
async def test_admin_login(client):
    resp = await client.post(
        "/api/v1/auth/login",
        json={"email": "test@test.com", "password": "test123"},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert "access_token" in data
    assert "refresh_token" in data


@pytest.mark.asyncio
async def test_protected_endpoint_with_token(client):
    # Login to get a token
    login_resp = await client.post(
        "/api/v1/auth/login",
        json={"email": "test@test.com", "password": "test123"},
    )
    token = login_resp.json()["access_token"]

    # Access protected endpoint
    resp = await client.get(
        "/api/profile",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code == 200
```

## Testing Wallet Auth Flow

```python
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat


@pytest.mark.asyncio
async def test_wallet_auth_ed25519(client):
    address = "0xTestWallet001"

    # 1. Request challenge
    resp = await client.post(
        "/api/v1/auth/challenge",
        json={"address": address},
    )
    assert resp.status_code == 200
    challenge = resp.json()["challenge"]

    # 2. Sign challenge
    private_key = Ed25519PrivateKey.generate()
    public_key = private_key.public_key()
    message = challenge.encode("utf-8")
    signature = private_key.sign(message)

    public_key_hex = public_key.public_bytes(Encoding.Raw, PublicFormat.Raw).hex()
    signature_hex = signature.hex()

    # 3. Verify and login
    resp = await client.post(
        "/api/v1/auth/sign-in",
        json={
            "address": address,
            "public_key": public_key_hex,
            "signature": signature_hex,
            "challenge": challenge,
            "algorithm": "Ed25519",
        },
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["address"] == address
    assert data["algorithm"] == "Ed25519"
    assert "access_token" in data


@pytest.mark.asyncio
async def test_expired_challenge(client):
    address = "0xTestWallet002"

    # Request challenge
    resp = await client.post("/api/v1/auth/challenge", json={"address": address})
    challenge = resp.json()["challenge"]

    # Try to use a wrong nonce
    resp = await client.post(
        "/api/v1/auth/sign-in",
        json={
            "address": address,
            "public_key": "aa" * 32,
            "signature": "bb" * 64,
            "challenge": "wrong-nonce",
            "algorithm": "Ed25519",
        },
    )
    assert resp.status_code == 401
    assert resp.json()["detail"] == "invalid or expired challenge"
```

## Unit Testing Components Directly

You can also test components in isolation:

```python
from pico_server_auth import (
    InMemoryChallengeStore,
    ServerAuthSettings,
    TokenIssuer,
    WalletVerifier,
)


def test_challenge_store():
    settings = ServerAuthSettings(challenge_ttl_seconds=60)
    store = InMemoryChallengeStore(settings)

    nonce = store.create("0xTest")
    assert store.validate("0xTest", nonce) is True
    # Second validation fails (single-use)
    assert store.validate("0xTest", nonce) is False


def test_token_issuer():
    settings = ServerAuthSettings(
        issuer="http://test",
        audience="test",
        access_token_expire_minutes=15,
    )
    issuer = TokenIssuer(settings)

    token = issuer.issue_access_token(subject="user@test.com", role="admin")
    assert isinstance(token, str)
    assert token.count(".") == 2  # JWT format

    jwks = issuer.jwks()
    assert len(jwks["keys"]) == 1
    assert jwks["keys"][0]["kid"] == "pico-server-auth-1"
```
