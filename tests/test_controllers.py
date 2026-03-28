import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi import FastAPI
from fastapi.testclient import TestClient
from pico_boot import init
from pico_ioc import DictSource, configuration


@pytest.fixture(scope="module")
def app():
    config = configuration(
        DictSource(
            {
                "fastapi": {"title": "test", "version": "0.1.0"},
                "auth_client": {"enabled": False, "issuer": "http://test", "audience": "test"},
                "server_auth": {
                    "issuer": "http://test",
                    "audience": "test",
                    "auto_create_admin": True,
                    "admin_email": "admin@test.com",
                    "admin_password": "secret",
                    "challenge_ttl_seconds": 30,
                },
                # Config for auto-discovered plugins that may be installed
                "database": {"url": "sqlite+aiosqlite:///test_auth.db", "echo": False},
                "celery": {"broker_url": "memory://", "backend_url": "cache+memory://"},
            }
        )
    )
    container = init(modules=["pico_server_auth"], config=config)
    return container.get(FastAPI)


@pytest.fixture(scope="module")
def client(app):
    return TestClient(app)


# --- JWKS ---


def test_jwks_returns_keys(client):
    r = client.get("/auth/jwks")
    assert r.status_code == 200
    data = r.json()
    assert "keys" in data
    assert len(data["keys"]) == 1
    key = data["keys"][0]
    assert key["kty"] == "RSA"
    assert key["alg"] == "RS256"


# --- Challenge ---


def test_challenge_returns_nonce(client):
    r = client.post("/auth/challenge", json={"address": "0xabc"})
    assert r.status_code == 200
    data = r.json()
    assert "challenge" in data
    assert "ttl" in data
    assert len(data["challenge"]) == 64


def test_challenge_requires_address(client):
    r = client.post("/auth/challenge", json={})
    assert r.status_code == 400


# --- Wallet login ---


def test_wallet_login_ed25519(client):
    # Get challenge
    r = client.post("/auth/challenge", json={"address": "0xed25519"})
    nonce = r.json()["challenge"]

    # Sign
    sk = Ed25519PrivateKey.generate()
    pk = sk.public_key()
    signature = sk.sign(nonce.encode("utf-8"))

    r = client.post(
        "/auth/wallet",
        json={
            "address": "0xed25519",
            "public_key": pk.public_bytes_raw().hex(),
            "signature": signature.hex(),
            "challenge": nonce,
            "algorithm": "Ed25519",
        },
    )
    assert r.status_code == 200
    data = r.json()
    assert "access_token" in data
    assert "refresh_token" in data
    assert data["address"] == "0xed25519"
    assert data["algorithm"] == "Ed25519"


def test_wallet_login_invalid_challenge(client):
    sk = Ed25519PrivateKey.generate()
    pk = sk.public_key()
    signature = sk.sign(b"wrong")

    r = client.post(
        "/auth/wallet",
        json={
            "address": "0xbad",
            "public_key": pk.public_bytes_raw().hex(),
            "signature": signature.hex(),
            "challenge": "nonexistent",
            "algorithm": "Ed25519",
        },
    )
    assert r.status_code == 401


def test_wallet_login_invalid_signature(client):
    r = client.post("/auth/challenge", json={"address": "0xbadsig"})
    nonce = r.json()["challenge"]

    sk = Ed25519PrivateKey.generate()
    pk = sk.public_key()
    # Sign wrong message
    signature = sk.sign(b"wrong message")

    r = client.post(
        "/auth/wallet",
        json={
            "address": "0xbadsig",
            "public_key": pk.public_bytes_raw().hex(),
            "signature": signature.hex(),
            "challenge": nonce,
            "algorithm": "Ed25519",
        },
    )
    assert r.status_code == 401


def test_wallet_login_missing_fields(client):
    r = client.post("/auth/wallet", json={"address": "0x"})
    assert r.status_code == 400


# --- Password login ---


def test_password_login_success(client):
    r = client.post("/auth/login", json={"email": "admin@test.com", "password": "secret"})
    assert r.status_code == 200
    data = r.json()
    assert "access_token" in data
    assert "refresh_token" in data


def test_password_login_wrong_password(client):
    r = client.post("/auth/login", json={"email": "admin@test.com", "password": "wrong"})
    assert r.status_code == 401


def test_password_login_wrong_email(client):
    r = client.post("/auth/login", json={"email": "nobody@test.com", "password": "secret"})
    assert r.status_code == 401


# --- Token validation (verify JWKS + token work together) ---


def test_issued_token_is_valid_jwt(client):
    r = client.post("/auth/login", json={"email": "admin@test.com", "password": "secret"})
    token = r.json()["access_token"]

    jwks = client.get("/auth/jwks").json()
    key = jwks["keys"][0]

    from jose import jwt

    claims = jwt.decode(token, key, algorithms=["RS256"], audience="test", issuer="http://test")
    assert claims["sub"] == "admin@test.com"
    assert claims["role"] == "admin"


def test_wallet_token_has_wallet_claims(client):
    r = client.post("/auth/challenge", json={"address": "0xclaims"})
    nonce = r.json()["challenge"]

    sk = Ed25519PrivateKey.generate()
    pk = sk.public_key()
    signature = sk.sign(nonce.encode("utf-8"))

    r = client.post(
        "/auth/wallet",
        json={
            "address": "0xclaims",
            "public_key": pk.public_bytes_raw().hex(),
            "signature": signature.hex(),
            "challenge": nonce,
            "algorithm": "Ed25519",
        },
    )
    token = r.json()["access_token"]

    jwks = client.get("/auth/jwks").json()
    key = jwks["keys"][0]

    from jose import jwt

    claims = jwt.decode(token, key, algorithms=["RS256"], audience="test", issuer="http://test")
    assert claims["sub"] == "0xclaims"
    assert claims["role"] == "wallet"
    assert claims["algorithm"] == "Ed25519"
    assert claims["wallet_address"] == "0xclaims"
