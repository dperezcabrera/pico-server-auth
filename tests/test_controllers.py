import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi import FastAPI
from fastapi.testclient import TestClient
from pico_boot import init
from pico_ioc import DictSource, configuration


@pytest.fixture(scope="module")
def container():
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
    return init(modules=["pico_server_auth"], config=config)


@pytest.fixture(scope="module")
def client(container):
    return TestClient(container.get(FastAPI))


# --- JWKS ---


def test_jwks_returns_keys(client):
    r = client.get("/api/v1/auth/jwks")
    assert r.status_code == 200
    data = r.json()
    assert "keys" in data
    assert len(data["keys"]) == 1
    key = data["keys"][0]
    assert key["kty"] == "RSA"
    assert key["alg"] == "RS256"


# --- Challenge ---


def test_challenge_returns_nonce(client):
    r = client.post("/api/v1/auth/challenge", json={"address": "0xabc"})
    assert r.status_code == 200
    data = r.json()
    assert "challenge" in data
    assert "ttl" in data
    assert len(data["challenge"]) == 64


def test_challenge_requires_address(client):
    r = client.post("/api/v1/auth/challenge", json={})
    assert r.status_code == 400


# --- Wallet login ---


def test_wallet_login_ed25519(client):
    # The canonical wallet id is the verified public key hex; address must equal it.
    sk = Ed25519PrivateKey.generate()
    pk = sk.public_key()
    addr = pk.public_bytes_raw().hex()

    # Get challenge (keyed by address == pubkey hex)
    r = client.post("/api/v1/auth/challenge", json={"address": addr})
    nonce = r.json()["challenge"]

    # Sign
    signature = sk.sign(nonce.encode("utf-8"))

    r = client.post(
        "/api/v1/auth/sign-in",
        json={
            "address": addr,
            "public_key": addr,
            "signature": signature.hex(),
            "challenge": nonce,
            "algorithm": "Ed25519",
        },
    )
    assert r.status_code == 200
    data = r.json()
    assert "access_token" in data
    assert "refresh_token" in data
    assert data["address"] == addr
    assert data["algorithm"] == "Ed25519"


def test_wallet_login_address_pubkey_mismatch_rejected(client):
    # Account-takeover regression: signing the nonce with the attacker's own
    # key while claiming a victim address must be rejected, not minted.
    victim = "00" * 32  # some address the attacker does not own
    r = client.post("/api/v1/auth/challenge", json={"address": victim})
    nonce = r.json()["challenge"]

    attacker = Ed25519PrivateKey.generate()
    signature = attacker.sign(nonce.encode("utf-8"))

    r = client.post(
        "/api/v1/auth/sign-in",
        json={
            "address": victim,
            "public_key": attacker.public_key().public_bytes_raw().hex(),
            "signature": signature.hex(),
            "challenge": nonce,
            "algorithm": "Ed25519",
        },
    )
    assert r.status_code == 400


def test_wallet_login_invalid_challenge(client):
    sk = Ed25519PrivateKey.generate()
    pk = sk.public_key()
    signature = sk.sign(b"wrong")

    r = client.post(
        "/api/v1/auth/sign-in",
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
    r = client.post("/api/v1/auth/challenge", json={"address": "0xbadsig"})
    nonce = r.json()["challenge"]

    sk = Ed25519PrivateKey.generate()
    pk = sk.public_key()
    # Sign wrong message
    signature = sk.sign(b"wrong message")

    r = client.post(
        "/api/v1/auth/sign-in",
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
    r = client.post("/api/v1/auth/sign-in", json={"address": "0x"})
    assert r.status_code == 400


# --- Password login ---


def test_password_login_success(client):
    r = client.post("/api/v1/auth/login", json={"email": "admin@test.com", "password": "secret"})
    assert r.status_code == 200
    data = r.json()
    assert "access_token" in data
    assert "refresh_token" in data


def test_password_login_wrong_password(client):
    r = client.post("/api/v1/auth/login", json={"email": "admin@test.com", "password": "wrong"})
    assert r.status_code == 401


def test_password_login_wrong_email(client):
    r = client.post("/api/v1/auth/login", json={"email": "nobody@test.com", "password": "secret"})
    assert r.status_code == 401


# --- Token validation (verify JWKS + token work together) ---


def test_issued_token_is_valid_jwt(client):
    r = client.post("/api/v1/auth/login", json={"email": "admin@test.com", "password": "secret"})
    token = r.json()["access_token"]

    jwks = client.get("/api/v1/auth/jwks").json()
    key = jwks["keys"][0]

    from jose import jwt

    claims = jwt.decode(token, key, algorithms=["RS256"], audience="test", issuer="http://test")
    assert claims["sub"] == "admin@test.com"
    # admin_role defaults to "operator" (configurable via server_auth.admin_role)
    assert claims["role"] == "operator"


def test_wallet_token_has_wallet_claims(client):
    sk = Ed25519PrivateKey.generate()
    pk = sk.public_key()
    addr = pk.public_bytes_raw().hex()

    r = client.post("/api/v1/auth/challenge", json={"address": addr})
    nonce = r.json()["challenge"]

    signature = sk.sign(nonce.encode("utf-8"))

    r = client.post(
        "/api/v1/auth/sign-in",
        json={
            "address": addr,
            "public_key": addr,
            "signature": signature.hex(),
            "challenge": nonce,
            "algorithm": "Ed25519",
        },
    )
    token = r.json()["access_token"]

    jwks = client.get("/api/v1/auth/jwks").json()
    key = jwks["keys"][0]

    from jose import jwt

    claims = jwt.decode(token, key, algorithms=["RS256"], audience="test", issuer="http://test")
    assert claims["sub"] == addr
    assert claims["role"] == "wallet"
    assert claims["algorithm"] == "Ed25519"
    assert claims["wallet_address"] == addr


def test_wallet_login_invalid_hex(client):
    r = client.post("/api/v1/auth/challenge", json={"address": "0xhex"})
    nonce = r.json()["challenge"]
    r = client.post(
        "/api/v1/auth/sign-in",
        json={
            "address": "0xhex",
            "public_key": "not-hex",
            "signature": "zz",
            "challenge": nonce,
            "algorithm": "Ed25519",
        },
    )
    assert r.status_code == 400
    assert "hex" in r.json()["detail"]


# --- Refresh ---


def _login(client):
    r = client.post("/api/v1/auth/login", json={"email": "admin@test.com", "password": "secret"})
    assert r.status_code == 200
    return r.json()


def _decode(client, token):
    from jose import jwt

    key = client.get("/api/v1/auth/jwks").json()["keys"][0]
    return jwt.decode(token, key, algorithms=["RS256"], audience="test", issuer="http://test")


def test_refresh_rotates_tokens_and_preserves_role(client):
    tokens = _login(client)

    r = client.post("/api/v1/auth/refresh", json={"refresh_token": tokens["refresh_token"]})
    assert r.status_code == 200
    data = r.json()
    assert data["refresh_token"] != tokens["refresh_token"]

    access_claims = _decode(client, data["access_token"])
    assert access_claims["sub"] == "admin@test.com"
    assert access_claims["role"] == "operator"
    refresh_claims = _decode(client, data["refresh_token"])
    assert refresh_claims["type"] == "refresh"
    assert refresh_claims["role"] == "operator"


def test_refresh_requires_token(client):
    assert client.post("/api/v1/auth/refresh", json={}).status_code == 400


def test_refresh_rejects_garbage_token(client):
    r = client.post("/api/v1/auth/refresh", json={"refresh_token": "not.a.jwt"})
    assert r.status_code == 401


def test_refresh_rejects_access_token(client):
    tokens = _login(client)
    r = client.post("/api/v1/auth/refresh", json={"refresh_token": tokens["access_token"]})
    assert r.status_code == 401
    assert "not a refresh token" in r.json()["detail"]


def test_refresh_rejects_expired_token(client, container):
    import time

    from pico_server_auth.token_issuer import TokenIssuer

    issuer = container.get(TokenIssuer)
    now = int(time.time())
    expired = issuer.sign(
        {"sub": "s1", "iss": "http://test", "aud": "test", "iat": now - 120, "exp": now - 60, "type": "refresh"}
    )
    r = client.post("/api/v1/auth/refresh", json={"refresh_token": expired})
    assert r.status_code == 401
    assert r.json()["detail"] == "refresh expired"


def test_refresh_rejects_token_without_sub(client, container):
    import time

    from pico_server_auth.token_issuer import TokenIssuer

    issuer = container.get(TokenIssuer)
    now = int(time.time())
    token = issuer.sign({"iss": "http://test", "aud": "test", "iat": now, "exp": now + 60, "type": "refresh"})
    r = client.post("/api/v1/auth/refresh", json={"refresh_token": token})
    assert r.status_code == 401
    assert r.json()["detail"] == "missing sub"


# --- Revocation + mint audit ---


def test_revoke_and_list(client):
    r = client.post("/api/v1/auth/revoke", json={"jti": "jti-1", "reason": "stolen"})
    assert r.status_code == 200
    entry = r.json()["revoked"]
    assert entry["jti"] == "jti-1"
    assert entry["reason"] == "stolen"
    # auth middleware disabled in tests -> actor falls back to "unknown"
    assert entry["revoked_by"] == "unknown"

    again = client.post("/api/v1/auth/revoke", json={"jti": "jti-1", "reason": "other"}).json()["revoked"]
    assert again["reason"] == "stolen"

    items = client.get("/api/v1/auth/revoked-jtis").json()["items"]
    assert "jti-1" in [e["jti"] for e in items]


def test_revoke_requires_jti(client):
    assert client.post("/api/v1/auth/revoke", json={"jti": ""}).status_code == 400


def test_mints_reflect_revocation_status(client):
    tokens = _login(client)
    jti = _decode(client, tokens["access_token"])["jti"]

    items = client.get("/api/v1/auth/mints").json()["items"]
    mine = next(e for e in items if e["jti"] == jti)
    assert mine["revoked"] is False
    assert mine["sub"] == "admin@test.com"

    client.post("/api/v1/auth/revoke", json={"jti": jti})
    items = client.get("/api/v1/auth/mints").json()["items"]
    assert next(e for e in items if e["jti"] == jti)["revoked"] is True


def test_mints_respects_limit(client):
    _login(client)
    _login(client)
    assert len(client.get("/api/v1/auth/mints", params={"limit": 1}).json()["items"]) == 1
