import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from jose import jwt
from pico_boot import init
from pico_ioc import DictSource, configuration

SECRET = "fleet-secret"


def _make_client(fleet_mint_secret: str) -> TestClient:
    config = configuration(
        DictSource(
            {
                "fastapi": {"title": "test", "version": "0.1.0"},
                "auth_client": {"enabled": False, "issuer": "http://test", "audience": "test"},
                "server_auth": {
                    "issuer": "http://test",
                    "audience": "test",
                    "fleet_mint_secret": fleet_mint_secret,
                    "fleet_session_ttl_seconds": 120,
                    "fleet_max_ttl_seconds": 3600,
                },
                "database": {"url": "sqlite+aiosqlite:///test_auth.db", "echo": False},
                "celery": {"broker_url": "memory://", "backend_url": "cache+memory://"},
            }
        )
    )
    container = init(modules=["pico_server_auth"], config=config)
    return TestClient(container.get(FastAPI))


@pytest.fixture(scope="module")
def client():
    return _make_client(SECRET)


def _mint(client, body, secret=SECRET):
    headers = {"X-Fleet-Secret": secret} if secret is not None else {}
    return client.post("/api/v1/auth/fleet/sessions", json=body, headers=headers)


def _decode(client, token):
    key = client.get("/api/v1/auth/jwks").json()["keys"][0]
    return jwt.decode(token, key, algorithms=["RS256"], audience="test", issuer="http://test")


def test_mint_session_returns_valid_token(client):
    r = _mint(client, {"session_id": "s1", "agent_id": "a1", "scope": "read"})
    assert r.status_code == 200
    data = r.json()
    claims = _decode(client, data["session_token"])
    assert claims["sub"] == "s1"
    assert claims["session_id"] == "s1"
    assert claims["agent_id"] == "a1"
    assert claims["role"] == "agent"
    assert claims["scope"] == "read"
    assert claims["exp"] == data["exp"]
    assert claims["exp"] - claims["iat"] == 120


def test_mint_session_role_override_and_no_scope(client):
    r = _mint(client, {"session_id": "s2", "agent_id": "a2", "role": "worker"})
    claims = _decode(client, r.json()["session_token"])
    assert claims["role"] == "worker"
    assert "scope" not in claims


def test_mint_session_ttl_clamped_to_minimum(client):
    r = _mint(client, {"session_id": "s3", "agent_id": "a3", "ttl": 5})
    claims = _decode(client, r.json()["session_token"])
    assert claims["exp"] - claims["iat"] == 60


def test_mint_session_ttl_clamped_to_ceiling(client):
    r = _mint(client, {"session_id": "s4", "agent_id": "a4", "ttl": 999_999})
    claims = _decode(client, r.json()["session_token"])
    assert claims["exp"] - claims["iat"] == 3600


def test_mint_session_wrong_secret(client):
    assert _mint(client, {"session_id": "s", "agent_id": "a"}, secret="wrong").status_code == 401


def test_mint_session_missing_secret_header(client):
    assert _mint(client, {"session_id": "s", "agent_id": "a"}, secret=None).status_code == 401


def test_mint_session_requires_ids(client):
    assert _mint(client, {"session_id": "", "agent_id": "a"}).status_code == 400
    assert _mint(client, {"session_id": "s", "agent_id": ""}).status_code == 400


def test_endpoint_disabled_without_configured_secret():
    client = _make_client("")
    assert _mint(client, {"session_id": "s", "agent_id": "a"}).status_code == 404
    # auto_create_admin defaults to False here -> password login is off too
    r = client.post("/api/v1/auth/login", json={"email": "a@b.c", "password": "x"})
    assert r.status_code == 403
