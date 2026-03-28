import pytest
from jose import jwt

from pico_server_auth.config import ServerAuthSettings
from pico_server_auth.token_issuer import TokenIssuer


@pytest.fixture
def settings():
    return ServerAuthSettings(
        issuer="http://test",
        audience="test-aud",
        access_token_expire_minutes=5,
        refresh_token_expire_days=1,
    )


@pytest.fixture
def issuer(settings):
    return TokenIssuer(settings)


def test_issue_access_token(issuer):
    token = issuer.issue_access_token("user@test.com", role="admin")
    assert isinstance(token, str)
    assert len(token) > 50


def test_access_token_claims(issuer, settings):
    token = issuer.issue_access_token("user@test.com", role="admin", extra_claims={"org": "pico"})
    jwks = issuer.jwks()
    key = jwks["keys"][0]

    claims = jwt.decode(
        token,
        key,
        algorithms=["RS256"],
        audience=settings.audience,
        issuer=settings.issuer,
    )
    assert claims["sub"] == "user@test.com"
    assert claims["role"] == "admin"
    assert claims["org"] == "pico"
    assert claims["iss"] == "http://test"
    assert claims["aud"] == "test-aud"
    assert "exp" in claims
    assert "iat" in claims


def test_issue_refresh_token(issuer):
    token = issuer.issue_refresh_token("user@test.com")
    assert isinstance(token, str)


def test_refresh_token_has_type_claim(issuer, settings):
    token = issuer.issue_refresh_token("user@test.com")
    jwks = issuer.jwks()
    key = jwks["keys"][0]

    claims = jwt.decode(token, key, algorithms=["RS256"], audience=settings.audience, issuer=settings.issuer)
    assert claims["type"] == "refresh"
    assert claims["sub"] == "user@test.com"


def test_jwks_format(issuer):
    jwks = issuer.jwks()
    assert "keys" in jwks
    assert len(jwks["keys"]) == 1
    key = jwks["keys"][0]
    assert key["kty"] == "RSA"
    assert key["alg"] == "RS256"
    assert key["use"] == "sig"
    assert "n" in key
    assert "e" in key
    assert "kid" in key


def test_jwks_is_stable(issuer):
    jwks1 = issuer.jwks()
    jwks2 = issuer.jwks()
    assert jwks1 == jwks2
