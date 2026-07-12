import jwt
import pytest

from pico_server_auth.config import ServerAuthSettings
from pico_server_auth.mint_audit_store import InMemoryMintAuditStore
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
    return TokenIssuer(settings, InMemoryMintAuditStore())


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
        jwt.PyJWK(key),
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

    claims = jwt.decode(token, jwt.PyJWK(key), algorithms=["RS256"], audience=settings.audience, issuer=settings.issuer)
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


def _decode(issuer, settings, token):
    return jwt.decode(
        token,
        jwt.PyJWK(issuer.jwks()["keys"][0]),
        algorithms=["RS256"],
        audience=settings.audience,
        issuer=settings.issuer,
    )


def test_sign_injects_jti(issuer, settings):
    import time

    now = int(time.time())
    payload = {"sub": "s1", "iss": settings.issuer, "aud": settings.audience, "iat": now, "exp": now + 60}
    claims = _decode(issuer, settings, issuer.sign(payload))
    assert claims["sub"] == "s1"
    assert claims["jti"]


def test_sign_preserves_caller_jti(issuer, settings):
    import time

    now = int(time.time())
    payload = {
        "sub": "s1",
        "iss": settings.issuer,
        "aud": settings.audience,
        "iat": now,
        "exp": now + 60,
        "jti": "fixed",
    }
    assert _decode(issuer, settings, issuer.sign(payload))["jti"] == "fixed"


def test_verify_refresh_roundtrip(issuer):
    token = issuer.issue_refresh_token("user@test.com", role="admin")
    claims = issuer.verify_refresh(token)
    assert claims["sub"] == "user@test.com"
    assert claims["role"] == "admin"
    assert claims["type"] == "refresh"


def test_verify_refresh_rejects_access_token(issuer):
    token = issuer.issue_access_token("user@test.com")
    with pytest.raises(ValueError, match="not a refresh token"):
        issuer.verify_refresh(token)


def test_verify_refresh_rejects_expired(issuer, settings):
    import time

    from jwt import ExpiredSignatureError

    now = int(time.time())
    token = issuer.sign(
        {
            "sub": "s1",
            "iss": settings.issuer,
            "aud": settings.audience,
            "iat": now - 120,
            "exp": now - 60,
            "type": "refresh",
        }
    )
    with pytest.raises(ExpiredSignatureError):
        issuer.verify_refresh(token)


def test_refresh_token_without_role_has_no_role_claim(issuer, settings):
    claims = _decode(issuer, settings, issuer.issue_refresh_token("user@test.com"))
    assert "role" not in claims


def test_ephemeral_mints_are_not_audited():
    settings = ServerAuthSettings(access_token_expire_minutes=1, mint_audit_min_ttl_seconds=300)
    audit = InMemoryMintAuditStore()
    TokenIssuer(settings, audit).issue_access_token("user@test.com")
    assert audit.list_recent() == []


def test_long_lived_mints_are_audited():
    settings = ServerAuthSettings(access_token_expire_minutes=60, mint_audit_min_ttl_seconds=300)
    audit = InMemoryMintAuditStore()
    TokenIssuer(settings, audit).issue_access_token("user@test.com", role="admin")
    entry = audit.list_recent()[0]
    assert entry["sub"] == "user@test.com"
    assert entry["role"] == "admin"
    assert entry["kind"] == "access"


def test_audit_failure_never_blocks_mint(settings, caplog):
    class BrokenAudit:
        def append(self, entry):
            raise OSError("disk on fire")

        def list_recent(self, limit=200):
            return []

    issuer = TokenIssuer(settings, BrokenAudit())
    with caplog.at_level("WARNING"):
        token = issuer.issue_access_token("user@test.com")
    assert isinstance(token, str)
    assert "mint audit append failed" in caplog.text


def test_mldsa_algorithm_fails_fast():
    # issuing with ML-DSA is unimplemented; an issuer without keys must not boot
    with pytest.raises(NotImplementedError, match="ML-DSA-65"):
        TokenIssuer(ServerAuthSettings(algorithm="ML-DSA-65"), InMemoryMintAuditStore())


def test_unsupported_algorithm_raises():
    with pytest.raises(ValueError, match="unsupported token algorithm"):
        TokenIssuer(ServerAuthSettings(algorithm="HS256"), InMemoryMintAuditStore())
