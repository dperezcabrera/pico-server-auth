import pytest

from pico_server_auth.config import ServerAuthSettings
from pico_server_auth.token_issuer import TokenIssuer


@pytest.fixture
def settings():
    return ServerAuthSettings(
        issuer="http://test",
        audience="test",
        challenge_ttl_seconds=30,
        auto_create_admin=True,
        admin_email="admin@test.com",
        admin_password="secret",
    )


@pytest.fixture
def issuer(settings):
    return TokenIssuer(settings)
