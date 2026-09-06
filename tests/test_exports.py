"""The public API is exactly what ``__all__`` declares (stability contract)."""

import pico_server_auth


def test_public_api_is_declared_and_importable():
    assert set(pico_server_auth.__all__) == {
        "ChallengeStore",
        "InMemoryChallengeStore",
        "ServerAuthSettings",
        "TokenIssuer",
        "WalletVerifier",
    }
    for name in pico_server_auth.__all__:
        assert getattr(pico_server_auth, name) is not None
