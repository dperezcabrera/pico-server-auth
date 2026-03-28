import time

import pytest

from pico_server_auth.challenge_store import InMemoryChallengeStore
from pico_server_auth.config import ServerAuthSettings


@pytest.fixture
def settings():
    return ServerAuthSettings(challenge_ttl_seconds=2)


@pytest.fixture
def store(settings):
    return InMemoryChallengeStore(settings)


def test_create_returns_nonce(store):
    nonce = store.create("0xabc")
    assert isinstance(nonce, str)
    assert len(nonce) == 64  # 32 bytes hex


def test_validate_succeeds(store):
    nonce = store.create("0xabc")
    assert store.validate("0xabc", nonce) is True


def test_validate_fails_wrong_nonce(store):
    store.create("0xabc")
    assert store.validate("0xabc", "wrong") is False


def test_validate_fails_wrong_address(store):
    nonce = store.create("0xabc")
    assert store.validate("0xdef", nonce) is False


def test_validate_consumes_nonce(store):
    nonce = store.create("0xabc")
    assert store.validate("0xabc", nonce) is True
    assert store.validate("0xabc", nonce) is False  # consumed


def test_validate_fails_after_ttl(store):
    nonce = store.create("0xabc")
    time.sleep(2.1)
    assert store.validate("0xabc", nonce) is False


def test_create_overwrites_previous(store):
    nonce1 = store.create("0xabc")
    nonce2 = store.create("0xabc")
    assert nonce1 != nonce2
    assert store.validate("0xabc", nonce1) is False
    assert store.validate("0xabc", nonce2) is True


def test_cleanup_removes_expired(store):
    store.create("0xabc")
    time.sleep(2.1)
    removed = store.cleanup()
    assert removed == 1
