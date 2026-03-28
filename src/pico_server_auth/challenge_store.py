import secrets
import time
from typing import Protocol

from pico_ioc import component

from pico_server_auth.config import ServerAuthSettings


class ChallengeStore(Protocol):
    """Protocol for storing and validating auth challenges.

    Default implementation is in-memory with TTL expiry.
    Replace with a Redis or DB-backed implementation by registering
    your own @component that implements this protocol.
    """

    def create(self, address: str) -> str: ...

    def validate(self, address: str, nonce: str) -> bool: ...

    def cleanup(self) -> int: ...


@component(on_missing_selector=ChallengeStore)
class InMemoryChallengeStore:
    """In-memory challenge store with TTL-based expiry.

    Suitable for single-process deployments. For multi-instance setups,
    register a shared-storage implementation of ChallengeStore.
    """

    def __init__(self, settings: ServerAuthSettings):
        self._ttl = settings.challenge_ttl_seconds
        self._challenges: dict[str, tuple[str, float]] = {}

    def create(self, address: str) -> str:
        self.cleanup()
        nonce = secrets.token_hex(32)
        self._challenges[address] = (nonce, time.time())
        return nonce

    def validate(self, address: str, nonce: str) -> bool:
        entry = self._challenges.pop(address, None)
        if entry is None:
            return False
        stored_nonce, created_at = entry
        if time.time() - created_at > self._ttl:
            return False
        return secrets.compare_digest(stored_nonce, nonce)

    def cleanup(self) -> int:
        now = time.time()
        expired = [k for k, (_, t) in self._challenges.items() if now - t > self._ttl]
        for k in expired:
            del self._challenges[k]
        return len(expired)
