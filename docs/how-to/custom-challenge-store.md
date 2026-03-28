# Custom Challenge Store

The default `InMemoryChallengeStore` stores challenges in a Python dict. For multi-instance deployments, replace it with a shared-storage implementation.

## The ChallengeStore Protocol

```python
from typing import Protocol

class ChallengeStore(Protocol):
    def create(self, address: str) -> str: ...
    def validate(self, address: str, nonce: str) -> bool: ...
    def cleanup(self) -> int: ...
```

| Method | Description |
|---|---|
| `create(address)` | Generate a random nonce, store it for the given address, return the nonce. |
| `validate(address, nonce)` | Check if the nonce matches, consume it (one-time use), return `True`/`False`. |
| `cleanup()` | Remove expired entries, return count of entries removed. |

## Redis Example

```python
import secrets
from pico_ioc import component
from pico_server_auth import ChallengeStore, ServerAuthSettings

@component(on_missing_selector=ChallengeStore)
class RedisChallengeStore:
    """Challenge store backed by Redis with automatic TTL expiry."""

    def __init__(self, settings: ServerAuthSettings):
        import redis
        self._redis = redis.Redis(host="localhost", port=6379, db=0)
        self._ttl = settings.challenge_ttl_seconds
        self._prefix = "pico:challenge:"

    def create(self, address: str) -> str:
        nonce = secrets.token_hex(32)
        key = f"{self._prefix}{address}"
        self._redis.setex(key, self._ttl, nonce)
        return nonce

    def validate(self, address: str, nonce: str) -> bool:
        key = f"{self._prefix}{address}"
        stored = self._redis.get(key)
        if stored is None:
            return False
        self._redis.delete(key)  # One-time use
        return secrets.compare_digest(stored.decode(), nonce)

    def cleanup(self) -> int:
        # Redis handles TTL expiry automatically
        return 0
```

## Database Example

```python
import secrets
import time
from pico_ioc import component
from pico_server_auth import ChallengeStore, ServerAuthSettings

@component(on_missing_selector=ChallengeStore)
class DatabaseChallengeStore:
    """Challenge store backed by a SQL database."""

    def __init__(self, settings: ServerAuthSettings, db_session):
        self._ttl = settings.challenge_ttl_seconds
        self._db = db_session

    def create(self, address: str) -> str:
        self.cleanup()
        nonce = secrets.token_hex(32)
        self._db.execute(
            "INSERT INTO challenges (address, nonce, created_at) "
            "VALUES (?, ?, ?) ON CONFLICT (address) DO UPDATE "
            "SET nonce = ?, created_at = ?",
            (address, nonce, time.time(), nonce, time.time()),
        )
        self._db.commit()
        return nonce

    def validate(self, address: str, nonce: str) -> bool:
        row = self._db.execute(
            "SELECT nonce, created_at FROM challenges WHERE address = ?",
            (address,),
        ).fetchone()
        if row is None:
            return False
        self._db.execute("DELETE FROM challenges WHERE address = ?", (address,))
        self._db.commit()
        stored_nonce, created_at = row
        if time.time() - created_at > self._ttl:
            return False
        return secrets.compare_digest(stored_nonce, nonce)

    def cleanup(self) -> int:
        cursor = self._db.execute(
            "DELETE FROM challenges WHERE created_at < ?",
            (time.time() - self._ttl,),
        )
        self._db.commit()
        return cursor.rowcount
```

## Registration

pico-ioc uses `on_missing_selector=ChallengeStore` to register the default `InMemoryChallengeStore` only when no other implementation exists. By decorating your class with `@component(on_missing_selector=ChallengeStore)`, your implementation takes priority.

!!! tip "Module discovery"
    Ensure your custom store's module is included in the pico-boot `module_names` list so pico-ioc discovers it.

## Key Requirements

- **Nonces must be single-use**: `validate()` must consume the nonce on first call.
- **Use `secrets.compare_digest`**: Prevents timing attacks on nonce comparison.
- **Respect TTL**: Expired nonces must be rejected even if they exist in storage.
- **Thread/async safety**: If your store is accessed concurrently, ensure operations are atomic.
