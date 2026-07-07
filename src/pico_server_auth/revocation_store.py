"""Per-token revocation store.

Implements the ``jti`` denylist that backs the no-time-expiry
policy (memory: feedback_no_time_expiry.md). Tokens are valid
indefinitely until explicitly revoked here; validators consult
this store before accepting a JWT.

Two implementations ship:

  * ``InMemoryRevocationStore`` — the simplest case. Lost on
    restart. Acceptable in dev / tests, NOT in production: a
    revoked-then-restarted token becomes valid again, defeating
    the entire purpose of the denylist.

  * ``JsonFileRevocationStore`` — JSON-Lines append + load on
    init. Atomic-ish (line-buffered append + flush). Preferred
    default in production; configure via
    ``revocation_store_path`` setting.

Multi-instance / HA deployments register their own
``@component`` (Redis, SQL, etc.) implementing the Protocol;
this module's auto-fallback plugs them in.
"""

from __future__ import annotations

import logging
import os
import threading
import time
from pathlib import Path
from typing import Protocol

from pico_ioc import component, configured

from pico_server_auth._jsonl import append_jsonl, iter_jsonl
from pico_server_auth.config import ServerAuthSettings

log = logging.getLogger(__name__)


class RevocationStore(Protocol):
    """Persistence for the jti denylist.

    Replace with a Redis/SQL implementation by registering a
    custom ``@component`` that satisfies this Protocol.
    """

    def revoke(
        self,
        jti: str,
        *,
        reason: str = "",
        revoked_by: str = "",
    ) -> dict: ...

    def is_revoked(self, jti: str) -> bool: ...

    def list_all(self) -> list[dict]: ...


class InMemoryRevocationStore:
    """Process-local denylist. The set grows as the operator
    revokes individual tokens; we never auto-prune because
    pruning would require knowing each token's max lifetime, and
    fleet policy says "no time expiry" — so prunable means
    "never forget".

    Realistic ceiling: even in a high-churn deployment, a few
    thousand revocations per year. Memory cost is trivial.

    **Lost on restart** — use ``JsonFileRevocationStore`` for
    production where a revoked token must STAY revoked across
    a process bounce.
    """

    def __init__(self):
        # ``jti -> {revoked_at, reason, revoked_by}``
        self._entries: dict[str, dict] = {}

    def revoke(
        self,
        jti: str,
        *,
        reason: str = "",
        revoked_by: str = "",
    ) -> dict:
        # Idempotent — re-revoking is a no-op (preserves the
        # original revoked_at so audits stay accurate).
        if jti in self._entries:
            return self._entries[jti]
        # Float timestamp so list_all ordering is stable even when
        # the operator hits Revoke twice in the same second.
        entry = {
            "jti": jti,
            "revoked_at": time.time(),
            "reason": reason,
            "revoked_by": revoked_by,
        }
        self._entries[jti] = entry
        return entry

    def is_revoked(self, jti: str) -> bool:
        return jti in self._entries

    def list_all(self) -> list[dict]:
        # Newest first — operators care about recent revocations.
        return sorted(
            self._entries.values(),
            key=lambda e: e["revoked_at"],
            reverse=True,
        )


class JsonFileRevocationStore:
    """Append-only JSON-Lines persistence.

    On revoke: append one JSON object per line + flush. Idempotent
    deduplication via the in-memory mirror so re-revoking the
    same jti does NOT bloat the file.

    On startup: read the file once, replay into the in-memory
    mirror.

    Trade-offs:
      * Single-process safety only — multiple writers to the
        same file would interleave bytes. Run a single
        pico-server-auth replica or front this with a real DB
        impl in HA setups.
      * No compaction. The file grows monotonically. With idempotent
        revoke + dedupe, that growth is bounded by the number of
        unique jtis ever revoked, which is small in practice.
      * Lock is a ``threading.Lock`` (not asyncio) because the
        Protocol surface is sync — matches ``InMemoryRevocationStore``.
        Async writers are free to run this in a thread.
    """

    def __init__(self, path: str | os.PathLike):
        # ``~`` expansion only — the store path is operator-config and is
        # a deliberate trust boundary (no sandboxing of where operators
        # may persist their denylist).
        self._path = Path(path).expanduser()
        self._entries: dict[str, dict] = {}
        self._lock = threading.Lock()
        self._load()

    def _load(self) -> None:
        existed = self._path.exists()
        for entry in iter_jsonl(self._path, label="revocation log"):
            jti = str(entry.get("jti", ""))
            if not jti:
                continue
            # Last-write-wins on duplicate jtis (shouldn't happen with
            # idempotent revoke, but tolerate hand-edited files).
            self._entries[jti] = entry
        if existed:
            log.info(
                "revocation store loaded %d entries from %s",
                len(self._entries),
                self._path,
            )

    def revoke(
        self,
        jti: str,
        *,
        reason: str = "",
        revoked_by: str = "",
    ) -> dict:
        with self._lock:
            if jti in self._entries:
                return self._entries[jti]
            entry = {
                "jti": jti,
                "revoked_at": time.time(),
                "reason": reason,
                "revoked_by": revoked_by,
            }
            self._entries[jti] = entry
            self._append(entry)
            return entry

    def is_revoked(self, jti: str) -> bool:
        return jti in self._entries

    def list_all(self) -> list[dict]:
        return sorted(
            self._entries.values(),
            key=lambda e: e["revoked_at"],
            reverse=True,
        )

    def _append(self, entry: dict) -> None:
        # Loud but non-fatal on failure — the in-memory mirror still
        # rejects the revoked jti for the rest of this process's
        # lifetime, and the operator gets a log line so they know the
        # durability invariant is broken.
        append_jsonl(self._path, entry, label="revocation store")


@component(on_missing_selector=RevocationStore)
class DefaultRevocationStore:
    """Switch between in-memory and JSONL based on settings.

    No path → in-memory (lossy on restart, fine for dev).
    Path set + writable → JSONL persistence.
    Path set but unwritable → in-memory + loud warning so the
    operator notices the durability gap.
    """

    def __init__(self, settings: ServerAuthSettings):
        path = settings.revocation_store_path
        impl: object
        if path:
            try:
                impl = JsonFileRevocationStore(path)
                log.info(
                    "RevocationStore: persistent at %s",
                    path,
                )
            except Exception as exc:  # noqa: BLE001
                log.warning(
                    "RevocationStore: failed to open %s, falling back to in-memory (revocations LOST on restart): %s",
                    path,
                    exc,
                )
                impl = InMemoryRevocationStore()
        else:
            impl = InMemoryRevocationStore()
        self._impl = impl

    def revoke(
        self,
        jti: str,
        *,
        reason: str = "",
        revoked_by: str = "",
    ) -> dict:
        return self._impl.revoke(  # type: ignore[attr-defined]
            jti,
            reason=reason,
            revoked_by=revoked_by,
        )

    def is_revoked(self, jti: str) -> bool:
        return self._impl.is_revoked(jti)  # type: ignore[attr-defined]

    def list_all(self) -> list[dict]:
        return self._impl.list_all()  # type: ignore[attr-defined]
