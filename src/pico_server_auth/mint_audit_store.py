"""Audit log of token mints.

Backs the operator's "live tokens" view. Each long-lived mint
appends a row here; the SPA's panel does ``mints − revocations``
to show what's currently valid + a Revoke button per row.

Mirror of ``revocation_store.py``: same Protocol + InMemory +
JsonFile + Default factory pattern. Two implementations ship —
in-memory for dev (lossy on restart) and JSONL for production
(persists across restarts when ``mint_audit_path`` is set).

Why not piggyback on the revocation store: revocations are a
slowly-growing set of operator decisions; mints are a chatty
audit log that may rotate / compact independently. Different
size envelopes, different retention policies.
"""

from __future__ import annotations

import logging
import os
import threading
from collections import deque
from pathlib import Path
from typing import Deque, Protocol

from pico_ioc import component

from pico_server_auth._jsonl import append_jsonl, iter_jsonl
from pico_server_auth.config import ServerAuthSettings

log = logging.getLogger(__name__)


class MintAuditStore(Protocol):
    """Persistence for the mint audit log.

    Replace with a Redis/SQL implementation by registering a
    custom ``@component`` that satisfies this Protocol.
    """

    def append(self, entry: dict) -> dict: ...

    def list_recent(self, limit: int = 200) -> list[dict]: ...


class InMemoryMintAuditStore:
    """Process-local audit log. Lost on restart — fine for dev,
    NOT for any deployment where the operator wants a stable
    "live tokens" view across pico-server-auth bounces.

    Bounded by ``max_in_memory``. When the cap is reached the
    oldest entry is dropped on each new append (deque semantics).
    """

    def __init__(self, max_in_memory: int = 5000):
        self._entries: Deque[dict] = deque(maxlen=max_in_memory)

    def append(self, entry: dict) -> dict:
        self._entries.append(entry)
        return entry

    def list_recent(self, limit: int = 200) -> list[dict]:
        # Newest first — operator usually wants the latest mints.
        return list(reversed(list(self._entries)[-limit:]))


class JsonFileMintAuditStore:
    """JSON-Lines append + reload. Same trade-offs as
    ``JsonFileRevocationStore``: single-process safe, monotonic
    file growth, atomic-ish on Linux via flush+fsync.

    Unlike the revocation store this one CAN grow unbounded if
    deployment-wide retention isn't applied externally — log
    rotation (logrotate, systemd) is the recommended hygiene.
    The ``mint_audit_min_ttl_seconds`` setting on the issuer
    pre-filters the high-volume ephemeral mints (60s
    agent_tokens) so the file stays manageable in practice.
    """

    def __init__(
        self,
        path: str | os.PathLike,
        max_in_memory: int = 5000,
    ):
        # ``~`` expansion only — the path is operator-config and is a
        # deliberate trust boundary (no sandboxing of where operators may
        # persist the audit log).
        self._path = Path(path).expanduser()
        # Deque so old entries auto-evict at the cap. The disk
        # file is the long-term audit; this is just the working
        # set served to the SPA.
        self._entries: Deque[dict] = deque(maxlen=max_in_memory)
        self._lock = threading.Lock()
        self._load()

    def _load(self) -> None:
        existed = self._path.exists()
        # Append to the deque; entries past the maxlen are dropped,
        # leaving only the tail of the file in RAM. For files much
        # bigger than maxlen this still scans the whole file once at
        # boot — a future optimisation could use a reverse-tail reader.
        for entry in iter_jsonl(self._path, label="mint audit"):
            self._entries.append(entry)
        if existed:
            log.info(
                "mint audit loaded %d entries from %s (cap %d)",
                len(self._entries),
                self._path,
                self._entries.maxlen or 0,
            )

    def append(self, entry: dict) -> dict:
        with self._lock:
            self._entries.append(entry)
            append_jsonl(self._path, entry, label="mint audit")
        return entry

    def list_recent(self, limit: int = 200) -> list[dict]:
        return list(reversed(list(self._entries)[-limit:]))


@component(on_missing_selector=MintAuditStore)
class DefaultMintAuditStore:
    """Switch between in-memory and JSONL based on settings.
    Same fallback pattern as DefaultRevocationStore."""

    def __init__(self, settings: ServerAuthSettings):
        path = settings.mint_audit_path
        cap = max(1, int(settings.mint_audit_max_in_memory))
        impl: object
        if path:
            try:
                impl = JsonFileMintAuditStore(path, max_in_memory=cap)
                log.info(
                    "MintAuditStore: persistent at %s (cap %d)",
                    path,
                    cap,
                )
            except Exception as exc:  # noqa: BLE001
                log.warning(
                    "MintAuditStore: failed to open %s, falling back to in-memory (mints LOST on restart): %s",
                    path,
                    exc,
                )
                impl = InMemoryMintAuditStore(max_in_memory=cap)
        else:
            impl = InMemoryMintAuditStore(max_in_memory=cap)
        self._impl = impl

    def append(self, entry: dict) -> dict:
        return self._impl.append(entry)  # type: ignore[attr-defined]

    def list_recent(self, limit: int = 200) -> list[dict]:
        return self._impl.list_recent(limit)  # type: ignore[attr-defined]
