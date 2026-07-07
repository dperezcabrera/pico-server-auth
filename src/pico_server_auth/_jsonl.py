"""Shared JSON-Lines I/O mechanics for the file-backed stores.

Internal helper (underscore-prefixed module — NOT public API). Both
``JsonFileRevocationStore`` and ``JsonFileMintAuditStore`` keep their own
container + dedup/eviction semantics; this module only owns the two pieces
that were byte-for-byte identical between them:

  * ``iter_jsonl`` — read + parse one JSON object per line, tolerating
    malformed lines (logged, skipped) and an unreadable file (logged).
  * ``append_jsonl`` — atomic-ish append: mkdir + open("a") + write line +
    ``flush()`` + ``os.fsync()``, with OSError logged loud-but-non-fatal.

Locking lives in the callers (each holds its own ``threading.Lock`` around
the append). These helpers do no locking and add no buffering, so the
flush+fsync durability and single-writer semantics are unchanged.
"""

from __future__ import annotations

import json
import logging
import os
from collections.abc import Iterator
from pathlib import Path

log = logging.getLogger(__name__)


def iter_jsonl(path: Path, *, label: str) -> Iterator[dict]:
    """Yield parsed JSON objects, one per non-empty line of ``path``.

    Missing file → yields nothing. Malformed line → warning (with
    ``label``, path, 1-based line number) and skip. Unreadable file →
    warning and stop. Mirrors the previous per-store ``_load`` loop
    exactly; the caller decides what to do with each yielded dict
    (dedup into a mapping, append to a bounded deque, etc.).
    """
    if not path.exists():
        return
    try:
        with path.open("r", encoding="utf-8") as f:
            for line_no, line in enumerate(f, 1):
                line = line.strip()
                if not line:
                    continue
                try:
                    yield json.loads(line)
                except json.JSONDecodeError as exc:
                    log.warning(
                        "%s %s:%d malformed: %s",
                        label,
                        path,
                        line_no,
                        exc,
                    )
                    continue
    except OSError as exc:
        log.warning(
            "%s could not read %s: %s",
            label,
            path,
            exc,
        )


def append_jsonl(path: Path, entry: dict, *, label: str) -> None:
    """Append ``entry`` as one JSON line to ``path`` and fsync.

    mkdir parents, open in append mode, write the line, ``flush()`` then
    ``os.fsync()`` the file, then best-effort ``os.fsync()`` the parent
    directory so a freshly-created file/entry survives a crash. OSError on
    the write path is logged at error level and
    swallowed (loud-but-non-fatal): the in-memory mirror stays correct
    for the rest of the process even if the durable write failed. The
    caller is expected to hold its own lock around this call.
    """
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("a", encoding="utf-8") as f:
            f.write(json.dumps(entry, ensure_ascii=False) + "\n")
            f.flush()
            os.fsync(f.fileno())
        # Crash-safety: fsync the parent directory too. fsync on the file
        # only durably persists its CONTENTS; the directory entry (a
        # freshly-created file, or its updated metadata) isn't guaranteed
        # to survive a crash until the directory itself is fsynced. Best
        # effort — some platforms can't open a dir for fsync; swallow.
        try:
            dir_fd = os.open(path.parent, os.O_RDONLY)
            try:
                os.fsync(dir_fd)
            finally:
                os.close(dir_fd)
        except OSError:
            pass
    except OSError as exc:
        log.error(
            "%s append to %s failed: %s",
            label,
            path,
            exc,
        )
