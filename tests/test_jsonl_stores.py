import json

import pico_server_auth.mint_audit_store as mint_audit_module
import pico_server_auth.revocation_store as revocation_module
from pico_server_auth._jsonl import append_jsonl, iter_jsonl
from pico_server_auth.config import ServerAuthSettings
from pico_server_auth.mint_audit_store import (
    DefaultMintAuditStore,
    InMemoryMintAuditStore,
    JsonFileMintAuditStore,
)
from pico_server_auth.revocation_store import (
    DefaultRevocationStore,
    InMemoryRevocationStore,
    JsonFileRevocationStore,
)

# --- _jsonl helpers ---


def test_iter_jsonl_missing_file_yields_nothing(tmp_path):
    assert list(iter_jsonl(tmp_path / "absent.jsonl", label="t")) == []


def test_iter_jsonl_skips_blank_and_malformed_lines(tmp_path, caplog):
    path = tmp_path / "log.jsonl"
    path.write_text('{"a": 1}\n\nnot json\n{"b": 2}\n', encoding="utf-8")
    with caplog.at_level("WARNING"):
        entries = list(iter_jsonl(path, label="mylabel"))
    assert entries == [{"a": 1}, {"b": 2}]
    assert "mylabel" in caplog.text
    assert ":3" in caplog.text


def test_iter_jsonl_unreadable_file_logs_and_stops(tmp_path, caplog):
    path = tmp_path / "dir-not-file"
    path.mkdir()
    with caplog.at_level("WARNING"):
        assert list(iter_jsonl(path, label="t")) == []
    assert "could not read" in caplog.text


def test_append_jsonl_creates_parents_and_appends(tmp_path):
    path = tmp_path / "sub" / "log.jsonl"
    append_jsonl(path, {"x": 1}, label="t")
    append_jsonl(path, {"x": 2}, label="t")
    lines = path.read_text(encoding="utf-8").splitlines()
    assert [json.loads(line) for line in lines] == [{"x": 1}, {"x": 2}]


def test_append_jsonl_write_failure_is_logged_not_raised(tmp_path, caplog):
    blocker = tmp_path / "file"
    blocker.write_text("", encoding="utf-8")
    with caplog.at_level("ERROR"):
        append_jsonl(blocker / "log.jsonl", {"x": 1}, label="t")
    assert "append" in caplog.text and "failed" in caplog.text


# --- InMemoryRevocationStore ---


def test_in_memory_revoke_is_idempotent():
    store = InMemoryRevocationStore()
    first = store.revoke("j1", reason="stolen", revoked_by="ops")
    again = store.revoke("j1", reason="other")
    assert again is first
    assert store.is_revoked("j1") is True
    assert store.is_revoked("j2") is False


def test_in_memory_list_all_newest_first():
    store = InMemoryRevocationStore()
    a = store.revoke("a")
    b = store.revoke("b")
    b["revoked_at"] = a["revoked_at"] + 1
    assert [e["jti"] for e in store.list_all()] == ["b", "a"]


# --- JsonFileRevocationStore ---


def test_json_file_revocation_persists_across_restart(tmp_path):
    path = tmp_path / "revoked.jsonl"
    store = JsonFileRevocationStore(path)
    store.revoke("j1", reason="stolen", revoked_by="ops")

    reloaded = JsonFileRevocationStore(path)
    assert reloaded.is_revoked("j1") is True
    entry = reloaded.list_all()[0]
    assert entry["reason"] == "stolen"
    assert entry["revoked_by"] == "ops"


def test_json_file_revoke_idempotent_does_not_grow_file(tmp_path):
    path = tmp_path / "revoked.jsonl"
    store = JsonFileRevocationStore(path)
    store.revoke("j1")
    store.revoke("j1")
    assert len(path.read_text(encoding="utf-8").splitlines()) == 1


def test_json_file_load_skips_entries_without_jti(tmp_path):
    path = tmp_path / "revoked.jsonl"
    path.write_text('{"revoked_at": 1}\n{"jti": "ok", "revoked_at": 2}\n', encoding="utf-8")
    store = JsonFileRevocationStore(path)
    assert [e["jti"] for e in store.list_all()] == ["ok"]


# --- DefaultRevocationStore ---


def test_default_revocation_no_path_uses_memory(tmp_path):
    store = DefaultRevocationStore(ServerAuthSettings())
    assert isinstance(store._impl, InMemoryRevocationStore)
    store.revoke("j1", reason="r", revoked_by="me")
    assert store.is_revoked("j1") is True
    assert store.list_all()[0]["jti"] == "j1"


def test_default_revocation_with_path_persists(tmp_path):
    settings = ServerAuthSettings(revocation_store_path=str(tmp_path / "rev.jsonl"))
    DefaultRevocationStore(settings).revoke("j1")
    assert DefaultRevocationStore(settings).is_revoked("j1") is True


def test_default_revocation_falls_back_to_memory_on_error(monkeypatch, caplog):
    def boom(path):
        raise OSError("disk on fire")

    monkeypatch.setattr(revocation_module, "JsonFileRevocationStore", boom)
    settings = ServerAuthSettings(revocation_store_path="/whatever")
    with caplog.at_level("WARNING"):
        store = DefaultRevocationStore(settings)
    assert isinstance(store._impl, InMemoryRevocationStore)
    assert "falling back to in-memory" in caplog.text


# --- InMemoryMintAuditStore ---


def test_in_memory_mint_audit_newest_first_and_limit():
    store = InMemoryMintAuditStore()
    for i in range(5):
        store.append({"jti": str(i)})
    assert [e["jti"] for e in store.list_recent(limit=2)] == ["4", "3"]


def test_in_memory_mint_audit_evicts_at_cap():
    store = InMemoryMintAuditStore(max_in_memory=2)
    for i in range(4):
        store.append({"jti": str(i)})
    assert [e["jti"] for e in store.list_recent()] == ["3", "2"]


# --- JsonFileMintAuditStore ---


def test_json_file_mint_audit_persists_across_restart(tmp_path):
    path = tmp_path / "mints.jsonl"
    store = JsonFileMintAuditStore(path)
    store.append({"jti": "a"})
    store.append({"jti": "b"})

    reloaded = JsonFileMintAuditStore(path)
    assert [e["jti"] for e in reloaded.list_recent()] == ["b", "a"]


def test_json_file_mint_audit_ram_cap_keeps_file_tail(tmp_path):
    path = tmp_path / "mints.jsonl"
    store = JsonFileMintAuditStore(path, max_in_memory=2)
    for i in range(4):
        store.append({"jti": str(i)})
    assert [e["jti"] for e in store.list_recent()] == ["3", "2"]
    assert len(path.read_text(encoding="utf-8").splitlines()) == 4


# --- DefaultMintAuditStore ---


def test_default_mint_audit_no_path_uses_memory():
    store = DefaultMintAuditStore(ServerAuthSettings())
    assert isinstance(store._impl, InMemoryMintAuditStore)
    store.append({"jti": "a"})
    assert store.list_recent()[0]["jti"] == "a"


def test_default_mint_audit_with_path_persists(tmp_path):
    settings = ServerAuthSettings(mint_audit_path=str(tmp_path / "mints.jsonl"))
    DefaultMintAuditStore(settings).append({"jti": "a"})
    assert DefaultMintAuditStore(settings).list_recent()[0]["jti"] == "a"


def test_default_mint_audit_falls_back_to_memory_on_error(monkeypatch, caplog):
    def boom(path, max_in_memory):
        raise OSError("disk on fire")

    monkeypatch.setattr(mint_audit_module, "JsonFileMintAuditStore", boom)
    settings = ServerAuthSettings(mint_audit_path="/whatever")
    with caplog.at_level("WARNING"):
        store = DefaultMintAuditStore(settings)
    assert isinstance(store._impl, InMemoryMintAuditStore)
    assert "falling back to in-memory" in caplog.text
