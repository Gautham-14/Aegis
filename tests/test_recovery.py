"""Recovery must preserve the trust key and reject untrusted snapshots."""

import os
import sqlite3

import pytest

from aegis import config
from aegis.control import store
from aegis.security import auth, recovery
from aegis.storage.database import get_db_connection, init_db


def test_recovery_validation_rejects_invalid_inputs(tmp_path, monkeypatch):
    with pytest.raises(ValueError, match="16-256"):
        recovery._key("too-short", b"x" * 16)

    with pytest.raises(ValueError, match="No Aegis database"):
        recovery._db_snapshot()

    with pytest.raises(ValueError, match="invalid"):
        recovery._valid_database(b"not-a-database", b"short")

    monkeypatch.setenv("AEGIS_KEY_BROKER_SOCKET", "/tmp/aegis-broker.sock")
    monkeypatch.delenv("AEGIS_RECOVERY_KEYRING", raising=False)
    with pytest.raises(ValueError, match="separately backed-up broker keyring"):
        recovery._payload()

    with pytest.raises(ValueError, match="absent or exceeds"):
        recovery._decode_backup(tmp_path / "missing.aegis-backup", "a-long-test-backup-passphrase")

    truncated = tmp_path / "truncated.aegis-backup"
    truncated.write_bytes(recovery.MAGIC)
    with pytest.raises(ValueError, match="truncated"):
        recovery.verify_backup(truncated, "a-long-test-backup-passphrase")


def test_recovery_create_backup_rejects_unsafe_destinations(tmp_path):
    init_db()
    store.init_control()

    with pytest.raises(ValueError, match="outside the live"):
        recovery.create_backup(
            config.DATA_DIR / "backup.aegis", "a-long-test-backup-passphrase"
        )

    missing_parent = tmp_path.parent / f"{tmp_path.name}-missing" / "backup.aegis"
    with pytest.raises(ValueError, match="does not exist"):
        recovery.create_backup(missing_parent, "a-long-test-backup-passphrase")


def test_recovery_payload_rejects_missing_key_and_oversized_state(tmp_path, monkeypatch):
    init_db()
    with pytest.raises(ValueError, match="Live control key is missing"):
        recovery._payload()

    store.init_control()
    (config.DATA_DIR / "control.key").write_bytes(b"\0" * 32)
    monkeypatch.setattr(recovery, "_db_snapshot", lambda: b"database")
    monkeypatch.setattr(recovery, "_valid_database", lambda *args, **kwargs: None)
    monkeypatch.setattr(recovery, "_managed_files", lambda: {"knowledge/x": {"data": "x", "sha256": "x"}})
    monkeypatch.setattr(recovery, "MAX_PLAINTEXT", 1)
    with pytest.raises(ValueError, match="Operational state exceeds"):
        recovery._payload()


def test_encrypted_backup_restores_database_key_and_managed_files(tmp_path):
    init_db()
    store.init_control()
    auth.provision("operator", "a-unique-test-password")
    (config.KNOWLEDGE_DIR / "example.txt").write_text("approved local document", encoding="utf-8")
    original_key = store.secret()
    archive = tmp_path.parent / f"{tmp_path.name}.aegis-backup"
    made = recovery.create_backup(archive, "a-long-test-backup-passphrase")
    assert made["bytes"] == archive.stat().st_size
    assert b"approved local document" not in archive.read_bytes()
    assert original_key not in archive.read_bytes()
    assert recovery.verify_backup(archive, "a-long-test-backup-passphrase")["valid"]
    target = tmp_path.parent / f"{tmp_path.name}-restored"
    restored = recovery.restore_backup(archive, target, "a-long-test-backup-passphrase")
    assert restored["files"] == 3
    if os.name == "nt":
        from aegis.security.dpapi import unprotect

        assert not (target / "control.key").exists()
        assert unprotect((target / "control.key.dpapi").read_bytes()) == original_key
    else:
        assert (target / "control.key").read_bytes() == original_key
    assert (target / "knowledge" / "example.txt").read_text(
        encoding="utf-8"
    ) == "approved local document"
    with sqlite3.connect(target / "db" / "aegis.db") as db:
        assert db.execute("SELECT actor FROM auth_accounts").fetchone()[0] == "operator"
    with pytest.raises(ValueError, match="new directory"):
        recovery.restore_backup(archive, target, "a-long-test-backup-passphrase")
    drilled = recovery.drill_backup(
        archive, tmp_path.parent / f"{tmp_path.name}-drill", "a-long-test-backup-passphrase"
    )
    assert drilled["post_restore_verified"] and drilled["receipt_chain_verified"]


def test_backup_rejects_wrong_passphrase_tampering_and_bad_receipt(tmp_path):
    init_db()
    store.init_control()
    store.receipt("RECOVERY_TEST", "operator")
    archive = tmp_path.parent / f"{tmp_path.name}.aegis-backup"
    recovery.create_backup(archive, "a-long-test-backup-passphrase")
    with pytest.raises(ValueError, match="passphrase"):
        recovery.verify_backup(archive, "a-different-long-passphrase")
    raw = bytearray(archive.read_bytes())
    raw[-1] ^= 1
    archive.write_bytes(raw)
    with pytest.raises(ValueError, match="changed"):
        recovery.verify_backup(archive, "a-long-test-backup-passphrase")
    with get_db_connection() as db:
        db.execute("UPDATE control_head SET signature=?", ("0" * 64,))
    with pytest.raises(ValueError, match="receipt chain"):
        recovery.create_backup(
            tmp_path.parent / f"{tmp_path.name}-bad.aegis-backup", "a-long-test-backup-passphrase"
        )
