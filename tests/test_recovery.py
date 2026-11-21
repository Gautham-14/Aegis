"""Recovery must preserve the trust key and reject untrusted snapshots."""

import os
import sqlite3

import pytest

from aegis import config
from aegis.control import store
from aegis.security import auth, recovery
from aegis.storage.database import get_db_connection, init_db


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


def test_recovery_rejects_invalid_keys_database_and_destinations(tmp_path, monkeypatch):
    with pytest.raises(ValueError, match="16-256"):
        recovery._key("too-short", b"salt")
    with pytest.raises(ValueError, match="invalid"):
        recovery._valid_database(b"fixture", b"short")

    monkeypatch.setattr(config, "DB_PATH", tmp_path / "missing.db")
    monkeypatch.setattr(config, "DATA_DIR", tmp_path / "live")
    with pytest.raises(ValueError, match="No Aegis database"):
        recovery._db_snapshot()

    archive = config.DATA_DIR / "inside-data.aegis-backup"
    with pytest.raises(ValueError, match="outside"):
        recovery.create_backup(archive, "a-long-test-backup-passphrase")
    missing_parent = tmp_path / "missing-parent" / "archive.aegis-backup"
    with pytest.raises(ValueError, match="does not exist"):
        recovery.create_backup(missing_parent, "a-long-test-backup-passphrase")


def test_recovery_rejects_missing_broker_keyring_and_truncated_archives(tmp_path, monkeypatch):
    monkeypatch.setenv("AEGIS_KEY_BROKER_SOCKET", "/tmp/aegis-broker.sock")
    with pytest.raises(ValueError, match="separately backed-up"):
        recovery._payload()

    archive = tmp_path / "truncated.aegis-backup"
    archive.write_bytes(recovery.MAGIC)
    with pytest.raises(ValueError, match="truncated"):
        recovery.verify_backup(archive, "a-long-test-backup-passphrase")
