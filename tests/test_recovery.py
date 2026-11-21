"""Recovery must preserve the trust key and reject untrusted snapshots."""

import os
import sqlite3
from unittest.mock import patch

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


def test_backup_validation_rejects_invalid_inputs(tmp_path):
    with pytest.raises(ValueError, match="16-256"):
        recovery._key("short", b"0123456789abcdef")

    init_db()
    store.init_control()
    config.DB_PATH.unlink()
    with pytest.raises(ValueError, match="No Aegis database"):
        recovery._db_snapshot()

    with pytest.raises(ValueError, match="key or database"):
        recovery._valid_database(b"fixture", b"x")

    init_db()
    store.init_control()
    inside_live_data = config.DATA_DIR / "archive.aegis-backup"
    with pytest.raises(ValueError, match="outside"):
        recovery.create_backup(inside_live_data, "a-long-test-backup-passphrase")
    with pytest.raises(ValueError, match="directory does not exist"):
        recovery.create_backup(
            tmp_path.parent / "missing-recovery-parent" / "archive.aegis-backup",
            "a-long-test-backup-passphrase",
        )


def test_backup_write_cleanup_and_missing_live_key(tmp_path):
    init_db()
    store.init_control()
    destination = tmp_path.parent / f"{tmp_path.name}.aegis-backup"
    with (
        patch.object(recovery, "_payload", return_value=b"fixture"),
        patch.object(recovery, "restrict_permissions", side_effect=RuntimeError("write failed")),
    ):
        with pytest.raises(RuntimeError, match="write failed"):
            recovery.create_backup(destination, "a-long-test-backup-passphrase")
    assert not destination.exists()

    for name in ("control.key", "control.key.dpapi"):
        (config.DATA_DIR / name).unlink(missing_ok=True)
    with pytest.raises(ValueError, match="Live control key is missing"):
        recovery._payload()
