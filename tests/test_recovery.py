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


def test_backup_rejects_invalid_key_database_and_missing_live_state():
    with pytest.raises(ValueError, match="16-256"):
        recovery._key("too-short", b"x" * 16)

    with pytest.raises(ValueError, match="No Aegis database"):
        recovery._db_snapshot()

    with pytest.raises(ValueError, match="invalid"):
        recovery._valid_database(b"not-a-database", b"short")

    init_db()
    store.init_control()
    control_key = config.DATA_DIR / "control.key"
    if control_key.exists():
        control_key.unlink()
    dpapi_key = config.DATA_DIR / "control.key.dpapi"
    if dpapi_key.exists():
        dpapi_key.unlink()
    with pytest.raises(ValueError, match="Live control key is missing"):
        recovery._payload()


def test_backup_rejects_oversized_managed_files_and_invalid_destinations(monkeypatch, tmp_path):
    init_db()
    store.init_control()
    managed = config.KNOWLEDGE_DIR / "large.txt"
    managed.write_text("synthetic fixture", encoding="utf-8")
    monkeypatch.setattr(recovery, "MAX_PLAINTEXT", 0)
    with pytest.raises(ValueError, match="Managed files exceed"):
        recovery._managed_files()

    monkeypatch.setattr(recovery, "MAX_PLAINTEXT", 128 * 1024 * 1024)
    with pytest.raises(ValueError, match="outside the live"):
        recovery.create_backup(tmp_path / "archive.aegis-backup", "a-long-test-backup-passphrase")
    with pytest.raises(ValueError, match="destination directory"):
        recovery.create_backup(
            tmp_path.parent / "missing-parent" / "archive.aegis-backup",
            "a-long-test-backup-passphrase",
        )


@pytest.mark.parametrize(
    ("contents", "match"),
    [
        (b"", "absent or exceeds"),
        (b"short", "truncated"),
    ],
)
def test_decode_backup_rejects_absent_and_truncated_archives(tmp_path, contents, match):
    archive = tmp_path / "archive.aegis-backup"
    if contents:
        archive.write_bytes(contents)
    with pytest.raises(ValueError, match=match):
        recovery._decode_backup(archive, "a-long-test-backup-passphrase")
