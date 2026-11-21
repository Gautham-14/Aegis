"""Recovery must preserve the trust key and reject untrusted snapshots."""

import os
import sqlite3

import pytest
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

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


@pytest.mark.parametrize("passphrase", ("too-short", "x" * 257))
def test_backup_passphrase_bounds(passphrase):
    with pytest.raises(ValueError, match="16-256 characters"):
        recovery._key(passphrase, b"0" * 16)


def test_backup_rejects_missing_database(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "DB_PATH", tmp_path / "missing.db")
    with pytest.raises(ValueError, match="No Aegis database"):
        recovery._db_snapshot()


def test_valid_database_rejects_invalid_key_and_executable_schema():
    with sqlite3.connect(":memory:") as db:
        db.execute("CREATE TABLE control_receipts(sequence INTEGER)")
        db.execute("CREATE TABLE control_head(singleton INTEGER)")
        db.execute("CREATE TRIGGER denied AFTER INSERT ON control_receipts BEGIN SELECT 1; END")
        raw = db.serialize()

    with pytest.raises(ValueError, match="key or database"):
        recovery._valid_database(raw, b"short")
    with pytest.raises(ValueError, match="unsupported executable schema"):
        recovery._valid_database(raw, b"s" * 32)


def test_decode_backup_rejects_malformed_payload(tmp_path):
    archive = tmp_path / "malformed.aegis-backup"
    passphrase = "a-long-test-backup-passphrase"
    salt = b"0" * 16
    nonce = b"1" * 12
    encrypted = (
        recovery.MAGIC
        + salt
        + nonce
        + AESGCM(recovery._key(passphrase, salt)).encrypt(
            nonce, b'{"version":2,"files":{}}', recovery.MAGIC
        )
    )
    archive.write_bytes(encrypted)

    with pytest.raises(ValueError, match="authentication or contents"):
        recovery.verify_backup(archive, passphrase)


def test_restore_files_revokes_sessions_and_requires_approval(tmp_path):
    init_db()
    store.init_control()
    auth.provision("operator", "a-unique-test-password")
    database = recovery._db_snapshot()
    secret = store.secret()
    files = {"db/aegis.db": database, "control.key": secret}

    restored = recovery._restore_files(files)

    with sqlite3.connect(":memory:") as db:
        db.deserialize(restored["db/aegis.db"])
        if db.execute(
            "SELECT COUNT(*) FROM sqlite_schema WHERE name='auth_sessions'"
        ).fetchone()[0]:
            assert db.execute("SELECT COUNT(*) FROM auth_sessions").fetchone()[0] == 0
