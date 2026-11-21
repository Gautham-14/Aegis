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


@pytest.mark.parametrize("passphrase", ["", "too-short", "x" * 257])
def test_backup_passphrase_bounds_are_rejected(passphrase):
    with pytest.raises(ValueError, match="16-256"):
        recovery._key(passphrase, b"\0" * 16)


def test_backup_rejects_missing_database_and_invalid_database_values(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "DB_PATH", tmp_path / "missing.db")
    with pytest.raises(ValueError, match="database exists|No Aegis database"):
        recovery._db_snapshot()
    with pytest.raises(ValueError, match="invalid"):
        recovery._valid_database(b"not-a-database", b"short")
    with pytest.raises(ValueError, match="invalid"):
        recovery._valid_database(b"x" * (recovery.MAX_PLAINTEXT + 1), b"x" * 32)
    init_db()
    store.init_control()
    with pytest.raises(ValueError, match="invalid"):
        recovery._valid_database(b"not-a-database", bytes(32))


def test_valid_database_rejects_executable_schema():
    with sqlite3.connect(":memory:") as db:
        db.execute("CREATE TABLE control_receipts(sequence INTEGER)")
        db.execute("CREATE TABLE control_head(singleton INTEGER)")
        db.execute("CREATE TRIGGER denied AFTER INSERT ON control_receipts BEGIN SELECT 1; END")
        raw = db.serialize()

    with pytest.raises(ValueError, match="unsupported executable schema"):
        recovery._valid_database(raw, b"s" * 32)


def test_backup_validates_destination_and_archive_format(tmp_path):
    init_db()
    store.init_control()
    inside = config.DATA_DIR / "archive.aegis-backup"
    with pytest.raises(ValueError, match="outside"):
        recovery.create_backup(inside, "a-long-test-backup-passphrase")
    missing_parent = tmp_path / "missing" / "archive.aegis-backup"
    with pytest.raises(ValueError, match="directory"):
        recovery.create_backup(missing_parent, "a-long-test-backup-passphrase")

    missing = tmp_path / "missing.aegis-backup"
    with pytest.raises(ValueError, match="absent|unsupported"):
        recovery.verify_backup(missing, "a-long-test-backup-passphrase")
    truncated = tmp_path / "truncated.aegis-backup"
    truncated.write_bytes(recovery.MAGIC)
    with pytest.raises(ValueError, match="truncated|unsupported"):
        recovery.verify_backup(truncated, "a-long-test-backup-passphrase")

    truncated_short = tmp_path / "short.aegis-backup"
    truncated_short.write_bytes(recovery.MAGIC + b"x")
    with pytest.raises(ValueError, match="unsupported|truncated"):
        recovery.verify_backup(truncated_short, "a-long-test-backup-passphrase")


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

    with pytest.raises(ValueError, match="authentication or contents|invalid"):
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
        cursor = db.execute("SELECT COUNT(*) FROM sqlite_schema WHERE name='auth_sessions'")
        if cursor.fetchone()[0]:
            assert db.execute("SELECT COUNT(*) FROM auth_sessions").fetchone()[0] == 0


def test_managed_file_inventory_rejects_oversized_and_changed_files(monkeypatch, tmp_path):
    knowledge = config.KNOWLEDGE_DIR
    large = knowledge / "large.bin"
    large.write_bytes(b"x")
    monkeypatch.setattr(recovery, "MAX_PLAINTEXT", 0)
    with pytest.raises(ValueError, match="Managed files"):
        recovery._managed_files()

    monkeypatch.setattr(recovery, "MAX_PLAINTEXT", 128 * 1024 * 1024)
    changed = knowledge / "changed.bin"
    changed.write_bytes(b"x")

    class ShortRead:
        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

        def read(self, size):
            return b""

    monkeypatch.setattr(type(changed), "open", lambda self, *args, **kwargs: ShortRead())
    with pytest.raises(ValueError, match="changed"):
        recovery._managed_files()
