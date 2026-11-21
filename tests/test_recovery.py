"""Recovery must preserve the trust key and reject untrusted snapshots."""

import base64
import hashlib
import json
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


def test_recovery_defensive_bounds_and_missing_files(tmp_path, monkeypatch):
    with pytest.raises(ValueError, match="16-256"):
        recovery._key("too-short", b"x" * 16)
    with pytest.raises(ValueError, match="No Aegis database"):
        recovery._db_snapshot()
    with pytest.raises(ValueError, match="key or database"):
        recovery._valid_database(b"fixture", b"short")

    monkeypatch.setenv("AEGIS_KEY_BROKER_SOCKET", "/run/aegis-broker.sock")
    with pytest.raises(ValueError, match="separately backed-up broker keyring"):
        recovery._payload()
    monkeypatch.delenv("AEGIS_KEY_BROKER_SOCKET")

    init_db()
    store.init_control()
    for name in ("control.key", "control.key.dpapi"):
        (config.DATA_DIR / name).unlink(missing_ok=True)
    with pytest.raises(ValueError, match="Live control key is missing"):
        recovery._payload()

    assert recovery._managed_files() == {}
    with pytest.raises(ValueError, match="outside"):
        recovery.create_backup(config.DATA_DIR / "backup.aegis", "a-long-test-backup-passphrase")
    missing_parent = tmp_path.parent / "missing-recovery-parent" / "backup.aegis"
    with pytest.raises(ValueError, match="directory does not exist"):
        recovery.create_backup(missing_parent, "a-long-test-backup-passphrase")
    with pytest.raises(ValueError, match="absent"):
        recovery.verify_backup(tmp_path / "missing.aegis", "a-long-test-backup-passphrase")
    archive = tmp_path / "truncated.aegis"
    archive.write_bytes(recovery.MAGIC)
    with pytest.raises(ValueError, match="truncated"):
        recovery.verify_backup(archive, "a-long-test-backup-passphrase")


@pytest.mark.parametrize(
    "mutation",
    [
        "unsafe-path",
        "bad-version",
        "bad-database-hash",
        "duplicate-path",
        "bad-file-hash",
    ],
)
def test_authenticated_payload_rejects_tampered_contents(tmp_path, mutation):
    init_db()
    store.init_control()
    store.receipt("TAMPERED_RECOVERY_PAYLOAD")
    payload = json.loads(recovery._payload())
    data = b"synthetic recovery fixture"
    entry = {
        "data": base64.b64encode(data).decode(),
        "sha256": hashlib.sha256(data).hexdigest(),
    }

    if mutation == "unsafe-path":
        payload["files"] = {"db/aegis.db": entry}
    elif mutation == "bad-version":
        payload["version"] = 2
    elif mutation == "bad-database-hash":
        payload["database_sha256"] = "0" * 64
    elif mutation == "duplicate-path":
        payload["files"] = {
            "knowledge/Case.txt": entry,
            "knowledge/case.txt": entry,
        }
    else:
        payload["files"] = {"knowledge/example.txt": entry}
        payload["files"]["knowledge/example.txt"]["sha256"] = "0" * 64

    password = "a-long-test-backup-passphrase"
    salt, nonce = os.urandom(16), os.urandom(12)
    encrypted = (
        recovery.MAGIC
        + salt
        + nonce
        + AESGCM(recovery._key(password, salt)).encrypt(
            nonce, json.dumps(payload).encode(), recovery.MAGIC
        )
    )
    archive = tmp_path / f"{mutation}.aegis-backup"
    archive.write_bytes(encrypted)
    with pytest.raises(ValueError, match="invalid"):
        recovery.verify_backup(archive, password)
