"""TOTP secrets encrypted at rest (Phase 2.2, Task A).

Before this change users.mfa_secret held the base32 TOTP seed in plaintext, so
anyone with a copy of the database file could generate valid step-up codes for
every identity. Seeds are now stored as AES-256-GCM ciphertext bound to the
user id, the key lives outside the database, and existing plaintext seeds are
encrypted on start-up in one all-or-nothing, repeatable migration.
"""

from __future__ import annotations

import logging
import subprocess
import sys
import threading

import pytest

from app import config, database, keystore, mfa_crypto, risk, security, seed
from conftest import ADMIN, decrypted, login

FINANCE = ("finance@hybridcloud.io", "Finance#2026")
CONTEXT = {"geo": "Bengaluru, IN", "hour": 13, "requests_last_5m": 4, "failed_attempts_24h": 0,
           "bytes_out_mb": 15, "session_minutes": 25, "concurrent_sessions": 1,
           "new_device": False, "mfa_verified": False, "threat_intel": "clean"}


def _users() -> list[dict]:
    with database.get_db() as conn:
        return database.rows(conn, "SELECT * FROM users ORDER BY id")


def _finance() -> dict:
    return next(u for u in _users() if u["email"] == FINANCE[0])


# ---------------------------------------------------------------------------
# Primitive behaviour
# ---------------------------------------------------------------------------


def test_round_trip_uses_a_fresh_nonce_and_hides_the_plaintext():
    key = mfa_crypto.parse_key(mfa_crypto.generate_key(), source="test")
    secret = security.generate_totp_secret()
    first = mfa_crypto.encrypt_secret(secret, 7, key)
    second = mfa_crypto.encrypt_secret(secret, 7, key)
    assert first.startswith(f"enc:v1:{mfa_crypto.key_id(key)}:")
    assert first != second
    assert secret not in first
    assert mfa_crypto.decrypt_secret(first, 7, key) == secret
    assert mfa_crypto.decrypt_secret(second, 7, key) == secret


def test_wrong_key_is_rejected():
    key = mfa_crypto.parse_key(mfa_crypto.generate_key(), source="test")
    other = mfa_crypto.parse_key(mfa_crypto.generate_key(), source="test")
    stored = mfa_crypto.encrypt_secret("JBSWY3DPEHPK3PXP", 1, key)
    with pytest.raises(mfa_crypto.SecretDecryptionError):
        mfa_crypto.decrypt_secret(stored, 1, other)
    # Same key id but different key bytes (forged prefix): the GCM tag fails.
    forged = stored.replace(mfa_crypto.key_id(key), mfa_crypto.key_id(other), 1)
    with pytest.raises(mfa_crypto.SecretDecryptionError):
        mfa_crypto.decrypt_secret(forged, 1, other)


def test_tampered_or_moved_ciphertext_is_rejected():
    key = mfa_crypto.parse_key(mfa_crypto.generate_key(), source="test")
    stored = mfa_crypto.encrypt_secret("JBSWY3DPEHPK3PXP", 1, key)
    prefix, blob = stored.rsplit(":", 1)
    flipped = blob[:20] + ("A" if blob[20] != "A" else "B") + blob[21:]
    for bad in (f"{prefix}:{flipped}", f"{prefix}:{blob[:-4]}", f"{prefix}:", stored + "x"):
        with pytest.raises(mfa_crypto.SecretDecryptionError):
            mfa_crypto.decrypt_secret(bad, 1, key)
    # Bound to the user id: copying the ciphertext onto another account fails.
    with pytest.raises(mfa_crypto.SecretDecryptionError):
        mfa_crypto.decrypt_secret(stored, 2, key)
    # No silent plaintext fallback.
    with pytest.raises(mfa_crypto.SecretDecryptionError):
        mfa_crypto.decrypt_secret("JBSWY3DPEHPK3PXP", 1, key)


@pytest.mark.parametrize("value", ["not-base64!!", "c2hvcnQ", "A" * 80])
def test_invalid_key_values_are_rejected_without_echoing_them(monkeypatch, value):
    monkeypatch.setenv(config.MFA_KEY_ENV, value)
    with pytest.raises(mfa_crypto.MfaKeyError) as raised:
        mfa_crypto.load_key()
    assert value not in str(raised.value)
    assert config.MFA_KEY_ENV in str(raised.value)


def test_cli_generates_a_usable_key():
    completed = subprocess.run(
        [sys.executable, "-m", "app.mfa_crypto", "generate-key"],
        capture_output=True, text=True, check=True, cwd=config.BASE_DIR,
    )
    assert len(mfa_crypto.parse_key(completed.stdout, source="cli")) == 32


def test_key_file_is_created_once_under_concurrency(tmp_path):
    target = tmp_path / "k.key"
    results: list[bytes] = []
    barrier = threading.Barrier(8)

    def worker(index: int) -> None:
        barrier.wait()
        results.append(keystore.create_once(target, f"key-{index}".encode()))

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(8)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert len(set(results)) == 1 and results[0] == target.read_bytes()
    assert keystore.create_once(target, b"later") == results[0]
    assert sorted(p.name for p in tmp_path.iterdir()) == ["k.key"]


# ---------------------------------------------------------------------------
# The running application's database
# ---------------------------------------------------------------------------


def test_stored_secrets_are_encrypted_with_the_active_key():
    key = mfa_crypto.active_key()
    users = _users()
    assert len(users) == 6
    for user in users:
        assert mfa_crypto.is_encrypted(user["mfa_secret"]), user["email"]
        assert user["mfa_secret"].split(":")[2] == mfa_crypto.key_id(key)
        assert len(decrypted(user)["mfa_secret"]) == 32
    # Neither the key nor any plaintext seed is anywhere in the database files.
    raw = b"".join(p.read_bytes() for p in config.DB_PATH.parent.glob(config.DB_PATH.name + "*"))
    assert config.MFA_KEY_PATH.read_text().strip().encode() not in raw
    for user in users:
        assert decrypted(user)["mfa_secret"].encode() not in raw


def test_api_responses_never_contain_secrets_or_ciphertext(make_client):
    users = _users()
    plaintexts = [decrypted(u)["mfa_secret"] for u in users]
    ciphertexts = [u["mfa_secret"] for u in users]
    key_text = config.MFA_KEY_PATH.read_text().strip()
    admin = make_client()
    assert login(admin, *ADMIN).status_code == 200
    finance = _finance()
    with database.get_db() as conn:
        device = database.row(conn, "SELECT id FROM devices WHERE user_id = ?", (finance["id"],))
        resource = database.row(conn, "SELECT id FROM resources WHERE name = 'finance-db'")
    bodies = [
        admin.post("/api/access/evaluate", json={"user_id": finance["id"], "device_id": device["id"],
                                                 "resource_id": resource["id"], "context": CONTEXT}).text
    ]
    for path in ("/api/auth/me", "/api/context/inventory", "/api/admin/inventory", "/api/events?limit=500",
                 "/api/alerts?status=all", "/api/dashboard", "/api/topology", "/api/openapi.json"):
        response = admin.get(path)
        assert response.status_code == 200, path
        bodies.append(response.text)
    for body in bodies:
        assert "enc:v1:" not in body and key_text not in body
        assert all(p not in body for p in plaintexts)
        assert all(c not in body for c in ciphertexts)


def _challenge_for_finance(browser) -> str:
    finance = _finance()
    with database.get_db() as conn:
        device = database.row(conn, "SELECT id FROM devices WHERE user_id = ? AND name = 'PRIYA-LT-03'", (finance["id"],))
        resource = database.row(conn, "SELECT id FROM resources WHERE name = 'finance-db'")
    response = browser.post("/api/access/evaluate", json={"device_id": device["id"], "resource_id": resource["id"],
                                                          "context": CONTEXT})
    assert response.json()["decision"] == "CHALLENGE", response.text
    return response.json()["challenge"]["id"]


def test_undecryptable_secret_fails_closed_without_counting_an_attempt(make_client, caplog):
    finance = _finance()
    original = finance["mfa_secret"]
    plaintext = decrypted(finance)["mfa_secret"]
    prefix, blob = original.rsplit(":", 1)
    tampered = f"{prefix}:{blob[:10]}{'A' if blob[10] != 'A' else 'B'}{blob[11:]}"
    browser = make_client()
    assert login(browser, *FINANCE).status_code == 200
    token = _challenge_for_finance(browser)
    with database.get_db() as conn:
        conn.execute("UPDATE users SET mfa_secret = ? WHERE id = ?", (tampered, finance["id"]))
    try:
        with caplog.at_level(logging.DEBUG):
            response = browser.post("/api/access/challenge",
                                    json={"challenge_id": token, "code": security.totp_code(plaintext)})
        assert response.status_code == 503
        assert response.json() == {"detail": risk.UNAVAILABLE_MESSAGE}
        with database.get_db() as conn:
            attempts = conn.execute("SELECT COUNT(*) FROM mfa_attempts WHERE user_id = ?", (finance["id"],)).fetchone()[0]
        assert attempts == 0
        assert "Cannot decrypt the MFA secret" in caplog.text
        for leaked in (plaintext, original, tampered, config.MFA_KEY_PATH.read_text().strip()):
            assert leaked not in caplog.text
    finally:
        with database.get_db() as conn:
            conn.execute("UPDATE users SET mfa_secret = ? WHERE id = ?", (original, finance["id"]))
    # Once the secret is intact again the same challenge still works.
    response = browser.post("/api/access/challenge", json={"challenge_id": token, "code": security.totp_code(plaintext)})
    assert response.status_code == 200, response.text


# ---------------------------------------------------------------------------
# Migration of databases created before encryption (isolated copies)
# ---------------------------------------------------------------------------


@pytest.fixture
def legacy_db(tmp_path, monkeypatch):
    """A seeded database whose secrets are plaintext and which has no key,
    i.e. what a pre-Phase-2.2 installation looks like."""
    monkeypatch.setattr(config, "DATA_DIR", tmp_path)
    monkeypatch.setattr(config, "DB_PATH", tmp_path / "legacy.db")
    monkeypatch.setattr(config, "MFA_KEY_PATH", tmp_path / "mfa.key")
    monkeypatch.delenv(config.MFA_KEY_ENV, raising=False)
    seed.seed_identity()
    plaintext = {}
    with database.get_db() as conn:
        for user in database.rows(conn, "SELECT id, mfa_secret FROM users"):
            plaintext[user["id"]] = mfa_crypto.user_secret(user)
            conn.execute("UPDATE users SET mfa_secret = ? WHERE id = ?", (plaintext[user["id"]], user["id"]))
    config.MFA_KEY_PATH.unlink()
    return plaintext


def _snapshot() -> list[tuple]:
    with database.get_db() as conn:
        return [tuple(r) for r in conn.execute(
            "SELECT id, email, role, password_hash, mfa_enabled, status FROM users ORDER BY id")]


def test_migration_encrypts_every_plaintext_secret_once(legacy_db, caplog):
    before = _snapshot()
    with caplog.at_level(logging.DEBUG):
        with database.get_db() as conn:
            assert mfa_crypto.prepare(conn) == len(legacy_db)
        with database.get_db() as conn:
            assert mfa_crypto.prepare(conn) == 0  # idempotent
        seed.seed_identity()                     # a normal restart
    assert _snapshot() == before
    assert config.MFA_KEY_PATH.exists()
    stored = {u["id"]: u["mfa_secret"] for u in _users()}
    for user_id, plaintext in legacy_db.items():
        assert mfa_crypto.is_encrypted(stored[user_id])
        assert mfa_crypto.decrypt_secret(stored[user_id], user_id) == plaintext
    with database.get_db() as conn:
        assert conn.execute("PRAGMA integrity_check").fetchone()[0] == "ok"
    key_text = config.MFA_KEY_PATH.read_text().strip()
    for leaked in [key_text, *legacy_db.values(), *stored.values()]:
        assert leaked not in caplog.text
    assert f"Encrypted {len(legacy_db)} plaintext MFA secret(s)" in caplog.text


def test_interrupted_migration_leaves_the_database_unchanged(legacy_db, monkeypatch):
    real_encrypt = mfa_crypto.encrypt_secret
    calls = {"n": 0}

    def failing_encrypt(*args, **kwargs):
        calls["n"] += 1
        if calls["n"] == 3:
            raise OSError("simulated crash mid-migration")
        return real_encrypt(*args, **kwargs)

    monkeypatch.setattr(mfa_crypto, "encrypt_secret", failing_encrypt)
    with pytest.raises(OSError):
        with database.get_db() as conn:
            mfa_crypto.prepare(conn)
    assert {u["id"]: u["mfa_secret"] for u in _users()} == legacy_db  # rolled back, nothing half-done
    monkeypatch.setattr(mfa_crypto, "encrypt_secret", real_encrypt)
    with database.get_db() as conn:
        assert mfa_crypto.prepare(conn) == len(legacy_db)


def test_existing_users_complete_mfa_after_migration(legacy_db):
    with database.get_db() as conn:
        mfa_crypto.prepare(conn)
        finance = database.row(conn, "SELECT id FROM users WHERE email = ?", (FINANCE[0],))
        device = database.row(conn, "SELECT id FROM devices WHERE user_id = ? AND name = 'PRIYA-LT-03'", (finance["id"],))
        resource = database.row(conn, "SELECT id FROM resources WHERE name = 'finance-db'")
    result = risk.evaluate(finance["id"], device["id"], resource["id"], dict(CONTEXT), persist=True)
    assert result["decision"] == "CHALLENGE"
    # The user's authenticator still holds the original (pre-migration) seed.
    code = security.totp_code(legacy_db[finance["id"]])
    verified = risk.verify_challenge(result["challenge"]["id"], code)
    assert verified["step_up"] is True


def test_missing_or_wrong_key_stops_startup_instead_of_replacing_it(legacy_db, monkeypatch):
    with database.get_db() as conn:
        mfa_crypto.prepare(conn)
    original = config.MFA_KEY_PATH.read_bytes()
    stored = {u["id"]: u["mfa_secret"] for u in _users()}

    config.MFA_KEY_PATH.unlink()
    with pytest.raises(mfa_crypto.MfaKeyError, match="no encryption key"):
        seed.seed_identity()
    assert not config.MFA_KEY_PATH.exists()  # no replacement key was generated

    monkeypatch.setenv(config.MFA_KEY_ENV, mfa_crypto.generate_key())
    with pytest.raises(mfa_crypto.MfaKeyError, match="different key"):
        seed.seed_identity()
    assert {u["id"]: u["mfa_secret"] for u in _users()} == stored

    # Restoring the key from backup (file or env var) recovers everything.
    monkeypatch.setenv(config.MFA_KEY_ENV, original.decode().strip())
    seed.seed_identity()
    monkeypatch.delenv(config.MFA_KEY_ENV)
    config.MFA_KEY_PATH.write_bytes(original)
    seed.seed_identity()
    for user_id, plaintext in legacy_db.items():
        assert mfa_crypto.decrypt_secret(stored[user_id], user_id) == plaintext


def test_env_key_is_used_for_a_new_database(tmp_path, monkeypatch):
    key_text = mfa_crypto.generate_key()
    monkeypatch.setattr(config, "DATA_DIR", tmp_path)
    monkeypatch.setattr(config, "DB_PATH", tmp_path / "fresh.db")
    monkeypatch.setattr(config, "MFA_KEY_PATH", tmp_path / "mfa.key")
    monkeypatch.setenv(config.MFA_KEY_ENV, key_text)
    seed.seed_identity()
    assert not config.MFA_KEY_PATH.exists()  # the env key is used; no file is written
    kid = mfa_crypto.key_id(mfa_crypto.parse_key(key_text, source="test"))
    assert {u["mfa_secret"].split(":")[2] for u in _users()} == {kid}
