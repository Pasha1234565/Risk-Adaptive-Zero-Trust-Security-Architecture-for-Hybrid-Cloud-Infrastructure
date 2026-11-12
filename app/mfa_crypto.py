"""Encryption at rest for TOTP seeds (AES-256-GCM from ``cryptography``).

Stored format (users.mfa_secret)::

    enc:v1:<key id>:<base64url(nonce || ciphertext || tag)>

* AES-256-GCM with a random 96-bit nonce per encryption.
* The associated data binds the ciphertext to the user row
  (``zt-mfa-secret:v1:user:<id>``), so a ciphertext copied onto another
  account fails authentication instead of decrypting.
* The key id is the first 8 hex characters of SHA-256(key). It is not
  secret; it lets startup detect "wrong key" before any user is affected.

Key source, in order: the ``ZT_MFA_ENCRYPTION_KEY`` environment variable
(base64url-encoded 32 bytes), then the key file ``config.MFA_KEY_PATH``. A new
key file is generated only when the database holds no encrypted secrets yet;
otherwise a missing key stops start-up with an explanatory error, because a
new key could never decrypt the existing secrets.

This is local key storage for a prototype, not a key-management service: the
key file sits on the same host as the database, protected only by file
permissions. See docs/ARCHITECTURE.md for backup, recovery and limitations.

Command line::

    python -m app.mfa_crypto generate-key   # print a new key for ZT_MFA_ENCRYPTION_KEY
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import logging
import os
import sqlite3
import sys

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from . import config, keystore

logger = logging.getLogger(__name__)

PREFIX = "enc:v1:"
KEY_BYTES = 32
NONCE_BYTES = 12
TAG_BYTES = 16


class MfaKeyError(RuntimeError):
    """The encryption key is missing, malformed or does not match the data."""


class SecretDecryptionError(ValueError):
    """A stored secret could not be decrypted (wrong key, tampered, malformed)."""


# ---------------------------------------------------------------------------
# Keys
# ---------------------------------------------------------------------------


def _b64encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def _b64decode(text: str) -> bytes:
    text = text.strip()
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def generate_key() -> str:
    """A new random key in the text form used by the env var and key file."""
    return _b64encode(os.urandom(KEY_BYTES))


def parse_key(text: str, *, source: str) -> bytes:
    """Decode a base64url key; the error message never contains the value."""
    try:
        key = _b64decode(text)
    except (binascii.Error, ValueError):
        key = b""
    if len(key) != KEY_BYTES:
        raise MfaKeyError(f"{source} must contain a base64url-encoded {KEY_BYTES}-byte key.")
    return key


def key_id(key: bytes) -> str:
    return hashlib.sha256(key).hexdigest()[:8]


def load_key() -> bytes | None:
    """The configured key, or None when neither the env var nor the file exists."""
    value = os.environ.get(config.MFA_KEY_ENV)
    if value is not None and value.strip():
        return parse_key(value, source=config.MFA_KEY_ENV)
    path = config.MFA_KEY_PATH
    if path.exists():
        return parse_key(path.read_text(encoding="ascii", errors="replace"), source=f"MFA key file {path.name}")
    return None


def active_key() -> bytes:
    key = load_key()
    if key is None:
        raise MfaKeyError(
            f"No MFA encryption key: set {config.MFA_KEY_ENV} or restore the key file "
            f"{config.MFA_KEY_PATH.name}."
        )
    return key


# ---------------------------------------------------------------------------
# Encrypt / decrypt
# ---------------------------------------------------------------------------


def _aad(user_id: int) -> bytes:
    return f"zt-mfa-secret:v1:user:{int(user_id)}".encode("ascii")


def is_encrypted(value: str | None) -> bool:
    return isinstance(value, str) and value.startswith(PREFIX)


def encrypt_secret(plaintext: str, user_id: int, key: bytes | None = None) -> str:
    key = active_key() if key is None else key
    nonce = os.urandom(NONCE_BYTES)
    sealed = AESGCM(key).encrypt(nonce, plaintext.encode("utf-8"), _aad(user_id))
    return f"{PREFIX}{key_id(key)}:{_b64encode(nonce + sealed)}"


def decrypt_secret(stored: str, user_id: int, key: bytes | None = None) -> str:
    """Return the plaintext seed. Never falls back to treating input as plaintext."""
    if not is_encrypted(stored):
        raise SecretDecryptionError("MFA secret is not in the encrypted format")
    key = active_key() if key is None else key
    try:
        stored_kid, blob_text = stored[len(PREFIX):].split(":", 1)
        blob = _b64decode(blob_text)
    except (ValueError, binascii.Error) as exc:
        raise SecretDecryptionError("MFA secret is malformed") from exc
    if stored_kid != key_id(key):
        raise SecretDecryptionError("MFA secret was encrypted with a different key")
    if len(blob) < NONCE_BYTES + TAG_BYTES:
        raise SecretDecryptionError("MFA secret is malformed")
    try:
        plaintext = AESGCM(key).decrypt(blob[:NONCE_BYTES], blob[NONCE_BYTES:], _aad(user_id))
    except InvalidTag as exc:
        raise SecretDecryptionError("MFA secret failed authentication") from exc
    return plaintext.decode("utf-8")


def user_secret(user: dict) -> str:
    """Plaintext TOTP seed for a ``users`` row (must contain id and mfa_secret)."""
    return decrypt_secret(user["mfa_secret"], user["id"])


# ---------------------------------------------------------------------------
# Start-up: key provisioning, migration of plaintext rows, key check
# ---------------------------------------------------------------------------


def _stored_key_ids(conn: sqlite3.Connection) -> set[str]:
    found = conn.execute(
        "SELECT mfa_secret FROM users WHERE mfa_secret LIKE ?", (PREFIX + "%",)
    ).fetchall()
    return {row[0][len(PREFIX):].split(":", 1)[0] for row in found}


def ensure_key(conn: sqlite3.Connection) -> bytes:
    """Return the configured key, generating the key file only for a database
    that has no encrypted secrets (a fresh or not-yet-migrated database)."""
    key = load_key()
    if key is not None:
        return key
    if _stored_key_ids(conn):
        # A key file is always published before the first secret is encrypted
        # with it, so another worker that started at the same moment may have
        # created it after the check above: look once more before giving up.
        key = load_key()
        if key is not None:
            return key
        raise MfaKeyError(
            "The database contains encrypted MFA secrets but no encryption key is configured. "
            f"Restore the key file {config.MFA_KEY_PATH.name} or set {config.MFA_KEY_ENV}; "
            "a new key cannot decrypt the existing secrets."
        )
    written = keystore.create_once(config.MFA_KEY_PATH, (generate_key() + "\n").encode("ascii"))
    logger.warning(
        "Generated a new MFA encryption key file %s. Back it up separately from the "
        "database: without it, enrolled authenticators cannot be verified.",
        config.MFA_KEY_PATH,
    )
    return parse_key(written.decode("ascii", errors="replace"), source=f"MFA key file {config.MFA_KEY_PATH.name}")


def migrate_plaintext_secrets(conn: sqlite3.Connection, key: bytes) -> int:
    """Encrypt every non-empty plaintext secret; return the number converted.

    Runs inside the caller's transaction, so either all rows are converted or
    (on any error) none are. Already-encrypted rows are skipped, which makes
    repeated runs no-ops.
    """
    pending = conn.execute(
        "SELECT id, mfa_secret FROM users WHERE mfa_secret != '' AND mfa_secret NOT LIKE ?",
        (PREFIX + "%",),
    ).fetchall()
    for user_id, plaintext in pending:
        conn.execute(
            "UPDATE users SET mfa_secret = ? WHERE id = ? AND mfa_secret = ?",
            (encrypt_secret(plaintext, user_id, key), user_id, plaintext),
        )
    return len(pending)


def verify_key_matches(conn: sqlite3.Connection, key: bytes) -> None:
    foreign = _stored_key_ids(conn) - {key_id(key)}
    if foreign:
        raise MfaKeyError(
            "Stored MFA secrets were encrypted with a different key "
            f"(key id {', '.join(sorted(foreign))}; configured key id {key_id(key)}). "
            f"Restore the original key file or {config.MFA_KEY_ENV}."
        )


def prepare(conn: sqlite3.Connection) -> int:
    """Provision the key, encrypt plaintext secrets and check the key matches.

    Call with a connection that is not inside a transaction; the migration
    runs under ``BEGIN IMMEDIATE`` so concurrent workers serialise on it.
    Returns the number of secrets encrypted by this call.
    """
    key = ensure_key(conn)
    conn.execute("BEGIN IMMEDIATE")
    try:
        verify_key_matches(conn, key)
        migrated = migrate_plaintext_secrets(conn, key)
    except BaseException:
        conn.rollback()
        raise
    conn.commit()
    if migrated:
        logger.info("Encrypted %d plaintext MFA secret(s) at rest (key id %s).", migrated, key_id(key))
    return migrated


def main(argv: list[str]) -> int:
    if argv[1:] == ["generate-key"]:
        print(generate_key())
        return 0
    print("usage: python -m app.mfa_crypto generate-key", file=sys.stderr)
    return 2


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
