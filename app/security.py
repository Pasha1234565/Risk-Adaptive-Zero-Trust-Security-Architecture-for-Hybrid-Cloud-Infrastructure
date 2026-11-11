"""Identity primitives: password hashing, session tokens and TOTP step-up.

Implemented with the standard library (hashlib/hmac/base64) so the prototype
has no dependency on an external identity provider. The code paths mirror
production concerns (salted PBKDF2, signed expiring tokens, replay-resistant
TOTP windows) while remaining fully reproducible offline.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import secrets
import struct
import time
from datetime import datetime, timedelta, timezone

from . import config, database

# ---------------------------------------------------------------------------
# Password hashing
# ---------------------------------------------------------------------------


def hash_password(password: str, *, salt: bytes | None = None,
                  iterations: int | None = None) -> str:
    iterations = iterations or config.PBKDF2_ITERATIONS
    salt = salt or os.urandom(16)
    digest = hashlib.pbkdf2_hmac(
        config.PBKDF2_ALGORITHM, password.encode("utf-8"), salt, iterations
    )
    return "pbkdf2_sha256${}${}${}".format(
        iterations,
        base64.b64encode(salt).decode("ascii"),
        base64.b64encode(digest).decode("ascii"),
    )


def verify_password(password: str, encoded: str) -> bool:
    try:
        algorithm, iterations, salt_b64, digest_b64 = encoded.split("$", 3)
        if algorithm != "pbkdf2_sha256":
            return False
        salt = base64.b64decode(salt_b64)
        expected = base64.b64decode(digest_b64)
        actual = hashlib.pbkdf2_hmac(
            config.PBKDF2_ALGORITHM, password.encode("utf-8"), salt, int(iterations)
        )
    except (ValueError, TypeError):
        return False
    return hmac.compare_digest(actual, expected)


# ---------------------------------------------------------------------------
# Signed session tokens (compact JWT compatible HS256)
# ---------------------------------------------------------------------------


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def _b64url_decode(data: str) -> bytes:
    padding = "=" * (-len(data) % 4)
    return base64.urlsafe_b64decode(data + padding)


def _secret() -> bytes:
    if config.SESSION_SECRET:
        return config.SESSION_SECRET.encode("utf-8")
    key_file = config.SECRET_PATH
    if key_file.exists():
        return key_file.read_bytes()
    key_file.parent.mkdir(parents=True, exist_ok=True)
    key = secrets.token_bytes(48)
    key_file.write_bytes(key)
    try:
        key_file.chmod(0o600)
    except OSError:
        pass
    return key


def issue_token(user_id: int, *, ttl_seconds: int | None = None) -> str:
    now = int(time.time())
    payload = {
        "sub": str(user_id),
        "iat": now,
        "exp": now + int(ttl_seconds or config.SESSION_TTL_SECONDS),
        "jti": secrets.token_hex(8),
    }
    header = {"alg": "HS256", "typ": "JWT"}
    segments = [
        _b64url(json.dumps(header, separators=(",", ":")).encode()),
        _b64url(json.dumps(payload, separators=(",", ":")).encode()),
    ]
    signing_input = ".".join(segments).encode("ascii")
    signature = hmac.new(_secret(), signing_input, hashlib.sha256).digest()
    return ".".join(segments + [_b64url(signature)])


def decode_token(token: str) -> dict | None:
    """Verify signature and expiry; return the claims or None.

    This is a stateless check. Use :func:`verify_session_token` for requests so
    that revoked (logged-out) sessions are rejected as well.
    """
    try:
        header_b64, payload_b64, signature_b64 = token.split(".")
        signing_input = f"{header_b64}.{payload_b64}".encode("ascii")
        expected = hmac.new(_secret(), signing_input, hashlib.sha256).digest()
        if not hmac.compare_digest(expected, _b64url_decode(signature_b64)):
            return None
        payload = json.loads(_b64url_decode(payload_b64))
        if not isinstance(payload, dict):
            return None
        expires_at = int(payload.get("exp", 0))
    except (ValueError, json.JSONDecodeError, TypeError, AttributeError):
        return None
    if expires_at < int(time.time()):
        return None
    # The jti is the server-side session id used for revocation.
    if not isinstance(payload.get("jti"), str) or not payload["jti"]:
        return None
    return payload


def verify_session_token(token: str) -> dict | None:
    """Return the claims of a valid, unexpired and non-revoked session token."""
    payload = decode_token(token)
    if payload is None or database.is_session_revoked(payload["jti"]):
        return None
    return payload


def revoke_session_token(token: str) -> bool:
    """Revoke the session behind ``token`` until it would have expired.

    Returns False when the token is not a valid session token (nothing to
    revoke). Expired revocation rows are purged opportunistically.
    """
    payload = decode_token(token)
    if payload is None:
        return False
    try:
        user_id: int | None = int(payload.get("sub"))
    except (TypeError, ValueError):
        user_id = None
    database.revoke_session(payload["jti"], user_id, int(payload["exp"]))
    database.purge_expired_revocations()
    return True


# ---------------------------------------------------------------------------
# TOTP step-up authentication
# ---------------------------------------------------------------------------


def generate_totp_secret() -> str:
    return base64.b32encode(secrets.token_bytes(20)).decode("ascii").rstrip("=")


def _hotp(secret: str, counter: int) -> str:
    padded = secret + "=" * (-len(secret) % 8)
    key = base64.b32decode(padded)
    digest = hmac.new(key, struct.pack(">Q", counter), hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    code = struct.unpack(">I", digest[offset:offset + 4])[0] & 0x7FFFFFFF
    return f"{code % 1_000_000:06d}"


def totp_code(secret: str, at: int | None = None) -> str:
    return _hotp(secret, int((at or time.time()) // 30))


def totp_seconds_remaining(at: int | None = None) -> int:
    return 30 - int((at or time.time()) % 30)


def verify_totp(secret: str, code: str, *, window: int = 1) -> bool:
    code = (code or "").strip().replace(" ", "")
    if not code.isdigit() or len(code) != 6 or not secret:
        return False
    counter = int(time.time()) // 30
    return any(
        hmac.compare_digest(_hotp(secret, counter + offset), code)
        for offset in range(-window, window + 1)
    )


# ---------------------------------------------------------------------------
# Login throttling helpers
# ---------------------------------------------------------------------------


def lock_state(failures: int, last_failure: str | None) -> tuple[bool, int]:
    """Return (locked, seconds_remaining) for a user's recent failures."""
    if failures < config.MAX_LOGIN_FAILURES or not last_failure:
        return False, 0
    try:
        last = datetime.fromisoformat(last_failure)
    except ValueError:
        return False, 0
    elapsed = (datetime.now(timezone.utc) - last).total_seconds()
    remaining = config.LOGIN_LOCK_SECONDS - elapsed
    return (remaining > 0, max(0, int(remaining)))


def session_expiry() -> str:
    return (datetime.now(timezone.utc) + timedelta(seconds=config.SESSION_TTL_SECONDS)).isoformat()
