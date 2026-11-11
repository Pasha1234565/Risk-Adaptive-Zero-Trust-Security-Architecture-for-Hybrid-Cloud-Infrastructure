"""Session lifecycle and server-side revocation (Phase 2, bug 2).

Before the fix, logout only deleted the browser cookie; the signed token stayed
valid until expiry and could be replayed as a cookie or ``Authorization: Bearer``.
"""

from __future__ import annotations

import time

from app import config, database, security
from conftest import ADMIN, ANALYST, login

COOKIE = config.SESSION_COOKIE


def _login_token(client, credentials) -> str:
    response = login(client, *credentials)
    assert response.status_code == 200, response.text
    token = client.cookies.get(COOKIE)
    assert token
    return token


def _bearer(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


# ---------------------------------------------------------------------------
# Login and session creation
# ---------------------------------------------------------------------------


def test_normal_login_creates_a_session_cookie_and_jti(make_client):
    browser = make_client()
    response = login(browser, *ANALYST)

    assert response.status_code == 200
    assert response.json()["user"]["email"] == ANALYST[0]
    set_cookie = response.headers["set-cookie"].lower()
    assert f"{COOKIE}=" in set_cookie
    assert "httponly" in set_cookie and "samesite=lax" in set_cookie
    claims = security.decode_token(browser.cookies.get(COOKIE))
    assert claims["sub"] == str(response.json()["user"]["id"])
    assert isinstance(claims["jti"], str) and claims["jti"]
    assert claims["exp"] > time.time()


def test_invalid_password_is_rejected_without_a_session(make_client):
    browser = make_client()
    response = login(browser, "dev@hybridcloud.io", "not-the-password")

    assert response.status_code == 401
    assert "Invalid email or password" in response.json()["detail"]
    assert browser.cookies.get(COOKIE) is None
    assert browser.get("/api/auth/me").status_code == 401
    # A correct login afterwards still works and resets the failure window.
    assert login(browser, "dev@hybridcloud.io", "Dev#2026").status_code == 200


# ---------------------------------------------------------------------------
# Logout revokes the session server-side (scenarios A-F)
# ---------------------------------------------------------------------------


def test_logout_revokes_cookie_and_bearer_but_not_other_sessions(make_client):
    browser = make_client()
    other = make_client()

    # A. Login creates a valid session.
    token = _login_token(browser, ANALYST)
    other_token = _login_token(other, ANALYST)
    assert token != other_token

    # B. The token works before logout, as cookie and as Bearer.
    assert browser.get("/api/auth/me").status_code == 200
    replay = make_client()
    assert replay.get("/api/auth/me", headers=_bearer(token)).status_code == 200

    # C. Logout succeeds and clears the cookie.
    response = browser.post("/api/auth/logout")
    assert response.status_code == 200
    assert response.json() == {"ok": True}
    assert browser.cookies.get(COOKIE) is None

    # D. The same old cookie value cannot access protected APIs.
    stale_cookie = make_client(cookies={COOKIE: token})
    for path in ("/api/auth/me", "/api/dashboard", "/api/context/inventory", "/api/events"):
        assert stale_cookie.get(path).status_code == 401, path
    page = stale_cookie.get("/")
    assert page.status_code == 303 and page.headers["location"] == "/login"

    # E. The same old token cannot be replayed as a Bearer token.
    for path in ("/api/auth/me", "/api/dashboard", "/api/topology"):
        assert replay.get(path, headers=_bearer(token)).status_code == 401, path

    # F. An unrelated session for the same identity keeps working.
    assert other.get("/api/auth/me").status_code == 200
    assert make_client().get("/api/auth/me", headers=_bearer(other_token)).status_code == 200


def test_bearer_only_logout_revokes_that_token(make_client):
    issuer = make_client()
    token = _login_token(issuer, ANALYST)
    api_client = make_client()

    assert api_client.get("/api/auth/me", headers=_bearer(token)).status_code == 200
    assert api_client.post("/api/auth/logout", headers=_bearer(token)).status_code == 200
    assert api_client.get("/api/auth/me", headers=_bearer(token)).status_code == 401
    # The cookie holding the same token is revoked too.
    assert issuer.get("/api/auth/me").status_code == 401


def test_logout_is_idempotent_without_a_valid_token(make_client):
    anonymous = make_client()
    assert anonymous.post("/api/auth/logout").status_code == 200
    garbage = anonymous.post("/api/auth/logout", headers=_bearer("not.a.token"))
    assert garbage.status_code == 200
    assert garbage.json() == {"ok": True}


def test_revocation_is_recorded_until_token_expiry(make_client):
    browser = make_client()
    token = _login_token(browser, ANALYST)
    claims = security.decode_token(token)
    browser.post("/api/auth/logout")

    with database.get_db() as conn:
        row = database.row(
            conn, "SELECT user_id, expires_at FROM revoked_sessions WHERE jti = ?", (claims["jti"],)
        )
    assert row == {"user_id": int(claims["sub"]), "expires_at": claims["exp"]}
    assert database.is_session_revoked(claims["jti"]) is True


# ---------------------------------------------------------------------------
# Token validation
# ---------------------------------------------------------------------------


def _user_id(email: str) -> int:
    with database.get_db() as conn:
        return database.row(conn, "SELECT id FROM users WHERE email = ?", (email,))["id"]


def test_expired_session_is_rejected(make_client):
    expired = security.issue_token(_user_id(ANALYST[0]), ttl_seconds=-5)
    api_client = make_client()

    assert security.decode_token(expired) is None
    assert api_client.get("/api/auth/me", headers=_bearer(expired)).status_code == 401
    assert make_client(cookies={COOKIE: expired}).get("/api/auth/me").status_code == 401


def test_tampered_and_jti_less_tokens_are_rejected(make_client):
    valid = security.issue_token(_user_id(ANALYST[0]))
    header, payload, signature = valid.split(".")
    tampered = ".".join([header, payload, signature[:-2] + ("AA" if signature[-2:] != "AA" else "BB")])

    # A correctly signed token without a jti cannot be revoked, so it is refused.
    now = int(time.time())
    claims = {"sub": str(_user_id(ANALYST[0])), "iat": now, "exp": now + 600}
    segments = [
        security._b64url(b'{"alg":"HS256","typ":"JWT"}'),
        security._b64url(security.json.dumps(claims, separators=(",", ":")).encode()),
    ]
    signature_bytes = security.hmac.new(
        security._secret(), ".".join(segments).encode("ascii"), security.hashlib.sha256
    ).digest()
    no_jti = ".".join(segments + [security._b64url(signature_bytes)])

    api_client = make_client()
    for token in (tampered, no_jti, "a.b", ""):
        assert security.verify_session_token(token) is None
        assert api_client.get("/api/auth/me", headers=_bearer(token)).status_code == 401


def test_purge_removes_only_expired_revocations():
    now = int(time.time())
    database.revoke_session("phase2-expired-jti", None, now - 10)
    database.revoke_session("phase2-live-jti", None, now + 3600)

    removed = database.purge_expired_revocations(now)

    assert removed >= 1
    assert database.is_session_revoked("phase2-expired-jti") is False
    assert database.is_session_revoked("phase2-live-jti") is True


# ---------------------------------------------------------------------------
# Admin permissions are unaffected
# ---------------------------------------------------------------------------


def test_admin_access_control_still_enforced(make_client):
    analyst = make_client()
    _login_token(analyst, ANALYST)
    assert analyst.get("/api/admin/inventory").status_code == 403
    assert analyst.get("/admin").status_code == 303

    admin = make_client()
    admin_token = _login_token(admin, ADMIN)
    assert admin.get("/api/admin/inventory").status_code == 200
    assert admin.get("/admin").status_code == 200

    admin.post("/api/auth/logout")
    assert make_client().get("/api/admin/inventory", headers=_bearer(admin_token)).status_code == 401
