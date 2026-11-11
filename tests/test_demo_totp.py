"""Demo TOTP disclosure helper and the real step-up flow (Phase 2, bug 3).

Before the fix, any signed-in session could call ``GET /api/auth/totp`` and
receive the very code that step-up MFA is supposed to obtain from an
independent authenticator.
"""

from __future__ import annotations

import time

import pytest

from app import config, database, security
from app.main import app
from conftest import ANALYST, login

LOCAL = {"base_url": "http://127.0.0.1:8000", "client": ("127.0.0.1", 50000)}
FINANCE = ("finance@hybridcloud.io", "Finance#2026")
SERVICE = ("svc-backup@hybridcloud.io", "Service#2026")


def _mfa_secret(email: str) -> str:
    with database.get_db() as conn:
        return database.row(conn, "SELECT mfa_secret FROM users WHERE email = ?", (email,))["mfa_secret"]


@pytest.fixture
def demo_enabled(monkeypatch):
    monkeypatch.setattr(config, "DEMO_TOTP_ENABLED", True)


# ---------------------------------------------------------------------------
# Configuration flag
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("value", ["1", "true", "TRUE", " yes ", "on"])
def test_flag_accepts_only_explicit_true_values(monkeypatch, value):
    monkeypatch.setenv("ZT_ENABLE_DEMO_TOTP", value)
    assert config.env_flag("ZT_ENABLE_DEMO_TOTP") is True


@pytest.mark.parametrize("value", ["", "0", "false", "off", "no", "enabled", "tru"])
def test_flag_treats_anything_else_as_false(monkeypatch, value):
    monkeypatch.setenv("ZT_ENABLE_DEMO_TOTP", value)
    assert config.env_flag("ZT_ENABLE_DEMO_TOTP") is False


def test_flag_is_false_when_unset(monkeypatch):
    monkeypatch.delenv("ZT_ENABLE_DEMO_TOTP", raising=False)
    assert config.env_flag("ZT_ENABLE_DEMO_TOTP") is False


# ---------------------------------------------------------------------------
# Disabled by default
# ---------------------------------------------------------------------------


def test_demo_helper_is_disabled_by_default():
    assert config.DEMO_TOTP_ENABLED is False
    assert "/api/auth/totp" not in app.openapi()["paths"]


def test_disabled_helper_returns_no_code_even_for_a_local_signed_in_user(make_client):
    browser = make_client(**LOCAL)
    assert login(browser, *ANALYST).status_code == 200

    response = browser.get("/api/auth/totp")

    assert response.status_code == 404
    assert response.json() == {"detail": "Not Found"}
    assert "code" not in response.text
    assert make_client(**LOCAL).get("/api/auth/totp").status_code == 404


def test_disabled_helper_is_not_offered_in_the_console(make_client):
    browser = make_client(**LOCAL)
    login(browser, *ANALYST)
    page = browser.get("/access")

    assert page.status_code == 200
    assert 'data-demo-totp="off"' in page.text
    assert "demo-totp-pill" not in page.text


# ---------------------------------------------------------------------------
# Explicit local demo mode
# ---------------------------------------------------------------------------


def test_enabled_helper_serves_a_valid_code_to_local_signed_in_user(make_client, demo_enabled):
    browser = make_client(**LOCAL)
    assert login(browser, *ANALYST).status_code == 200

    response = browser.get("/api/auth/totp")

    assert response.status_code == 200
    body = response.json()
    assert set(body) == {"code", "seconds_remaining", "note"}
    assert security.verify_totp(_mfa_secret(ANALYST[0]), body["code"])
    assert "mfa_secret" not in response.text
    assert _mfa_secret(ANALYST[0]) not in response.text


def test_enabled_helper_is_indicated_in_the_console(make_client, demo_enabled):
    browser = make_client(**LOCAL)
    login(browser, *ANALYST)
    page = browser.get("/access")

    assert 'data-demo-totp="on"' in page.text
    assert "Demo MFA helper on" in page.text


def test_ipv6_loopback_counts_as_local(make_client, demo_enabled):
    browser = make_client(base_url="http://[::1]:8000", client=("::1", 50000))
    login(browser, *ANALYST)
    assert browser.get("/api/auth/totp").status_code == 200


@pytest.mark.parametrize(
    "client_kwargs, headers",
    [
        ({"client": ("testclient", 50000)}, {}),                                   # non-IP peer
        ({"client": ("203.0.113.7", 50000), "base_url": "http://127.0.0.1:8000"}, {}),  # remote peer
        ({"client": ("192.168.1.20", 50000), "base_url": "http://127.0.0.1:8000"}, {}),  # LAN peer
        (LOCAL, {"X-Forwarded-For": "203.0.113.7"}),                               # via proxy
        (LOCAL, {"Forwarded": "for=203.0.113.7"}),
        (LOCAL, {"X-Real-IP": "203.0.113.7"}),
        ({"client": ("127.0.0.1", 50000), "base_url": "http://zt.example.com"}, {}),  # rebinding host
    ],
)
def test_enabled_helper_refuses_non_local_requests(make_client, demo_enabled, client_kwargs, headers):
    issuer = make_client(**LOCAL)
    login(issuer, *ANALYST)
    token = issuer.cookies.get(config.SESSION_COOKIE)
    remote = make_client(**client_kwargs)

    response = remote.get("/api/auth/totp", headers={**headers, "Authorization": f"Bearer {token}"})

    assert response.status_code == 403
    assert "code" not in response.json()
    page = remote.get("/access", headers={**headers, "Authorization": f"Bearer {token}"})
    assert 'data-demo-totp="off"' in page.text


def test_enabled_helper_still_requires_authentication(make_client, demo_enabled):
    assert make_client(**LOCAL).get("/api/auth/totp").status_code == 401


def test_enabled_helper_refuses_identities_without_mfa(make_client, demo_enabled):
    browser = make_client(**LOCAL)
    assert login(browser, *SERVICE).status_code == 200
    response = browser.get("/api/auth/totp")
    assert response.status_code == 400
    assert "code" not in response.json()


# ---------------------------------------------------------------------------
# TOTP verification (independent of the helper)
# ---------------------------------------------------------------------------


def test_totp_verification_accepts_current_and_adjacent_steps_only():
    secret = security.generate_totp_secret()
    now = int(time.time())

    for offset in (-30, 0, 30):
        assert security.verify_totp(secret, security.totp_code(secret, at=now + offset))
    for offset in (-150, 150):
        assert not security.verify_totp(secret, security.totp_code(secret, at=now + offset))
    for bad in ("", "12345", "1234567", "abcdef", "12 34 5"):
        assert not security.verify_totp(secret, bad)
    assert not security.verify_totp("", security.totp_code(secret))


def _invalid_code(secret: str) -> str:
    now = int(time.time())
    valid = {security.totp_code(secret, at=now + step * 30) for step in range(-2, 3)}
    return next(code for code in ("000000", "111111", "222222") if code not in valid)


def test_step_up_challenge_over_http_invalid_valid_and_single_use(make_client):
    browser = make_client()
    assert login(browser, *FINANCE).status_code == 200
    inventory = browser.get("/api/context/inventory").json()
    user = next(u for u in inventory["users"] if u["email"] == FINANCE[0])
    device = next(d for d in user["devices"] if d["name"] == "PRIYA-LT-03")
    resource = next(r for r in inventory["resources"] if r["name"] == "finance-db")

    evaluated = browser.post(
        "/api/access/evaluate",
        json={
            "user_id": user["id"],
            "device_id": device["id"],
            "resource_id": resource["id"],
            "context": {"hour": 13, "failed_attempts_24h": 0, "mfa_verified": False},
        },
    ).json()
    assert evaluated["decision"] == "CHALLENGE"
    challenge_id = evaluated["challenge"]["id"]
    secret = _mfa_secret(FINANCE[0])

    wrong = browser.post("/api/access/challenge", json={"challenge_id": challenge_id, "code": _invalid_code(secret)})
    assert wrong.status_code == 400
    assert wrong.json()["detail"] == "Incorrect verification code"

    right = browser.post(
        "/api/access/challenge", json={"challenge_id": challenge_id, "code": security.totp_code(secret)}
    )
    assert right.status_code == 200, right.text
    assert right.json()["step_up"] is True
    assert right.json()["context"]["mfa_verified"] is True

    replay = browser.post(
        "/api/access/challenge", json={"challenge_id": challenge_id, "code": security.totp_code(secret)}
    )
    assert replay.status_code == 400
    assert replay.json()["detail"] == "Challenge expired or already used"
