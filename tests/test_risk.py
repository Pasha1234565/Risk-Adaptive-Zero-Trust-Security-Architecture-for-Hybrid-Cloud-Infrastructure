from __future__ import annotations

import pytest

from app import database, risk, security


def _target(email: str, device_name: str, resource_name: str):
    with database.get_db() as conn:
        user = database.row(conn, "SELECT * FROM users WHERE email = ?", (email,))
        device = database.row(conn, "SELECT * FROM devices WHERE user_id = ? AND name = ?", (user["id"], device_name))
        resource = database.row(conn, "SELECT * FROM resources WHERE name = ?", (resource_name,))
    assert user and device and resource
    return user, device, resource


def _clean_context(**overrides):
    context = {
        "geo": "Bengaluru, IN",
        "hour": 13,
        "requests_last_5m": 4,
        "failed_attempts_24h": 0,
        "bytes_out_mb": 15,
        "session_minutes": 25,
        "concurrent_sessions": 1,
        "new_device": False,
        "mfa_verified": True,
        "threat_intel": "clean",
    }
    context.update(overrides)
    return context


def test_routine_access_is_allowed():
    user, device, resource = _target("analyst@hybridcloud.io", "AISHA-LT-02", "internal-wiki")
    result = risk.evaluate(user["id"], device["id"], resource["id"], _clean_context(), persist=False)
    assert result["decision"] == "ALLOW"
    assert result["risk_score"] < 40
    assert sum(signal["weight"] for signal in result["signals"]) == pytest.approx(100, abs=0.1)
    assert result["challenge"] is None


def test_malicious_context_is_blocked_by_hard_control():
    user, device, resource = _target("analyst@hybridcloud.io", "AISHA-LT-02", "internal-wiki")
    result = risk.evaluate(
        user["id"],
        device["id"],
        resource["id"],
        _clean_context(threat_intel="malicious", geo="Lagos, NG", hour=2, failed_attempts_24h=11),
        persist=False,
    )
    assert result["decision"] == "BLOCK"
    assert any("malicious" in reason["text"].lower() for reason in result["reasons"])


def test_impossible_travel_escalates():
    user, device, resource = _target("admin@hybridcloud.io", "FARHAAN-LT-01", "finance-db")
    result = risk.evaluate(
        user["id"],
        device["id"],
        resource["id"],
        _clean_context(geo="London, UK", hour=3, new_device=True, threat_intel="suspicious"),
        persist=False,
    )
    assert result["decision"] in {"RESTRICT", "BLOCK"}
    assert result["risk_score"] >= 60


def test_missing_mfa_challenge_can_be_satisfied_and_recovered():
    user, device, resource = _target("finance@hybridcloud.io", "PRIYA-LT-03", "finance-db")
    result = risk.evaluate(
        user["id"],
        device["id"],
        resource["id"],
        _clean_context(mfa_verified=False),
        persist=True,
    )
    assert result["decision"] == "CHALLENGE", result["reasons"]
    assert result["challenge"]
    assert result["event_id"]

    code = security.totp_code(user["mfa_secret"])
    recovered = risk.verify_challenge(result["challenge"]["id"], code)

    assert recovered["step_up"] is True
    assert recovered["context"]["mfa_verified"] is True
    assert recovered["decision"] in {"ALLOW", "CHALLENGE"}
    assert recovered["risk_score"] <= result["risk_score"]

    with database.get_db() as conn:
        stored = database.row(conn, "SELECT decision, outcome FROM events WHERE id = ?", (result["event_id"],))
    assert stored["outcome"] == "step_up_verified"
    assert stored["decision"] == recovered["decision"]


def test_challenge_token_is_single_use():
    user, device, resource = _target("finance@hybridcloud.io", "PRIYA-LT-03", "finance-db")
    result = risk.evaluate(
        user["id"], device["id"], resource["id"], _clean_context(mfa_verified=False), persist=True
    )
    code = security.totp_code(user["mfa_secret"])
    risk.verify_challenge(result["challenge"]["id"], code)
    with pytest.raises(ValueError):
        risk.verify_challenge(result["challenge"]["id"], code)
