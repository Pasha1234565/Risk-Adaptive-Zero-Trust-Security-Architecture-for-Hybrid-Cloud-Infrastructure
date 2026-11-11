"""Decision-level regression tests for the risk engine (Phase 2 regression list).

Covers normal, restricted and blocked outcomes, the behaviour rules that drive
detection (high request rate, mass egress), and event/alert logging. Contexts
were chosen with margin from the band thresholds so they are not brittle.
"""

from __future__ import annotations

from app import database, risk

CLEAN = {
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


def _ids(email: str, device_name: str, resource_name: str) -> tuple[int, int, int]:
    with database.get_db() as conn:
        user = database.row(conn, "SELECT id FROM users WHERE email = ?", (email,))
        device = database.row(
            conn, "SELECT id FROM devices WHERE user_id = ? AND name = ?", (user["id"], device_name)
        )
        resource = database.row(conn, "SELECT id FROM resources WHERE name = ?", (resource_name,))
    return user["id"], device["id"], resource["id"]


def _evaluate(target, **overrides):
    return risk.evaluate(*_ids(*target), dict(CLEAN, **overrides), persist=False)


def _rules(result) -> set[str]:
    return {hit["rule"] for hit in result["anomaly"]["rule_hits"]}


ANALYST_WIKI = ("analyst@hybridcloud.io", "AISHA-LT-02", "internal-wiki")
ANALYST_LAKE = ("analyst@hybridcloud.io", "AISHA-LT-02", "analytics-lake")


def test_normal_access_is_allowed_with_low_risk():
    result = _evaluate(ANALYST_WIKI)
    assert result["decision"] == "ALLOW"
    assert result["risk_score"] < 20
    assert _rules(result) == set()


def test_high_request_rate_triggers_rule_only_at_threshold():
    below = _evaluate(ANALYST_WIKI, requests_last_5m=39)
    at = _evaluate(ANALYST_WIKI, requests_last_5m=40)

    assert "requests_last_5m>=40" not in _rules(below)
    assert "requests_last_5m>=40" in _rules(at)
    assert at["anomaly_score"] >= 0.74
    assert at["risk_score"] > below["risk_score"]


def test_mass_egress_triggers_rule():
    normal = _evaluate(ANALYST_LAKE, bytes_out_mb=30)
    mass = _evaluate(ANALYST_LAKE, bytes_out_mb=300)

    assert "bytes_out_mb>=250" not in _rules(normal)
    assert "bytes_out_mb>=250" in _rules(mass)
    assert mass["anomaly_score"] >= 0.82
    assert mass["risk_score"] > normal["risk_score"]


def test_role_outside_policy_is_restricted():
    result = _evaluate(("dev@hybridcloud.io", "dev-vm-01", "finance-db"))

    assert result["decision"] == "RESTRICT"
    assert result["policy"]["role_restricted"] is True
    assert any("Least privilege" in reason["text"] for reason in result["reasons"])


def test_malicious_source_is_blocked_regardless_of_score():
    result = _evaluate(ANALYST_WIKI, threat_intel="malicious")

    assert result["decision"] == "BLOCK"
    assert result["risk_score"] < 80  # blocked by the hard control, not by the score band
    assert any("malicious" in reason["text"] for reason in result["reasons"])


def test_impossible_travel_with_new_device_is_contained():
    result = _evaluate(
        ("admin@hybridcloud.io", "FARHAAN-LT-01", "finance-db"),
        geo="London, UK", hour=3, new_device=True, threat_intel="suspicious",
    )
    assert result["decision"] in {"RESTRICT", "BLOCK"}
    assert result["anomaly_score"] >= 0.92  # intercontinental distance floor


def test_restricted_and_blocked_decisions_are_logged_with_alerts():
    restricted = risk.evaluate(
        *_ids("dev@hybridcloud.io", "dev-vm-01", "finance-db"), dict(CLEAN), persist=True
    )
    blocked = risk.evaluate(*_ids(*ANALYST_WIKI), dict(CLEAN, threat_intel="malicious"), persist=True)
    allowed = risk.evaluate(*_ids(*ANALYST_WIKI), dict(CLEAN), persist=True)

    with database.get_db() as conn:
        for result, severity in ((restricted, "high"), (blocked, "critical")):
            event = database.row(conn, "SELECT decision, scenario FROM events WHERE id = ?", (result["event_id"],))
            alert = database.row(conn, "SELECT severity, status FROM alerts WHERE event_id = ?", (result["event_id"],))
            assert event == {"decision": result["decision"], "scenario": "live"}
            assert alert == {"severity": severity, "status": "open"}
        assert database.row(conn, "SELECT id FROM events WHERE id = ?", (allowed["event_id"],))
        assert database.row(conn, "SELECT id FROM alerts WHERE event_id = ?", (allowed["event_id"],)) is None
