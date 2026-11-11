"""Regression tests for the contextual anomaly-rule evaluator (Phase 2, bug 1).

Before the fix, ``_rule_matches`` only understood ``>=``, so the built-in
``hour<=5`` (off-hours) and ``new_device==1`` (new device) rules never fired.
"""

from __future__ import annotations

import builtins
import math

import pytest

from app import anomaly, database, risk, simulator


def _legacy_rule_matches(expression, vector):
    """The pre-fix evaluator, kept only to prove the fix does not move normal traffic."""
    try:
        field, threshold = expression.split(">=")
        return float(vector.get(field, 0.0)) >= float(threshold)
    except (ValueError, TypeError):
        return False


NORMAL_VECTOR = {
    "hour": 13.0,
    "requests_last_5m": 4.0,
    "geo_distance_km": 0.0,
    "failed_attempts_24h": 0.0,
    "device_trust": 90.0,
    "bytes_out_mb": 12.0,
    "session_minutes": 24.0,
    "sensitivity": 2.0,
    "new_device": 0.0,
}


def _rule_hits(result):
    return {hit["rule"] for hit in result["rule_hits"]}


# ---------------------------------------------------------------------------
# Operator semantics
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "expression, value, expected",
    [
        (">=", 5, True), (">=", 5.01, True), (">=", 4.99, False),
        ("<=", 5, True), ("<=", 4.99, True), ("<=", 5.01, False),
        ("==", 5, True), ("==", 5.0, True), ("==", 4.99, False), ("==", 5.01, False),
        (">", 5.01, True), (">", 5, False), (">", 4.99, False),
        ("<", 4.99, True), ("<", 5, False), ("<", 5.01, False),
    ],
)
def test_every_operator_including_boundaries(expression, value, expected):
    assert anomaly._rule_matches(f"x{expression}5", {"x": value}) is expected


def test_whitespace_negative_and_decimal_thresholds():
    assert anomaly._rule_matches("  x >= -2.5 ", {"x": -2.5}) is True
    assert anomaly._rule_matches("x<0.25", {"x": 0.2}) is True
    assert anomaly._rule_matches("x<0.25", {"x": 0.25}) is False


def test_all_builtin_rules_parse():
    for expression, floor, _reason in anomaly.RULES:
        assert anomaly._parse_rule(expression) is not None, expression
        assert 0.0 < floor <= 1.0


# ---------------------------------------------------------------------------
# Boundaries of the built-in rules
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "expression, field, value, expected",
    [
        ("hour<=5", "hour", 0, True),
        ("hour<=5", "hour", 5, True),
        ("hour<=5", "hour", 6, False),
        ("hour<=5", "hour", 13, False),
        ("new_device==1", "new_device", 1.0, True),
        ("new_device==1", "new_device", True, True),
        ("new_device==1", "new_device", 0.0, False),
        ("geo_distance_km>=1500", "geo_distance_km", 1499.9, False),
        ("geo_distance_km>=1500", "geo_distance_km", 1500, True),
        ("geo_distance_km>=3000", "geo_distance_km", 2999.9, False),
        ("geo_distance_km>=3000", "geo_distance_km", 3000, True),
        ("failed_attempts_24h>=6", "failed_attempts_24h", 5, False),
        ("failed_attempts_24h>=6", "failed_attempts_24h", 6, True),
        ("requests_last_5m>=40", "requests_last_5m", 39.9, False),
        ("requests_last_5m>=40", "requests_last_5m", 40, True),
        ("bytes_out_mb>=250", "bytes_out_mb", 249.9, False),
        ("bytes_out_mb>=250", "bytes_out_mb", 250, True),
    ],
)
def test_builtin_rule_boundaries(expression, field, value, expected):
    assert anomaly._rule_matches(expression, {field: value}) is expected


# ---------------------------------------------------------------------------
# Safe failure
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "expression",
    [
        "",
        "hour",
        "hour=>5",
        "hour=<5",
        "hour=5",
        "hour!=5",
        "hour<>5",
        "5<=hour",
        "hour<=five",
        "hour<=5;import os",
        "hour <= 5 <= 6",
        "hour<=5 or True",
        "__import__('os').system('echo pwned')",
        None,
        42,
        ["hour<=5"],
    ],
)
def test_malformed_expressions_never_match_and_never_raise(expression):
    assert anomaly._rule_matches(expression, {"hour": 3, "__import__": 1}) is False


@pytest.mark.parametrize("value", [None, "abc", "", object(), math.nan])
def test_non_numeric_feature_values_never_match(value):
    assert anomaly._rule_matches("hour<=5", {"hour": value}) is False


def test_missing_feature_does_not_default_to_zero():
    # The old evaluator substituted 0.0 for a missing feature, which would make
    # any "<=" rule fire on incomplete input.
    assert anomaly._rule_matches("hour<=5", {}) is False


def test_evaluator_does_not_use_eval(monkeypatch):
    def forbidden(*_args, **_kwargs):
        raise AssertionError("rule evaluation must not call eval()")

    monkeypatch.setattr(builtins, "eval", forbidden)
    anomaly._parse_rule.cache_clear()
    assert anomaly._rule_matches("hour<=5", {"hour": 3}) is True
    assert anomaly._rule_matches("new_device==1", {"new_device": 1}) is True


# ---------------------------------------------------------------------------
# Model and engine integration
# ---------------------------------------------------------------------------


def test_off_hours_rule_applies_its_floor_at_hour_5_but_not_hour_6():
    model = anomaly.get_model()
    at_five = model.score(dict(NORMAL_VECTOR, hour=5.0))
    at_six = model.score(dict(NORMAL_VECTOR, hour=6.0))

    assert "hour<=5" in _rule_hits(at_five)
    assert at_five["score"] >= 0.55
    assert "hour<=5" not in _rule_hits(at_six)
    assert at_six["score"] == at_six["isolation_score"]


def test_new_device_and_recognised_device():
    model = anomaly.get_model()
    new_device = dict(NORMAL_VECTOR, new_device=1.0)
    recognised = dict(NORMAL_VECTOR, new_device=0.0)

    assert anomaly._rule_matches("new_device==1", new_device) is True
    assert anomaly._rule_matches("new_device==1", recognised) is False
    # The floor guarantees a minimum behaviour score for a new device.
    assert model.score(new_device)["score"] >= 0.42
    assert model.score(new_device)["score"] > model.score(recognised)["score"]


def _target(email, device_name, resource_name):
    with database.get_db() as conn:
        user = database.row(conn, "SELECT * FROM users WHERE email = ?", (email,))
        device = database.row(
            conn, "SELECT * FROM devices WHERE user_id = ? AND name = ?", (user["id"], device_name)
        )
        resource = database.row(conn, "SELECT * FROM resources WHERE name = ?", (resource_name,))
    return user["id"], device["id"], resource["id"]


CLEAN_CONTEXT = {
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
OFF_HOURS_REASON = "Access outside the user's normal working hours."


def test_engine_reports_off_hours_access_only_up_to_hour_5():
    ids = _target("analyst@hybridcloud.io", "AISHA-LT-02", "internal-wiki")
    at_five = risk.evaluate(*ids, dict(CLEAN_CONTEXT, hour=5), persist=False)
    at_six = risk.evaluate(*ids, dict(CLEAN_CONTEXT, hour=6), persist=False)

    assert OFF_HOURS_REASON in [reason["text"] for reason in at_five["reasons"]]
    assert OFF_HOURS_REASON not in [reason["text"] for reason in at_six["reasons"]]
    assert at_five["anomaly_score"] >= 0.55
    assert at_five["risk_score"] > at_six["risk_score"]


def test_engine_scores_new_device_above_recognised_device():
    ids = _target("analyst@hybridcloud.io", "AISHA-LT-02", "internal-wiki")
    recognised = risk.evaluate(*ids, dict(CLEAN_CONTEXT, new_device=False), persist=False)
    new_device = risk.evaluate(*ids, dict(CLEAN_CONTEXT, new_device=True), persist=False)

    assert recognised["decision"] == "ALLOW"
    assert recognised["features"]["new_device"] == 0.0
    assert new_device["features"]["new_device"] == 1.0
    assert new_device["anomaly_score"] >= 0.42
    assert new_device["risk_score"] > recognised["risk_score"]


def test_fix_does_not_change_scores_for_normal_traffic(monkeypatch):
    """The labelled normal corpus never hits the repaired rules, so its scores are unchanged."""
    fixed = simulator.run_normal(140, persist=False, seed=2026)
    monkeypatch.setattr(anomaly, "_rule_matches", _legacy_rule_matches)
    legacy = simulator.run_normal(140, persist=False, seed=2026)

    assert [r["risk_score"] for r in fixed] == [r["risk_score"] for r in legacy]
    assert [r["decision"] for r in fixed] == [r["decision"] for r in legacy]
    repaired = {"hour<=5", "new_device==1"}
    assert not any(repaired & _rule_hits(r["anomaly"]) for r in fixed)
