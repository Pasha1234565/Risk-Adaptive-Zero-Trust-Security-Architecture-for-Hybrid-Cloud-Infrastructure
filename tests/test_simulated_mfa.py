"""Simulated MFA separated from real MFA (Phase 2.2, Task D).

Before this change a challenge raised while an operator simulated access for
another identity was answered with that identity's real TOTP code. Operator
mistakes consumed the identity's TOTP time step and counted towards its
failure throttle: six wrong codes by the admin on simulations locked Priya
(finance) out of her own real step-up with HTTP 429.

Now a challenge has a mode. ``simulation`` (operator acting for someone else,
or simulator traffic) is answered only with an operator-chosen
``simulated_outcome``; the subject's TOTP counter and throttle are never
touched, the attempt is recorded for audit as mode 'simulation' against the
operator, and the event is labelled as simulated. ``live`` challenges keep
the full protection and reject simulated outcomes.
"""

from __future__ import annotations

import sqlite3

import pytest

from app import config, database, risk, security, simulator
from conftest import ADMIN, ANALYST, decrypted, login

FINANCE = ("finance@hybridcloud.io", "Finance#2026")
CONTRACTOR = ("contractor@hybridcloud.io", "Guest#2026")
CONTEXT = {"geo": "Bengaluru, IN", "hour": 13, "requests_last_5m": 4, "failed_attempts_24h": 0,
           "bytes_out_mb": 15, "session_minutes": 25, "concurrent_sessions": 1,
           "new_device": False, "mfa_verified": False, "threat_intel": "clean"}


def _user(email: str) -> dict:
    with database.get_db() as conn:
        return decrypted(database.row(conn, "SELECT * FROM users WHERE email = ?", (email,)))


def _finance_body(*, as_subject: bool) -> dict:
    finance = _user(FINANCE[0])
    with database.get_db() as conn:
        device = database.row(conn, "SELECT id FROM devices WHERE user_id = ? AND name = 'PRIYA-LT-03'", (finance["id"],))
        resource = database.row(conn, "SELECT id FROM resources WHERE name = 'finance-db'")
    body = {"device_id": device["id"], "resource_id": resource["id"], "context": CONTEXT}
    if as_subject:
        body["user_id"] = finance["id"]
    return body


def _signed_in(make_client, credentials):
    browser = make_client()
    assert login(browser, *credentials).status_code == 200
    return browser


def _challenge(browser, *, simulate: bool) -> dict:
    response = browser.post("/api/access/evaluate", json=_finance_body(as_subject=simulate))
    assert response.status_code == 200, response.text
    assert response.json()["decision"] == "CHALLENGE", response.text
    return response.json()


def _answer(browser, token: str, **answer):
    return browser.post("/api/access/challenge", json={"challenge_id": token, **answer})


def _attempts(user_id: int) -> list[dict]:
    with database.get_db() as conn:
        return database.rows(conn, "SELECT * FROM mfa_attempts WHERE user_id = ? ORDER BY id", (user_id,))


def test_operator_simulation_does_not_throttle_or_spend_the_subjects_mfa(make_client):
    """The Phase 2.2 reproduction: it used to end with finance receiving 429."""
    finance = _user(FINANCE[0])
    admin = _signed_in(make_client, ADMIN)
    admin_id = _user(ADMIN[0])["id"]
    for _ in range(2):  # 6 simulated failures, as many as the identity budget
        token = _challenge(admin, simulate=True)["challenge"]["id"]
        statuses = [_answer(admin, token, simulated_outcome="failure").status_code for _ in range(3)]
        assert statuses == [400, 400, 429]
    # Real codes are refused for simulations and change nothing.
    token = _challenge(admin, simulate=True)["challenge"]["id"]
    refused = _answer(admin, token, code=security.totp_code(finance["mfa_secret"]))
    assert refused.status_code == 400 and refused.json()["detail"] == risk.SIMULATION_NEEDS_OUTCOME
    assert risk.challenge_state(token)["failed_attempts"] == 0

    attempts = _attempts(finance["id"])
    assert len(attempts) == 6
    assert {(a["mode"], a["success"], a["actor_user_id"]) for a in attempts} == {("simulation", 0, admin_id)}
    assert database.recent_mfa_failures(finance["id"], config.MFA_USER_FAILURE_WINDOW_SECONDS)[0] == 0
    assert database.last_totp_counter(finance["id"]) is None

    # Priya's own real step-up is unaffected.
    owner = _signed_in(make_client, FINANCE)
    own = _challenge(owner, simulate=False)["challenge"]
    assert own["mode"] == "live"
    response = _answer(owner, own["id"], code=security.totp_code(finance["mfa_secret"]))
    assert response.status_code == 200, response.text
    assert response.json()["step_up_mode"] == "live"


def test_simulated_success_is_labelled_and_leaves_real_mfa_untouched(make_client):
    finance = _user(FINANCE[0])
    analyst = _signed_in(make_client, ANALYST)
    result = _challenge(analyst, simulate=True)
    assert result["simulated"] is True and result["challenge"]["mode"] == "simulation"
    response = _answer(analyst, result["challenge"]["id"], simulated_outcome="success")
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["step_up"] is True and body["step_up_mode"] == "simulation"
    assert "no authenticator code was checked" in body["reasons"][-1]["text"]
    assert risk.challenge_state(result["challenge"]["id"])["status"] == "consumed"
    with database.get_db() as conn:
        event = database.row(conn, "SELECT outcome, actor_user_id FROM events WHERE id = ?", (result["event_id"],))
    assert event == {"outcome": "step_up_simulated", "actor_user_id": _user(ANALYST[0])["id"]}
    assert [(a["mode"], a["success"]) for a in _attempts(finance["id"])] == [("simulation", 1)]
    # The subject's TOTP step was not consumed: the current code still works for her.
    assert database.last_totp_counter(finance["id"]) is None
    owner = _signed_in(make_client, FINANCE)
    own = _challenge(owner, simulate=False)["challenge"]["id"]
    assert _answer(owner, own, code=security.totp_code(finance["mfa_secret"])).status_code == 200
    # Replaying the simulation is refused like any used challenge.
    again = _answer(analyst, result["challenge"]["id"], simulated_outcome="success")
    assert again.status_code == 400 and again.json()["detail"] == risk.INVALID_CHALLENGE


def test_event_apis_label_simulations(make_client):
    admin = _signed_in(make_client, ADMIN)
    simulated = _challenge(admin, simulate=True)["event_id"]
    owner = _signed_in(make_client, FINANCE)
    live = _challenge(owner, simulate=False)["event_id"]
    assert admin.get(f"/api/events/{simulated}").json()["simulated"] is True
    assert admin.get(f"/api/events/{live}").json()["simulated"] is False
    events = {e["id"]: e["simulated"] for e in admin.get("/api/events?limit=500").json()["events"]}
    assert events[simulated] is True and events[live] is False
    recent = {e["id"]: e["simulated"] for e in admin.get("/api/dashboard").json()["recent"]}
    assert recent.get(live) is False


def test_live_challenges_reject_simulated_outcomes(make_client):
    owner = _signed_in(make_client, FINANCE)
    token = _challenge(owner, simulate=False)["challenge"]["id"]
    # A non-operator cannot activate simulation mode at all ...
    assert _answer(owner, token, simulated_outcome="success").status_code == 403
    # ... and an operator's own (live) step-up still needs the real code.
    analyst = _signed_in(make_client, ANALYST)
    analyst_user = _user(ANALYST[0])
    with database.get_db() as conn:
        device = database.row(conn, "SELECT id FROM devices WHERE user_id = ? AND name = 'AISHA-LT-02'", (analyst_user["id"],))
        wiki = database.row(conn, "SELECT id FROM resources WHERE name = 'internal-wiki'")
    own = analyst.post("/api/access/evaluate", json={"device_id": device["id"], "resource_id": wiki["id"],
                                                     "context": CONTEXT}).json()
    assert own["decision"] == "CHALLENGE" and own["challenge"]["mode"] == "live"
    refused = _answer(analyst, own["challenge"]["id"], simulated_outcome="success")
    assert refused.status_code == 400 and refused.json()["detail"] == risk.LIVE_REJECTS_OUTCOME
    assert risk.challenge_state(own["challenge"]["id"])["failed_attempts"] == 0
    assert _answer(analyst, own["challenge"]["id"], code=security.totp_code(analyst_user["mfa_secret"])).status_code == 200
    assert risk.challenge_state(token)["status"] == "pending"


@pytest.mark.parametrize("answer", [
    {},
    {"code": "123456", "simulated_outcome": "success"},
    {"simulated_outcome": "maybe"},
    {"simulated_outcome": None, "code": None},
])
def test_exactly_one_kind_of_answer_is_accepted(make_client, answer):
    admin = _signed_in(make_client, ADMIN)
    token = _challenge(admin, simulate=True)["challenge"]["id"]
    assert _answer(admin, token, **answer).status_code == 422
    assert risk.challenge_state(token)["failed_attempts"] == 0


def test_other_operators_and_subjects_cannot_answer_a_simulation(make_client):
    admin = _signed_in(make_client, ADMIN)
    token = _challenge(admin, simulate=True)["challenge"]["id"]
    for other in (ANALYST, FINANCE, CONTRACTOR):
        response = _answer(_signed_in(make_client, other), token, simulated_outcome="success")
        assert response.status_code in (400, 403)
    assert risk.challenge_state(token)["status"] == "pending"
    assert risk.challenge_state(token)["failed_attempts"] == 0


def test_challenge_mode_rules():
    assert risk.challenge_mode(4, 4, "live") == "live"
    assert risk.challenge_mode(4, None, "live") == "live"
    assert risk.challenge_mode(4, 1, "live") == "simulation"
    assert risk.challenge_mode(4, 4, "credential_stuffing") == "simulation"
    assert risk.challenge_mode(4, None, "normal") == "simulation"


def test_all_twelve_attack_scenarios_still_run(make_client):
    admin = _signed_in(make_client, ADMIN)
    assert len(simulator.SCENARIOS) == 12
    for scenario in simulator.SCENARIOS:
        response = admin.post("/api/sim/scenario", json={"scenario_id": scenario["id"], "variants": 1})
        assert response.status_code == 200, (scenario["id"], response.text)
        for result in response.json()["results"]:
            if result.get("challenge"):
                assert result["challenge"]["mode"] == "simulation"


def test_init_db_adds_the_mode_column_to_existing_attempt_rows(tmp_path, monkeypatch):
    db_path = tmp_path / "pre-2.2.db"
    legacy = sqlite3.connect(db_path)
    schema = database.SCHEMA.replace(",\n    mode          TEXT NOT NULL DEFAULT 'live'\n);", "\n);", 1)
    assert "mode          TEXT" not in schema.split("CREATE TABLE IF NOT EXISTS mfa_attempts")[1].split(");")[0]
    legacy.executescript(schema)
    legacy.execute("INSERT INTO users (email, name, role, password_hash, created_at) "
                   "VALUES ('old@example.test', 'Old', 'analyst', 'x', '2026-01-01T00:00:00+00:00')")
    legacy.execute("INSERT INTO mfa_attempts (user_id, ts, success) VALUES (1, '2026-01-01T00:00:00+00:00', 0)")
    legacy.commit()
    legacy.close()
    monkeypatch.setattr(config, "DATA_DIR", tmp_path)
    monkeypatch.setattr(config, "DB_PATH", db_path)
    assert database.init_db() == ["mfa_attempts.mode"]
    assert database.init_db() == []
    with database.get_db() as conn:
        assert database.row(conn, "SELECT user_id, success, mode FROM mfa_attempts") == {
            "user_id": 1, "success": 0, "mode": "live"}
