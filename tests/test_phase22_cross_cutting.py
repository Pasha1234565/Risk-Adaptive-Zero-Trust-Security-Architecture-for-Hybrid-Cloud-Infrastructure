"""End-to-end checks that the Phase 2.2 changes work together and leave the
Phase 2 / 2.1 controls intact (login throttle, session revocation, replay
protection, challenge ownership, RBAC, actor attribution, PDP/PEP, audit
records, security headers)."""

from __future__ import annotations

import time

from app import config, database, risk, security
from app.main import CONTENT_SECURITY_POLICY
from conftest import ANALYST, decrypted, login

FINANCE = ("finance@hybridcloud.io", "Finance#2026")
CONTRACTOR = ("contractor@hybridcloud.io", "Guest#2026")
CONTEXT = {"geo": "Bengaluru, IN", "hour": 13, "requests_last_5m": 4, "failed_attempts_24h": 0,
           "bytes_out_mb": 15, "session_minutes": 25, "concurrent_sessions": 1,
           "new_device": False, "mfa_verified": False, "threat_intel": "clean"}


def _user(email: str) -> dict:
    with database.get_db() as conn:
        return decrypted(database.row(conn, "SELECT * FROM users WHERE email = ?", (email,)))


def _signed_in(make_client, credentials):
    browser = make_client()
    assert login(browser, *credentials).status_code == 200
    return browser


def _assert_headers(response) -> None:
    assert response.headers["content-security-policy"] == CONTENT_SECURITY_POLICY
    assert response.headers["x-content-type-options"] == "nosniff"
    assert response.headers["x-frame-options"] == "DENY"
    assert response.headers["cache-control"] == "no-store"


def test_security_headers_on_every_kind_of_api_error(make_client):
    anonymous = make_client()
    contractor = _signed_in(make_client, CONTRACTOR)
    responses = {
        401: anonymous.get("/api/events"),
        403: contractor.post("/api/alerts/1/ack"),
        404: contractor.get("/api/events/999999999"),
        422: contractor.post("/api/access/preview", json={"event_id": "abc"}),
    }
    email = f"nobody-{time.time_ns()}@example.test"
    for _ in range(config.MAX_LOGIN_FAILURES):
        assert anonymous.post("/api/auth/login", json={"email": email, "password": "wrong"}).status_code == 401
    responses[429] = anonymous.post("/api/auth/login", json={"email": email, "password": "wrong"})
    for status, response in responses.items():
        assert response.status_code == status, (status, response.text)
        _assert_headers(response)


def test_contractor_end_to_end_stays_inside_its_own_scope(make_client):
    contractor = _user(CONTRACTOR[0])
    browser = _signed_in(make_client, CONTRACTOR)
    inventory = browser.get("/api/context/inventory").json()
    assert inventory["scope"] == "self" and [u["id"] for u in inventory["users"]] == [contractor["id"]]
    device = next(d for d in inventory["users"][0]["devices"] if d["name"] == "CONTRACTOR-LT-12")
    wiki = next(r for r in inventory["resources"] if r["name"] == "internal-wiki")
    result = browser.post("/api/access/evaluate", json={"device_id": device["id"], "resource_id": wiki["id"],
                                                        "context": CONTEXT}).json()
    if result["decision"] == "CHALLENGE":
        assert result["challenge"]["mode"] == "live"
        verified = browser.post("/api/access/challenge", json={
            "challenge_id": result["challenge"]["id"], "code": security.totp_code(contractor["mfa_secret"])})
        assert verified.status_code == 200 and verified.json()["step_up_mode"] == "live"
        result = verified.json()
    # Another identity cannot be evaluated, simulated or inspected.
    finance = _user(FINANCE[0])
    assert browser.post("/api/access/evaluate", json={"user_id": finance["id"], "device_id": device["id"],
                                                      "resource_id": wiki["id"]}).status_code == 403
    assert browser.post("/api/sim/scenario", json={"scenario_id": "impossible_travel"}).status_code == 403
    events = browser.get("/api/events?limit=500").json()["events"]
    assert {e["user_id"] for e in events} == {contractor["id"]}
    assert result["event_id"] in {e["id"] for e in events}


def test_operator_simulation_end_to_end_is_attributed_and_isolated(make_client):
    finance = _user(FINANCE[0])
    analyst = _user(ANALYST[0])
    operator = _signed_in(make_client, ANALYST)
    with database.get_db() as conn:
        device = database.row(conn, "SELECT id FROM devices WHERE user_id = ? AND name = 'PRIYA-LT-03'", (finance["id"],))
        resource = database.row(conn, "SELECT id FROM resources WHERE name = 'finance-db'")
    body = {"user_id": finance["id"], "device_id": device["id"], "resource_id": resource["id"], "context": CONTEXT}
    simulated = operator.post("/api/access/evaluate", json=body).json()
    token = simulated["challenge"]["id"]
    assert operator.post("/api/access/challenge",
                         json={"challenge_id": token, "simulated_outcome": "failure"}).status_code == 400
    assert operator.post("/api/access/challenge",
                         json={"challenge_id": token, "simulated_outcome": "success"}).status_code == 200

    # Finance sees the simulation in her own log, labelled and attributed.
    owner = _signed_in(make_client, FINANCE)
    event = owner.get(f"/api/events/{simulated['event_id']}").json()
    assert event["simulated"] is True and event["actor_user_id"] == analyst["id"]
    assert event["outcome"] == "step_up_simulated"
    with database.get_db() as conn:
        audit = database.rows(conn, "SELECT actor_user_id, success, mode FROM mfa_attempts WHERE user_id = ?",
                              (finance["id"],))
    assert audit == [{"actor_user_id": analyst["id"], "success": 0, "mode": "simulation"},
                     {"actor_user_id": analyst["id"], "success": 1, "mode": "simulation"}]

    # Her real MFA: replay protection and challenge ownership still apply.
    real = owner.post("/api/access/evaluate", json={k: v for k, v in body.items() if k != "user_id"}).json()
    code = security.totp_code(finance["mfa_secret"])
    stranger = _signed_in(make_client, FINANCE)  # same password, another session
    assert stranger.post("/api/access/challenge",
                         json={"challenge_id": real["challenge"]["id"], "code": code}).status_code == 400
    assert owner.post("/api/access/challenge",
                      json={"challenge_id": real["challenge"]["id"], "code": code}).status_code == 200
    again = owner.post("/api/access/evaluate", json={k: v for k, v in body.items() if k != "user_id"}).json()
    replay = owner.post("/api/access/challenge", json={"challenge_id": again["challenge"]["id"], "code": code})
    assert replay.status_code == 400 and "Incorrect verification code" in replay.json()["detail"]


def test_logout_stops_a_pending_persisted_challenge(make_client):
    finance = _user(FINANCE[0])
    owner = _signed_in(make_client, FINANCE)
    with database.get_db() as conn:
        device = database.row(conn, "SELECT id FROM devices WHERE user_id = ? AND name = 'PRIYA-LT-03'", (finance["id"],))
        resource = database.row(conn, "SELECT id FROM resources WHERE name = 'finance-db'")
    token = owner.post("/api/access/evaluate", json={"device_id": device["id"], "resource_id": resource["id"],
                                                     "context": CONTEXT}).json()["challenge"]["id"]
    session_cookie = owner.cookies[config.SESSION_COOKIE]
    assert owner.post("/api/auth/logout").status_code == 200
    stale = make_client()
    response = stale.post("/api/access/challenge", json={"challenge_id": token,
                                                         "code": security.totp_code(finance["mfa_secret"])},
                          headers={"Authorization": f"Bearer {session_cookie}"})
    assert response.status_code == 401
    assert risk.challenge_state(token)["status"] == "pending"
    assert database.last_totp_counter(finance["id"]) is None


def test_stored_challenge_rows_hold_no_codes_or_secrets():
    with database.get_db() as conn:
        columns = [row["name"] for row in conn.execute("PRAGMA table_info(mfa_challenges)")]
    assert columns == ["token_hash", "event_id", "user_id", "device_id", "resource_id", "actor_user_id",
                       "session_hash", "mode", "created_at", "expires_at", "failed_attempts", "status",
                       "consumed_at"]
