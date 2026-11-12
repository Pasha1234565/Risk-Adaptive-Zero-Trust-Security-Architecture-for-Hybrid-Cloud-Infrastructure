"""Authenticated identity in access evaluation (Phase 2.1, issue 4).

Before the fix ``POST /api/access/evaluate`` evaluated whatever ``user_id`` the
client sent, so any signed-in user could submit requests as any identity, and
the simulation endpoints needed only authentication.

Documented policy:
* the actor is always the signed-in user (from the session);
* every user may evaluate their own identity, with their own devices;
* evaluating another identity, and running scenario / normal-traffic /
  evaluation simulations, requires ``security_admin`` or ``analyst``;
* every persisted event records the actor in ``events.actor_user_id``,
  separately from the evaluated subject (``events.user_id``).
"""

from __future__ import annotations

import pytest

from app import config, database, simulator
from conftest import ADMIN, ANALYST, login

FINANCE = ("finance@hybridcloud.io", "Finance#2026")
DEV = ("dev@hybridcloud.io", "Dev#2026")
CONTRACTOR = ("contractor@hybridcloud.io", "Guest#2026")
SERVICE = ("svc-backup@hybridcloud.io", "Service#2026")
CONTEXT = {"hour": 13, "failed_attempts_24h": 0, "mfa_verified": True}


def _user(email: str) -> dict:
    with database.get_db() as conn:
        return database.row(conn, "SELECT id, role FROM users WHERE email = ?", (email,))


def _device(email: str, name: str | None = None) -> int:
    with database.get_db() as conn:
        user = database.row(conn, "SELECT id FROM users WHERE email = ?", (email,))
        sql = "SELECT id FROM devices WHERE user_id = ?" + (" AND name = ?" if name else "") + " ORDER BY id"
        return database.row(conn, sql, (user["id"], name) if name else (user["id"],))["id"]


def _resource(name: str = "internal-wiki") -> int:
    with database.get_db() as conn:
        return database.row(conn, "SELECT id FROM resources WHERE name = ?", (name,))["id"]


def _event_count() -> int:
    with database.get_db() as conn:
        return conn.execute("SELECT COUNT(*) FROM events").fetchone()[0]


def _event(event_id: int) -> dict:
    with database.get_db() as conn:
        return database.row(conn, "SELECT user_id, device_id, actor_user_id FROM events WHERE id = ?", (event_id,))


def _signed_in(make_client, credentials):
    browser = make_client()
    assert login(browser, *credentials).status_code == 200
    return browser


def _evaluate(browser, **body):
    body.setdefault("resource_id", _resource())
    body.setdefault("context", CONTEXT)
    return browser.post("/api/access/evaluate", json=body)


# ---------------------------------------------------------------------------
# Ordinary users
# ---------------------------------------------------------------------------


def test_policy_roles_are_documented_in_config():
    assert config.SIMULATION_ROLES == frozenset({"security_admin", "analyst"})


def test_user_evaluates_own_identity_without_sending_a_user_id(make_client):
    finance = _user(FINANCE[0])
    browser = _signed_in(make_client, FINANCE)

    response = _evaluate(browser, device_id=_device(FINANCE[0]))

    assert response.status_code == 200, response.text
    body = response.json()
    assert body["user"]["id"] == finance["id"]
    assert body["simulated"] is False
    assert body["actor"]["id"] == finance["id"]
    assert _event(body["event_id"]) == {
        "user_id": finance["id"], "device_id": _device(FINANCE[0]), "actor_user_id": finance["id"],
    }


def test_user_may_name_themselves_explicitly(make_client):
    finance = _user(FINANCE[0])
    response = _evaluate(_signed_in(make_client, FINANCE), user_id=finance["id"], device_id=_device(FINANCE[0]))
    assert response.status_code == 200
    assert response.json()["simulated"] is False


@pytest.mark.parametrize("credentials", [FINANCE, DEV, CONTRACTOR, SERVICE])
def test_ordinary_user_cannot_submit_another_users_id(make_client, credentials):
    victim = _user(ANALYST[0])
    browser = _signed_in(make_client, credentials)
    before = _event_count()

    response = _evaluate(browser, user_id=victim["id"], device_id=_device(ANALYST[0], "AISHA-LT-02"))

    assert response.status_code == 403
    assert "security administrator or SOC analyst" in response.json()["detail"]
    assert _event_count() == before


@pytest.mark.parametrize("forged", [0, -1, 999999])
def test_ordinary_user_cannot_use_forged_ids(make_client, forged):
    before = _event_count()
    response = _evaluate(_signed_in(make_client, FINANCE), user_id=forged, device_id=_device(FINANCE[0]))
    assert response.status_code == 403
    assert _event_count() == before


@pytest.mark.parametrize("value", ["2", "abc", 1.5, [1], {"id": 1}])
def test_malformed_user_id_is_rejected_by_validation(make_client, value):
    response = _evaluate(_signed_in(make_client, FINANCE), user_id=value, device_id=_device(FINANCE[0]))
    if value == "2":
        # Pydantic coerces numeric strings; it is then just another identity.
        assert response.status_code == 403
    else:
        assert response.status_code == 422


def test_user_cannot_use_another_users_device(make_client):
    before = _event_count()
    response = _evaluate(_signed_in(make_client, FINANCE), device_id=_device(ANALYST[0], "AISHA-LT-02"))

    assert response.status_code == 400
    assert response.json()["detail"] == "Device does not belong to the selected user"
    assert _event_count() == before


def test_unauthenticated_evaluation_is_rejected(make_client):
    response = _evaluate(make_client(), device_id=_device(FINANCE[0]))
    assert response.status_code == 401


# ---------------------------------------------------------------------------
# Privileged simulation
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("credentials", [ADMIN, ANALYST])
def test_simulation_roles_can_evaluate_another_identity(make_client, credentials):
    operator, subject = _user(credentials[0]), _user(FINANCE[0])
    browser = _signed_in(make_client, credentials)

    response = _evaluate(browser, user_id=subject["id"], device_id=_device(FINANCE[0]))

    assert response.status_code == 200, response.text
    body = response.json()
    assert body["simulated"] is True
    assert body["user"]["id"] == subject["id"]
    assert body["actor"]["id"] == operator["id"]
    assert _event(body["event_id"])["actor_user_id"] == operator["id"]
    assert _event(body["event_id"])["user_id"] == subject["id"]


def test_simulation_still_requires_the_subjects_own_device(make_client):
    response = _evaluate(
        _signed_in(make_client, ADMIN), user_id=_user(FINANCE[0])["id"], device_id=_device(ANALYST[0], "AISHA-LT-02")
    )
    assert response.status_code == 400


def test_simulation_of_unknown_identity_is_rejected(make_client):
    response = _evaluate(_signed_in(make_client, ADMIN), user_id=999999, device_id=_device(FINANCE[0]))
    assert response.status_code == 400
    assert response.json()["detail"] == "Unknown user, device or resource"


@pytest.mark.parametrize(
    "path, body",
    [
        ("/api/sim/scenario", {"scenario_id": "impossible_travel", "variants": 1}),
        ("/api/sim/normal", {"count": 1}),
        ("/api/sim/evaluation", {"name": "unauthorised", "normal_samples": 20, "variants": 1}),
    ],
)
@pytest.mark.parametrize("credentials", [FINANCE, DEV, CONTRACTOR])
def test_ordinary_users_cannot_run_simulations(make_client, credentials, path, body):
    before = _event_count()
    response = _signed_in(make_client, credentials).post(path, json=body)
    assert response.status_code == 403
    assert _event_count() == before


def test_anyone_signed_in_can_list_scenarios(make_client):
    response = _signed_in(make_client, CONTRACTOR).get("/api/sim/scenarios")
    assert response.status_code == 200
    assert len(response.json()["scenarios"]) == 12


def test_all_twelve_attack_scenarios_still_run_for_an_operator(make_client):
    admin = _user(ADMIN[0])
    browser = _signed_in(make_client, ADMIN)

    for scenario in simulator.SCENARIOS:
        response = browser.post("/api/sim/scenario", json={"scenario_id": scenario["id"], "variants": 1})
        assert response.status_code == 200, (scenario["id"], response.text)
        result = response.json()["results"][0]
        assert result["decision"] != "ALLOW", scenario["id"]
        event = _event(result["event_id"])
        assert event["actor_user_id"] == admin["id"]
        assert event["user_id"] != admin["id"] or scenario["user_email"] == ADMIN[0]


def test_operator_normal_traffic_and_evaluation(make_client):
    analyst = _user(ANALYST[0])
    browser = _signed_in(make_client, ANALYST)

    normal = browser.post("/api/sim/normal", json={"count": 3})
    run = browser.post("/api/sim/evaluation", json={"name": "operator run", "normal_samples": 20, "variants": 1})

    assert normal.status_code == 200
    assert all(_event(r["event_id"])["actor_user_id"] == analyst["id"] for r in normal.json()["results"])
    assert run.status_code == 200
    assert run.json()["samples"]["attack"] == 12


# ---------------------------------------------------------------------------
# Audit attribution
# ---------------------------------------------------------------------------


def test_event_apis_expose_actor_separately_from_subject(make_client):
    admin, subject = _user(ADMIN[0]), _user(FINANCE[0])
    browser = _signed_in(make_client, ADMIN)
    event_id = _evaluate(browser, user_id=subject["id"], device_id=_device(FINANCE[0])).json()["event_id"]

    detail = browser.get(f"/api/events/{event_id}").json()
    listed = next(e for e in browser.get("/api/events", params={"limit": 50}).json()["events"] if e["id"] == event_id)

    for item in (detail, listed):
        assert item["user_id"] == subject["id"]
        assert item["actor_user_id"] == admin["id"]
        assert item["actor_email"] == ADMIN[0]
        assert item["user_email"] == FINANCE[0]


def test_system_generated_events_have_no_actor():
    result = simulator.run_normal(1, persist=True, seed=5)[0]
    assert _event(result["event_id"])["actor_user_id"] is None


# ---------------------------------------------------------------------------
# Console reflects the server rule
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("credentials, expected", [(ADMIN, "yes"), (ANALYST, "yes"), (FINANCE, "no"), (CONTRACTOR, "no")])
def test_console_flags_follow_the_role(make_client, credentials, expected):
    browser = _signed_in(make_client, credentials)
    access = browser.get("/access").text
    simulation = browser.get("/simulation").text

    assert f'data-can-simulate="{expected}"' in access
    assert f'data-user-id="{_user(credentials[0])["id"]}"' in access
    assert ('id="simulation-restricted"' in simulation) is (expected == "no")
