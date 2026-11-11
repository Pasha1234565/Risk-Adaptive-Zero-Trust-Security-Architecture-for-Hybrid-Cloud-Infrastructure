"""Role-based visibility of identities, devices, events and alerts (Phase 2.2, Task B).

Before this change every signed-in user, including a contractor, received all
identities (with e-mail addresses) and all devices from
/api/context/inventory, every other user's access decisions (device names,
trust scores, source IPs) from /api/events and /api/events/{id}, the global
alert queue, and could acknowledge alerts.

Matrix enforced on the server:

=================  ==========================  =======================  ==========
role               identities and devices      resources                events/alerts
=================  ==========================  =======================  ==========
security_admin     all (scope "full")          all                      all, triage
analyst            all (scope "soc")           all                      all, triage
developer,         own only (scope "self")     permitted by policy      own only
finance,
contractor
service            own only (scope "self")     permitted by policy      own only
                                               (smallest set)
=================  ==========================  =======================  ==========
"""

from __future__ import annotations

import pytest

from app import database
from conftest import ADMIN, ANALYST, login

DEV = ("dev@hybridcloud.io", "Dev#2026")
FINANCE = ("finance@hybridcloud.io", "Finance#2026")
CONTRACTOR = ("contractor@hybridcloud.io", "Guest#2026")
SERVICE = ("svc-backup@hybridcloud.io", "Service#2026")

UNRESTRICTED = {"hr-portal", "public-web", "internal-wiki"}  # web + collaboration
EXPECTED_RESOURCES = {
    CONTRACTOR: UNRESTRICTED,
    SERVICE: UNRESTRICTED,
    FINANCE: UNRESTRICTED | {"finance-db", "analytics-lake", "backup-vault", "api-gateway"},
    DEV: UNRESTRICTED | {"k8s-prod", "analytics-lake", "backup-vault", "vpn-gateway", "dev-vm-01",
                         "ml-training", "api-gateway"},
}
USER_FIELDS = {"id", "name", "email", "role", "department", "status", "mfa_enabled", "devices"}
DEVICE_FIELDS = {"id", "user_id", "name", "kind", "os", "managed", "compliant", "trust_score"}
FORBIDDEN_TEXT = ("password_hash", "pbkdf2_sha256", "mfa_secret", "enc:v1:", "fingerprint", "fp-", "jti")
CONTEXT = {"geo": "Bengaluru, IN", "hour": 13, "requests_last_5m": 4, "failed_attempts_24h": 0,
           "bytes_out_mb": 15, "session_minutes": 25, "concurrent_sessions": 1,
           "new_device": False, "mfa_verified": True, "threat_intel": "clean"}


def _signed_in(make_client, credentials):
    browser = make_client()
    assert login(browser, *credentials).status_code == 200
    return browser


def _user(email: str) -> dict:
    with database.get_db() as conn:
        return database.row(conn, "SELECT id, name, email FROM users WHERE email = ?", (email,))


def _all_emails() -> set[str]:
    with database.get_db() as conn:
        return {r["email"] for r in database.rows(conn, "SELECT email FROM users")}


def _foreign_device_names(user_id: int) -> set[str]:
    with database.get_db() as conn:
        return {r["name"] for r in database.rows(conn, "SELECT name FROM devices WHERE user_id != ?", (user_id,))}


def _finance_event(admin, *, threat: str = "clean") -> int:
    finance = _user(FINANCE[0])
    with database.get_db() as conn:
        device = database.row(conn, "SELECT id FROM devices WHERE user_id = ?", (finance["id"],))
        resource = database.row(conn, "SELECT id FROM resources WHERE name = 'internal-wiki'")
    response = admin.post("/api/access/evaluate", json={
        "user_id": finance["id"], "device_id": device["id"], "resource_id": resource["id"],
        "context": dict(CONTEXT, threat_intel=threat)})
    assert response.status_code == 200, response.text
    return response.json()["event_id"]


# ---------------------------------------------------------------------------
# /api/context/inventory
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("credentials,scope", [(ADMIN, "full"), (ANALYST, "soc")])
def test_soc_roles_see_the_whole_inventory(make_client, credentials, scope):
    body = _signed_in(make_client, credentials).get("/api/context/inventory").json()
    assert body["scope"] == scope
    assert len(body["users"]) == 6
    assert sum(len(u["devices"]) for u in body["users"]) == 10
    assert len(body["resources"]) == 12


@pytest.mark.parametrize("credentials", [DEV, FINANCE, CONTRACTOR, SERVICE])
def test_other_roles_see_only_themselves_and_policy_permitted_resources(make_client, credentials):
    me = _user(credentials[0])
    response = _signed_in(make_client, credentials).get("/api/context/inventory")
    assert response.status_code == 200
    body = response.json()
    assert body["scope"] == "self"
    assert [u["id"] for u in body["users"]] == [me["id"]]
    assert all(d["user_id"] == me["id"] for d in body["users"][0]["devices"])
    assert {r["name"] for r in body["resources"]} == EXPECTED_RESOURCES[credentials]
    # No other identity's e-mail address or device name appears anywhere.
    for email in _all_emails() - {me["email"]}:
        assert email not in response.text
    for device in _foreign_device_names(me["id"]):
        assert device not in response.text


def test_contractor_cannot_see_other_users_devices(make_client):
    contractor = _user(CONTRACTOR[0])
    body = _signed_in(make_client, CONTRACTOR).get("/api/context/inventory").json()
    devices = body["users"][0]["devices"]
    assert {d["name"] for d in devices} == {"CONTRACTOR-LT-11", "CONTRACTOR-LT-12"}
    assert {d["user_id"] for d in devices} == {contractor["id"]}


@pytest.mark.parametrize("credentials", [ADMIN, ANALYST, DEV, CONTRACTOR, SERVICE])
def test_inventory_never_contains_credentials_or_fingerprints(make_client, credentials):
    response = _signed_in(make_client, credentials).get("/api/context/inventory")
    for marker in FORBIDDEN_TEXT:
        assert marker not in response.text, marker
    for user in response.json()["users"]:
        assert set(user) <= USER_FIELDS
        for device in user["devices"]:
            assert set(device) <= DEVICE_FIELDS


def test_resource_visibility_follows_the_policy_table(make_client):
    admin = _signed_in(make_client, ADMIN)
    contractor = _signed_in(make_client, CONTRACTOR)
    with database.get_db() as conn:
        policy = database.row(conn, "SELECT id FROM policies WHERE name = 'Critical finance data'")
    names = lambda: {r["name"] for r in contractor.get("/api/context/inventory").json()["resources"]}  # noqa: E731
    assert "finance-db" not in names()
    assert admin.post(f"/api/admin/policies/{policy['id']}/toggle").json()["enabled"] is False
    try:
        # With the role restriction disabled the database is no longer role-limited.
        assert "finance-db" in names()
    finally:
        assert admin.post(f"/api/admin/policies/{policy['id']}/toggle").json()["enabled"] is True
    assert "finance-db" not in names()


# ---------------------------------------------------------------------------
# Events, alerts and the dashboard
# ---------------------------------------------------------------------------


def test_events_are_limited_to_the_callers_identity(make_client):
    admin = _signed_in(make_client, ADMIN)
    finance_event = _finance_event(admin)
    contractor = _user(CONTRACTOR[0])
    browser = _signed_in(make_client, CONTRACTOR)
    with database.get_db() as conn:
        device = database.row(conn, "SELECT id FROM devices WHERE user_id = ? AND name = 'CONTRACTOR-LT-12'",
                              (contractor["id"],))
        wiki = database.row(conn, "SELECT id FROM resources WHERE name = 'internal-wiki'")
        own_total = conn.execute("SELECT COUNT(*) FROM events WHERE user_id = ?", (contractor["id"],)).fetchone()[0]
    mine = browser.post("/api/access/evaluate", json={"device_id": device["id"], "resource_id": wiki["id"],
                                                         "context": CONTEXT}).json()["event_id"]

    response = browser.get("/api/events?limit=500")
    body = response.json()
    assert body["total"] == own_total + 1
    assert {e["user_id"] for e in body["events"]} == {contractor["id"]}
    for device_name in _foreign_device_names(contractor["id"]):
        assert device_name not in response.text
    finance = _user(FINANCE[0])
    assert browser.get(f"/api/events?user_id={finance['id']}").json()["total"] == 0
    # Another identity's event looks exactly like a missing one.
    assert browser.get(f"/api/events/{finance_event}").status_code == 404
    assert browser.get("/api/events/999999").json() == browser.get(f"/api/events/{finance_event}").json()
    assert browser.get(f"/api/events/{mine}").status_code == 200
    # SOC roles keep the full view.
    analyst = _signed_in(make_client, ANALYST)
    assert analyst.get(f"/api/events/{finance_event}").status_code == 200
    assert analyst.get("/api/events?limit=1").json()["total"] > body["total"]
    # The PEP still refuses another identity's decision.
    assert browser.post("/api/access/preview", json={"event_id": finance_event}).status_code == 403


def test_alerts_are_scoped_and_only_soc_roles_can_triage(make_client):
    admin = _signed_in(make_client, ADMIN)
    _finance_event(admin, threat="malicious")  # BLOCK raises an alert for finance
    finance = _user(FINANCE[0])
    with database.get_db() as conn:
        alert_id = conn.execute(
            "SELECT a.id FROM alerts a JOIN events e ON e.id = a.event_id WHERE e.user_id = ? "
            "AND a.status = 'open' ORDER BY a.id DESC LIMIT 1", (finance["id"],)).fetchone()[0]

    contractor = _signed_in(make_client, CONTRACTOR)
    body = contractor.get("/api/alerts?status=all&limit=500").json()
    assert body["scope"] == "self"
    assert all(a["user_id"] == _user(CONTRACTOR[0])["id"] for a in body["alerts"])
    assert alert_id not in {a["id"] for a in body["alerts"]}
    assert contractor.post(f"/api/alerts/{alert_id}/ack").status_code == 403

    finance_view = _signed_in(make_client, FINANCE).get("/api/alerts?status=open&limit=500").json()
    assert alert_id in {a["id"] for a in finance_view["alerts"]}
    assert _signed_in(make_client, FINANCE).post(f"/api/alerts/{alert_id}/ack").status_code == 403

    analyst = _signed_in(make_client, ANALYST)
    assert alert_id in {a["id"] for a in analyst.get("/api/alerts?status=open&limit=500").json()["alerts"]}
    assert analyst.post(f"/api/alerts/{alert_id}/ack").status_code == 200
    with database.get_db() as conn:
        assert conn.execute("SELECT status FROM alerts WHERE id = ?", (alert_id,)).fetchone()[0] == "acknowledged"


def test_dashboard_is_scoped_for_non_soc_roles(make_client):
    admin = _signed_in(make_client, ADMIN)
    _finance_event(admin, threat="malicious")
    contractor = _user(CONTRACTOR[0])
    with database.get_db() as conn:
        own_total = conn.execute("SELECT COUNT(*) FROM events WHERE user_id = ?", (contractor["id"],)).fetchone()[0]
        all_total = conn.execute("SELECT COUNT(*) FROM events").fetchone()[0]
    response = _signed_in(make_client, CONTRACTOR).get("/api/dashboard")
    body = response.json()
    assert body["scope"] == "self"
    assert body["stats"]["events_total"] == own_total
    assert all(item["user_name"] == contractor["name"] for item in body["recent"])
    for device_name in _foreign_device_names(contractor["id"]):
        assert device_name not in response.text
    assert "Priya Nair" not in response.text  # finance's open alert title is not shown
    soc = _signed_in(make_client, ANALYST).get("/api/dashboard").json()
    assert soc["scope"] == "all" and soc["stats"]["events_total"] == all_total


def test_pages_explain_the_scope_and_admin_apis_stay_admin_only(make_client):
    contractor = _signed_in(make_client, CONTRACTOR)
    analyst = _signed_in(make_client, ANALYST)
    for page in ("/", "/monitoring"):
        assert 'id="scope-note"' in contractor.get(page).text
        assert 'id="scope-note"' not in analyst.get(page).text
    for browser in (contractor, analyst):
        assert browser.get("/api/admin/inventory").status_code == 403
    assert _signed_in(make_client, ADMIN).get("/api/admin/inventory").status_code == 200


def test_unauthenticated_requests_are_rejected(make_client):
    anonymous = make_client()
    for path in ("/api/context/inventory", "/api/events", "/api/events/1", "/api/alerts", "/api/dashboard"):
        assert anonymous.get(path).status_code == 401, path
    assert anonymous.post("/api/alerts/1/ack").status_code == 401
