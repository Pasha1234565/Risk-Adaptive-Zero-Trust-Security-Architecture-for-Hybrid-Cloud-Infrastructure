"""Malformed API input (Phase 2.2, Task E).

Before this change POST /api/access/preview with {"event_id": "abc"} or
{"event_id": null}, and POST /api/admin/model/train with {"samples": "abc"}
or {"contamination": "x"}, raised inside the handler and returned HTTP 500.
Out-of-range ids reached SQLite and raised OverflowError (500), the access
context was an unchecked dict, and 422 bodies echoed the rejected input.

Now every endpoint validates ids, ranges, enums, JSON syntax and field types
(422, or 400/401/403/404 where those apply), 422 bodies carry a readable
``detail`` plus ``errors`` without the rejected input, and any unexpected
exception returns a generic 500 with the security headers while the
traceback goes only to the server log.
"""

from __future__ import annotations

import json
import logging

import pytest
from fastapi.routing import APIRoute

from app import database
from app import main as app_main
from app.main import app
from conftest import ADMIN, login

FINANCE = ("finance@hybridcloud.io", "Finance#2026")
HUGE = 2**70
LEAK_MARKERS = ("Traceback", 'File "', "sqlite3", "SELECT ", "INSERT ", "OverflowError", "pbkdf2_sha256",
                "enc:v1:", "zt-marker")
CLEAN = {"geo": "Bengaluru, IN", "hour": 13, "requests_last_5m": 4, "failed_attempts_24h": 0,
         "bytes_out_mb": 15, "session_minutes": 25, "concurrent_sessions": 1,
         "new_device": False, "mfa_verified": True, "threat_intel": "clean"}


def _client(make_client, credentials=None):
    browser = make_client(raise_server_exceptions=False)
    if credentials:
        assert login(browser, *credentials).status_code == 200
    return browser


def _finance_ids() -> tuple[int, int]:
    with database.get_db() as conn:
        user = database.row(conn, "SELECT id FROM users WHERE email = ?", (FINANCE[0],))
        device = database.row(conn, "SELECT id FROM devices WHERE user_id = ? AND name = 'PRIYA-LT-03'", (user["id"],))
        resource = database.row(conn, "SELECT id FROM resources WHERE name = 'internal-wiki'")
    return device["id"], resource["id"]


def _assert_clean_422(response) -> None:
    assert response.status_code == 422, response.text
    body = response.json()
    assert isinstance(body["detail"], str) and body["detail"].startswith("Invalid request")
    for error in body.get("errors", []):
        assert set(error) == {"loc", "msg", "type"}
    for marker in LEAK_MARKERS:
        assert marker not in response.text, marker


# ---------------------------------------------------------------------------
# The reproduced 500s
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("path,payload", [
    ("/api/access/preview", {"event_id": "abc"}),
    ("/api/access/preview", {"event_id": None}),
    ("/api/access/preview", {}),
    ("/api/access/preview", {"event_id": 0}),
    ("/api/access/preview", {"event_id": -1}),
    ("/api/access/preview", {"event_id": 1.5}),
    ("/api/access/preview", {"event_id": HUGE}),
    ("/api/admin/model/train", {"samples": "abc"}),
    ("/api/admin/model/train", {"contamination": "x"}),
    ("/api/admin/model/train", {"samples": 100}),
    ("/api/admin/model/train", {"samples": 6000}),
    ("/api/admin/model/train", {"contamination": 0.5}),
    ("/api/admin/model/train", {"samples": [1200]}),
])
def test_previously_crashing_bodies_are_rejected_with_422(make_client, path, payload):
    _assert_clean_422(_client(make_client, ADMIN).post(path, json=payload))


def test_preview_still_works_and_missing_events_are_404(make_client):
    browser = _client(make_client, FINANCE)
    device_id, resource_id = _finance_ids()
    event = browser.post("/api/access/evaluate", json={"device_id": device_id, "resource_id": resource_id,
                                                       "context": CLEAN}).json()
    assert event["decision"] in ("ALLOW", "RESTRICT")
    assert browser.post("/api/access/preview", json={"event_id": event["event_id"]}).status_code == 200
    missing = browser.post("/api/access/preview", json={"event_id": 10**12})
    assert missing.status_code == 404 and missing.json() == {"detail": "Access decision not found"}


# ---------------------------------------------------------------------------
# Ids, ranges and enums in paths and query strings
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("method,path", [
    ("get", "/api/events/{}"),
    ("post", "/api/alerts/{}/ack"),
    ("get", "/api/evaluation/runs/{}"),
    ("post", "/api/admin/policies/{}/toggle"),
])
@pytest.mark.parametrize("value", ["abc", "0", "-1", str(HUGE), "1.5", "1e3"])
def test_path_ids_are_validated(make_client, method, path, value):
    _assert_clean_422(getattr(_client(make_client, ADMIN), method)(path.format(value)))


@pytest.mark.parametrize("query", [
    "decision=FOO", "decision=ALLOW,DROP", "decision=,", "truth=maybe", "user_id=abc", "user_id=0",
    f"offset={HUGE}", "offset=-1", "limit=0", "limit=10000", "scenario=" + "x" * 65,
])
def test_event_filters_are_validated(make_client, query):
    _assert_clean_422(_client(make_client, ADMIN).get(f"/api/events?{query}"))


@pytest.mark.parametrize("query", ["status=maybe", "limit=0", "limit=abc", "limit=100000"])
def test_alert_filters_are_validated(make_client, query):
    _assert_clean_422(_client(make_client, ADMIN).get(f"/api/alerts?{query}"))


def test_valid_filters_still_work(make_client):
    browser = _client(make_client, ADMIN)
    assert browser.get("/api/events?decision=ALLOW,block&truth=attack&limit=5&offset=0").status_code == 200
    assert browser.get("/api/events?decision=ALL").status_code == 200
    for status in ("open", "acknowledged", "all"):
        assert browser.get(f"/api/alerts?status={status}&limit=10").status_code == 200


# ---------------------------------------------------------------------------
# Request bodies
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("context", [
    {"geo": "Atlantis"}, {"hour": 24}, {"hour": -1}, {"hour": "noon"}, {"hour": 13.5},
    {"requests_last_5m": -1}, {"bytes_out_mb": 1e12}, {"concurrent_sessions": "many"},
    {"threat_intel": "evil"}, {"new_device": "sometimes"}, {"source_ip": "not-an-ip"},
    {"note": "x" * 501}, {"unexpected": 1}, "not-an-object", [1, 2],
])
def test_access_context_is_validated(make_client, context):
    device_id, resource_id = _finance_ids()
    with database.get_db() as conn:
        before = conn.execute("SELECT COUNT(*) FROM events").fetchone()[0]
    response = _client(make_client, FINANCE).post(
        "/api/access/evaluate", json={"device_id": device_id, "resource_id": resource_id, "context": context})
    _assert_clean_422(response)
    with database.get_db() as conn:
        assert conn.execute("SELECT COUNT(*) FROM events").fetchone()[0] == before  # nothing recorded


@pytest.mark.parametrize("raw", [
    b'{"device_id": 1, "resource_id": 1, "context": {"bytes_out_mb": NaN}}',
    b'{"device_id": 1, "resource_id": 1, "context": {"session_minutes": Infinity}}',
    b'{"device_id": 1, "resource_id": 1',
    b"not json at all",
    b"",
    b"[]",
    b'"device_id"',
])
def test_malformed_json_is_rejected(make_client, raw):
    response = _client(make_client, FINANCE).post(
        "/api/access/evaluate", content=raw, headers={"content-type": "application/json"})
    _assert_clean_422(response)


@pytest.mark.parametrize("field", ["user_id", "device_id", "resource_id"])
def test_out_of_range_ids_in_the_body_are_rejected(make_client, field):
    device_id, resource_id = _finance_ids()
    body = {"device_id": device_id, "resource_id": resource_id, "context": CLEAN, field: HUGE}
    _assert_clean_422(_client(make_client, ADMIN).post("/api/access/evaluate", json=body))


def test_the_full_console_context_is_still_accepted(make_client):
    device_id, resource_id = _finance_ids()
    context = dict(CLEAN, source_ip="203.0.113.7", note="manual test", geo="London, UK")
    response = _client(make_client, FINANCE).post(
        "/api/access/evaluate", json={"device_id": device_id, "resource_id": resource_id, "context": context})
    assert response.status_code == 200, response.text
    assert response.json()["context"]["source_ip"] == "203.0.113.7"


def test_rejected_input_is_not_reflected(make_client):
    marker = "<script>zt-marker</script>"
    device_id, resource_id = _finance_ids()
    browser = _client(make_client, FINANCE)
    responses = [
        browser.post("/api/access/evaluate", json={"device_id": marker, "resource_id": resource_id}),
        browser.post("/api/access/evaluate", json={"device_id": device_id, "resource_id": resource_id,
                                                   "context": {"geo": marker, marker: 1}}),
        browser.post("/api/access/challenge", json={"challenge_id": marker, "simulated_outcome": marker}),
        browser.get(f"/api/events?decision={marker}"),
        _client(make_client, ADMIN).post("/api/sim/scenario", json={"scenario_id": marker}),
    ]
    for response in responses:
        _assert_clean_422(response)
        assert "<script>" not in response.text


@pytest.mark.parametrize("path,payload", [
    ("/api/auth/login", {"email": 5, "password": "x"}),
    ("/api/auth/login", {"email": "a@b.c"}),
    ("/api/admin/settings", {"thresholds": {"allow_max": "x"}}),
    ("/api/admin/settings", {"thresholds": {"unknown": 10}}),
    ("/api/admin/settings", {"thresholds": [40, 60, 80]}),
    ("/api/sim/scenario", {"scenario_id": "no-such-scenario"}),
    ("/api/sim/scenario", {"scenario_id": "impossible_travel", "variants": 9}),
    ("/api/sim/normal", {"count": "x"}),
    ("/api/sim/evaluation", {"normal_samples": 5}),
])
def test_other_bodies_are_validated(make_client, path, payload):
    browser = _client(make_client, ADMIN)
    method = browser.put if path == "/api/admin/settings" else browser.post
    _assert_clean_422(method(path, json=payload))


def test_settings_reject_non_finite_thresholds(make_client):
    response = _client(make_client, ADMIN).put(
        "/api/admin/settings", content=b'{"thresholds": {"allow_max": NaN}}',
        headers={"content-type": "application/json"})
    _assert_clean_422(response)


def test_errors_do_not_replace_authentication(make_client):
    anonymous = _client(make_client)
    assert anonymous.post("/api/access/preview", json={"event_id": 1}).status_code == 401
    assert anonymous.post("/api/admin/model/train", json={"samples": 1200}).status_code == 401
    assert anonymous.get("/api/events/1").status_code == 401


# ---------------------------------------------------------------------------
# Unexpected errors
# ---------------------------------------------------------------------------


def test_unexpected_errors_return_a_generic_500(make_client, monkeypatch, caplog):
    def broken():
        raise RuntimeError("SELECT secret FROM users WHERE zt-marker")

    monkeypatch.setattr(app_main.database, "engine_config", broken)
    with caplog.at_level(logging.ERROR, logger="app.main"):
        response = _client(make_client, ADMIN).get("/api/admin/inventory")
    assert response.status_code == 500
    assert response.json() == {"detail": "Internal server error"}
    for marker in LEAK_MARKERS:
        assert marker not in response.text
    assert response.headers["content-security-policy"] == app_main.CONTENT_SECURITY_POLICY
    assert response.headers["x-content-type-options"] == "nosniff"
    assert response.headers["cache-control"] == "no-store"
    # The details are kept for the operator, in the server log only.
    assert "Unhandled error on GET /api/admin/inventory" in caplog.text
    assert "RuntimeError" in caplog.text


# ---------------------------------------------------------------------------
# Every API route against junk input
# ---------------------------------------------------------------------------

JUNK_BODIES = [
    b"{", b"not json", b"[]", b'"text"', b"123",
    json.dumps({
        "challenge_id": 5, "code": [], "simulated_outcome": 7, "event_id": "abc", "samples": "abc",
        "contamination": "x", "thresholds": "x", "scenario_id": [], "variants": "x", "count": "x",
        "normal_samples": "x", "name": 5, "device_id": "x", "resource_id": None, "user_id": "abc",
        "context": "x", "email": 5, "password": [],
    }).encode(),
]
JUNK_PATH_VALUES = ["abc", "-1", "0", str(HUGE), "%00", "1;DROP TABLE users"]
JUNK_QUERY = "limit=abc&offset=-5&decision=;DROP&truth=x&user_id=abc&status=x&scenario=%00"
SKIPPED = {("POST", "/api/auth/logout")}  # would end the admin session used for the sweep


def _api_routes() -> list[tuple[str, str]]:
    routes = []
    for route in app.routes:
        if isinstance(route, APIRoute) and route.path.startswith("/api/"):
            for method in sorted(route.methods - {"HEAD", "OPTIONS"}):
                routes.append((method, route.path))
    return routes


def test_route_inventory_is_complete():
    paths = {path for _, path in _api_routes()}
    assert {"/api/access/preview", "/api/admin/model/train", "/api/events/{event_id}"} <= paths
    assert len(_api_routes()) >= 24


@pytest.mark.parametrize("credentials", [None, ADMIN], ids=["anonymous", "admin"])
def test_no_api_route_returns_500_for_junk(make_client, credentials):
    browser = _client(make_client, credentials)
    checked = 0
    for method, template in _api_routes():
        if (method, template) in SKIPPED:
            continue
        paths = [template] if "{" not in template else [
            template.split("{")[0] + value + template.split("}", 1)[1] for value in JUNK_PATH_VALUES]
        for path in paths:
            requests = [dict(params=JUNK_QUERY)]
            if method in ("POST", "PUT"):
                requests += [dict(content=body, headers={"content-type": "application/json"}) for body in JUNK_BODIES]
            for extra in requests:
                response = browser.request(method, path, **extra)
                checked += 1
                assert response.status_code != 500, (method, path, extra, response.text)
                assert response.status_code in (200, 400, 401, 403, 404, 405, 422), (method, path, response.status_code)
                for marker in LEAK_MARKERS:
                    assert marker not in response.text, (method, path, marker)
    assert checked > 100
