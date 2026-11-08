from __future__ import annotations

ADMIN = ("admin@hybridcloud.io", "Admin#2026")
ANALYST = ("analyst@hybridcloud.io", "Analyst#2026")


def login(client, email: str, password: str):
    return client.post("/api/auth/login", json={"email": email, "password": password})


def test_health_does_not_require_auth(client):
    response = client.get("/api/health")
    assert response.status_code == 200
    assert response.json()["status"] == "ok"


def test_pages_and_api_require_login(client):
    client.cookies.clear()
    page = client.get("/", follow_redirects=False)
    assert page.status_code == 303
    assert page.headers["location"] == "/login"
    assert client.get("/api/dashboard").status_code == 401


def test_login_and_context_inventory(client):
    response = login(client, *ANALYST)
    assert response.status_code == 200
    assert response.json()["user"]["role"] == "analyst"

    me = client.get("/api/auth/me")
    assert me.status_code == 200
    assert me.json()["user"]["email"] == ANALYST[0]

    inventory = client.get("/api/context/inventory")
    assert inventory.status_code == 200
    body = inventory.json()
    assert len(body["users"]) == 6
    assert len(body["resources"]) == 12
    assert "Bengaluru, IN" in body["geo_presets"]

    topology = client.get("/api/topology")
    assert topology.status_code == 200
    assert topology.json()["zones"]["private"]
    assert topology.json()["zones"]["public"]


def test_evaluate_event_and_dashboard_flow(client):
    login(client, *ANALYST)
    inventory = client.get("/api/context/inventory").json()
    user = next(u for u in inventory["users"] if u["email"] == ANALYST[0])
    device = next(d for d in user["devices"] if d["managed"])
    resource = next(r for r in inventory["resources"] if r["name"] == "internal-wiki")

    response = client.post(
        "/api/access/evaluate",
        json={
            "user_id": user["id"],
            "device_id": device["id"],
            "resource_id": resource["id"],
            "context": {
                "geo": "Bengaluru, IN",
                "hour": 13,
                "requests_last_5m": 4,
                "failed_attempts_24h": 0,
                "bytes_out_mb": 14,
                "session_minutes": 20,
                "concurrent_sessions": 1,
                "new_device": False,
                "mfa_verified": True,
                "threat_intel": "clean",
            },
        },
    )
    assert response.status_code == 200, response.text
    result = response.json()
    assert result["decision"] in {"ALLOW", "CHALLENGE", "RESTRICT", "BLOCK"}
    assert len(result["signals"]) == 6
    assert 0 <= result["risk_score"] <= 100
    assert result["event_id"]

    event = client.get(f"/api/events/{result['event_id']}")
    assert event.status_code == 200
    assert event.json()["decision"] == result["decision"]

    dashboard = client.get("/api/dashboard")
    assert dashboard.status_code == 200
    assert dashboard.json()["stats"]["events_24h"] >= 1

    preview = client.post("/api/access/preview", json={"event_id": result["event_id"]})
    if result["decision"] in {"ALLOW", "RESTRICT"}:
        assert preview.status_code == 200
        assert preview.json()["records"]
    else:
        assert preview.status_code == 403


def test_admin_inventory_is_gated(client):
    login(client, *ANALYST)
    assert client.get("/api/admin/inventory").status_code == 403

    login(client, *ADMIN)
    response = client.get("/api/admin/inventory")
    assert response.status_code == 200
    body = response.json()
    assert body["engine"]["thresholds"]["allow_max"] < body["engine"]["thresholds"]["challenge_max"]
    assert body["model"]["features"]
    assert all("password_hash" not in user for user in body["users"])


def test_threshold_update_validates_and_applies(client):
    login(client, *ADMIN)
    original = client.get("/api/admin/inventory").json()["engine"]["thresholds"]
    updated = {"allow_max": 38, "challenge_max": 61, "restrict_max": 82}

    response = client.put("/api/admin/settings", json={"thresholds": updated})
    assert response.status_code == 200
    assert response.json()["thresholds"]["challenge_max"] == 61

    invalid = client.put(
        "/api/admin/settings",
        json={"thresholds": {"allow_max": 70, "challenge_max": 60, "restrict_max": 80}},
    )
    assert invalid.status_code == 400

    restored = client.put("/api/admin/settings", json={"thresholds": original})
    assert restored.status_code == 200
    assert restored.json()["thresholds"]["allow_max"] == original["allow_max"]


def test_policy_toggle_round_trip(client):
    login(client, *ADMIN)
    policies = client.get("/api/admin/inventory").json()["policies"]
    target = policies[0]
    first = client.post(f"/api/admin/policies/{target['id']}/toggle")
    assert first.status_code == 200
    assert first.json()["enabled"] is (not bool(target["enabled"]))
    second = client.post(f"/api/admin/policies/{target['id']}/toggle")
    assert second.status_code == 200
    assert second.json()["enabled"] is bool(target["enabled"])
