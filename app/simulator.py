"""Controlled attack simulation and normal-traffic generation.

All scenarios execute entirely inside this process against the local decision
engine. Nothing is sent to an external system: this is the authorised project
environment only.

Scenario contexts are built from real-world attack patterns (impossible travel,
credential stuffing, mass egress, lateral movement, MFA fatigue, rogue service
accounts) and mapped to MITRE ATT&CK techniques for reporting.
"""

from __future__ import annotations

import random
from datetime import datetime, timedelta, timezone
from typing import Any

from . import database, risk

SCENARIOS = [
    {
        "id": "impossible_travel",
        "name": "Impossible Travel",
        "technique": "T1078 · Valid Accounts",
        "severity": "high",
        "description": "An administrator session appears from London three minutes after a Bengaluru login, on an unrecognised personal phone.",
        "user_email": "admin@hybridcloud.io",
        "device_name": "iPhone 15 (personal)",
        "resource": "identity-provider",
        "context": {
            "geo": "London, UK",
            "hour": 3,
            "requests_last_5m": 12,
            "failed_attempts_24h": 1,
            "bytes_out_mb": 24,
            "session_minutes": 45,
            "concurrent_sessions": 3,
            "new_device": True,
            "mfa_verified": True,
            "threat_intel": "suspicious",
            "note": "Geo-velocity breach between Bengaluru and London.",
        },
    },
    {
        "id": "credential_stuffing",
        "name": "Credential Stuffing",
        "technique": "T1110.004 · Credential Stuffing",
        "severity": "high",
        "description": "A burst of failed logins against the internal wiki succeeds from a Singapore IP, reusing an analyst account.",
        "user_email": "analyst@hybridcloud.io",
        "device_name": "AISHA-LT-02",
        "resource": "internal-wiki",
        "context": {
            "geo": "Singapore, SG",
            "hour": 2,
            "requests_last_5m": 65,
            "failed_attempts_24h": 12,
            "bytes_out_mb": 8,
            "session_minutes": 5,
            "concurrent_sessions": 1,
            "new_device": True,
            "mfa_verified": False,
            "threat_intel": "suspicious",
            "note": "Automated credential reuse from a hosting range.",
        },
    },
    {
        "id": "brute_force",
        "name": "Distributed Brute Force",
        "technique": "T1110.001 · Password Guessing",
        "severity": "high",
        "description": "Finance portal hit with 80 requests in five minutes and 14 failed authentications from the US.",
        "user_email": "finance@hybridcloud.io",
        "device_name": "PRIYA-LT-03",
        "resource": "hr-portal",
        "context": {
            "geo": "Ashburn, US",
            "hour": 2,
            "requests_last_5m": 80,
            "failed_attempts_24h": 14,
            "bytes_out_mb": 6,
            "session_minutes": 2,
            "concurrent_sessions": 2,
            "new_device": True,
            "mfa_verified": False,
            "threat_intel": "malicious",
            "note": "Password guessing against the HR portal.",
        },
    },
    {
        "id": "compromised_device",
        "name": "Compromised Developer Endpoint",
        "technique": "T1078 + T1021 · Remote Services",
        "severity": "critical",
        "description": "A non-compliant developer laptop with 480 MB egress tries to reach the production Kubernetes control plane at 02:00.",
        "user_email": "dev@hybridcloud.io",
        "device_name": "ROHAN-LT-07",
        "resource": "k8s-prod",
        "context": {
            "geo": "Bengaluru, IN",
            "hour": 2,
            "requests_last_5m": 22,
            "failed_attempts_24h": 6,
            "bytes_out_mb": 480,
            "session_minutes": 140,
            "concurrent_sessions": 4,
            "new_device": True,
            "mfa_verified": True,
            "threat_intel": "suspicious",
            "note": "Endpoint flagged for unpatched kernel and unusual egress.",
        },
    },
    {
        "id": "insider_exfiltration",
        "name": "Insider Data Exfiltration",
        "technique": "T1567 · Exfiltration Over Web Service",
        "severity": "critical",
        "description": "A finance account downloads 950 MB from the analytics lake at 02:00 from Singapore with five concurrent sessions.",
        "user_email": "finance@hybridcloud.io",
        "device_name": "PRIYA-LT-03",
        "resource": "analytics-lake",
        "context": {
            "geo": "Singapore, SG",
            "hour": 2,
            "requests_last_5m": 40,
            "failed_attempts_24h": 3,
            "bytes_out_mb": 950,
            "session_minutes": 480,
            "concurrent_sessions": 5,
            "new_device": False,
            "mfa_verified": True,
            "threat_intel": "suspicious",
            "note": "Mass egress far above the finance baseline.",
        },
    },
    {
        "id": "privilege_escalation",
        "name": "Privilege Escalation",
        "technique": "T1078.004 · Cloud Accounts",
        "severity": "critical",
        "description": "An unmanaged contractor laptop attempts production orchestration access that its role does not permit.",
        "user_email": "contractor@hybridcloud.io",
        "device_name": "CONTRACTOR-LT-11",
        "resource": "k8s-prod",
        "context": {
            "geo": "Chennai, IN",
            "hour": 14,
            "requests_last_5m": 20,
            "failed_attempts_24h": 2,
            "bytes_out_mb": 20,
            "session_minutes": 30,
            "concurrent_sessions": 1,
            "new_device": True,
            "mfa_verified": True,
            "threat_intel": "clean",
            "note": "Role outside the orchestration allow-list.",
        },
    },
    {
        "id": "mfa_fatigue",
        "name": "MFA Fatigue",
        "technique": "T1621 · Multi-Factor Authentication Request Generation",
        "severity": "high",
        "description": "Eight failed attempts followed by repeated step-up prompts from an analyst account at 23:00 with eight parallel sessions.",
        "user_email": "analyst@hybridcloud.io",
        "device_name": "AISHA-LT-02",
        "resource": "api-gateway",
        "context": {
            "geo": "Chennai, IN",
            "hour": 23,
            "requests_last_5m": 30,
            "failed_attempts_24h": 8,
            "bytes_out_mb": 14,
            "session_minutes": 40,
            "concurrent_sessions": 8,
            "new_device": False,
            "mfa_verified": False,
            "threat_intel": "suspicious",
            "note": "Repeated challenge prompts to exhaust the user.",
        },
    },
    {
        "id": "rogue_service_account",
        "name": "Rogue Service Account",
        "technique": "T1078.004 · Cloud Accounts",
        "severity": "critical",
        "description": "The backup service account reaches the immutable backup vault from a known-malicious US address and stages 600 MB.",
        "user_email": "svc-backup@hybridcloud.io",
        "device_name": "backup-runner-01",
        "resource": "backup-vault",
        "context": {
            "geo": "Ashburn, US",
            "hour": 2,
            "requests_last_5m": 50,
            "failed_attempts_24h": 0,
            "bytes_out_mb": 600,
            "session_minutes": 90,
            "concurrent_sessions": 3,
            "new_device": False,
            "mfa_verified": False,
            "threat_intel": "malicious",
            "note": "Service credential used outside its automation window.",
        },
    },
    {
        "id": "off_hours_drift",
        "name": "Off-Hours Access Drift",
        "technique": "T1078 · Valid Accounts",
        "severity": "medium",
        "description": "An analyst opens the critical backup vault at 03:00 for the first time, with 80 MB of egress.",
        "user_email": "analyst@hybridcloud.io",
        "device_name": "AISHA-LT-02",
        "resource": "backup-vault",
        "context": {
            "geo": "Bengaluru, IN",
            "hour": 3,
            "requests_last_5m": 8,
            "failed_attempts_24h": 0,
            "bytes_out_mb": 80,
            "session_minutes": 60,
            "concurrent_sessions": 1,
            "new_device": False,
            "mfa_verified": True,
            "threat_intel": "clean",
            "note": "First-ever backup vault access outside business hours.",
        },
    },
    {
        "id": "unmanaged_contractor",
        "name": "Unmanaged Contractor Device",
        "technique": "T1200 · Hardware Additions",
        "severity": "medium",
        "description": "A contractor uses an unmanaged Windows 10 laptop to read internal documentation.",
        "user_email": "contractor@hybridcloud.io",
        "device_name": "CONTRACTOR-LT-11",
        "resource": "internal-wiki",
        "context": {
            "geo": "Chennai, IN",
            "hour": 11,
            "requests_last_5m": 6,
            "failed_attempts_24h": 0,
            "bytes_out_mb": 12,
            "session_minutes": 25,
            "concurrent_sessions": 1,
            "new_device": True,
            "mfa_verified": True,
            "threat_intel": "clean",
            "note": "Unmanaged and non-compliant device posture.",
        },
    },
    {
        "id": "lateral_movement",
        "name": "Lateral Movement",
        "technique": "T1021 · Remote Services",
        "severity": "high",
        "description": "A developer account probes the finance database from a non-compliant laptop, outside its least-privilege role.",
        "user_email": "dev@hybridcloud.io",
        "device_name": "ROHAN-LT-07",
        "resource": "finance-db",
        "context": {
            "geo": "Bengaluru, IN",
            "hour": 14,
            "requests_last_5m": 25,
            "failed_attempts_24h": 2,
            "bytes_out_mb": 40,
            "session_minutes": 55,
            "concurrent_sessions": 2,
            "new_device": False,
            "mfa_verified": True,
            "threat_intel": "clean",
            "note": "Developer role reaching a finance-only system.",
        },
    },
    {
        "id": "api_abuse",
        "name": "API Abuse / Key Misuse",
        "technique": "T1496 · Resource Hijacking",
        "severity": "high",
        "description": "A developer API key is used from Singapore at 02:00 for 90 requests in five minutes with 200 MB egress.",
        "user_email": "dev@hybridcloud.io",
        "device_name": "dev-vm-01",
        "resource": "api-gateway",
        "context": {
            "geo": "Singapore, SG",
            "hour": 2,
            "requests_last_5m": 90,
            "failed_attempts_24h": 3,
            "bytes_out_mb": 200,
            "session_minutes": 30,
            "concurrent_sessions": 6,
            "new_device": False,
            "mfa_verified": False,
            "threat_intel": "suspicious",
            "note": "Automated traffic well above the API key baseline.",
        },
    },
]

SCENARIO_MAP = {scenario["id"]: scenario for scenario in SCENARIOS}


def _inventory() -> tuple[dict[str, dict], dict[str, dict], dict[str, list[dict]]]:
    with database.get_db() as conn:
        users = {u["email"]: u for u in database.rows(conn, "SELECT * FROM users")}
        resources = {r["name"]: r for r in database.rows(conn, "SELECT * FROM resources")}
        devices = database.rows(conn, "SELECT * FROM devices")
    by_user: dict[str, list[dict]] = {}
    for device in devices:
        by_user.setdefault(str(device["user_id"]), []).append(device)
    return users, resources, by_user


def scenario_target(scenario: dict) -> tuple[dict, dict, dict]:
    users, resources, devices = _inventory()
    user = users[scenario["user_email"]]
    device = next(
        d for d in devices[str(user["id"])] if d["name"] == scenario["device_name"]
    )
    resource = resources[scenario["resource"]]
    return user, device, resource


def run_scenario(
    scenario_id: str,
    *,
    variants: int = 3,
    persist: bool = True,
    actor_id: int | None = None,
) -> list[dict[str, Any]]:
    scenario = SCENARIO_MAP.get(scenario_id)
    if not scenario:
        raise ValueError(f"Unknown scenario: {scenario_id}")
    user, device, resource = scenario_target(scenario)
    rng = random.Random(f"{scenario_id}-{variants}")
    results = []
    for index in range(max(1, variants)):
        context = dict(scenario["context"])
        if index:
            context["requests_last_5m"] = round(
                max(1.0, context["requests_last_5m"] * rng.uniform(0.75, 1.25)), 1
            )
            context["failed_attempts_24h"] = max(
                0, int(context["failed_attempts_24h"] * rng.uniform(0.7, 1.3))
            )
            context["bytes_out_mb"] = round(
                max(1.0, context["bytes_out_mb"] * rng.uniform(0.7, 1.4)), 1
            )
            context["note"] = f"{scenario['context']['note']} (variant {index + 1})"
        else:
            context["note"] = scenario["context"]["note"]
        result = risk.evaluate(
            user["id"],
            device["id"],
            resource["id"],
            context,
            persist=persist,
            ground_truth=1,
            scenario=scenario_id,
            actor_id=actor_id,
        )
        result["scenario_name"] = scenario["name"]
        result["technique"] = scenario["technique"]
        results.append(result)
    return results


def _normal_rng(seed: int | None = None) -> random.Random:
    return random.Random(seed if seed is not None else 2026)


def normal_context(
    user: dict, device: dict, resource: dict, rng: random.Random,
    *, timestamp: datetime | None = None,
) -> dict[str, Any]:
    # Business-hours distribution; contractor slightly later, service account at night.
    if user["role"] == "service":
        hour = rng.choice([1, 2, 3, 18, 19, 20])
    elif user["role"] == "contractor":
        hour = rng.randint(9, 20)
    else:
        hour = int(min(20, max(8, rng.gauss(13.5, 2.4))))
    location = "Bengaluru, IN"
    if rng.random() < 0.18:
        location = "Chennai, IN"
    session = round(rng.uniform(8, 95), 1)
    return {
        "geo": location,
        "hour": hour,
        "requests_last_5m": round(rng.uniform(1, 12), 1),
        "failed_attempts_24h": int(rng.choices([0, 1, 2], weights=[0.75, 0.2, 0.05])[0]),
        "bytes_out_mb": round(rng.uniform(3, 55), 1),
        "session_minutes": session,
        "concurrent_sessions": int(rng.choices([1, 2, 3], weights=[0.72, 0.22, 0.06])[0]),
        "new_device": False,
        "mfa_verified": bool(user["mfa_enabled"]),
        "threat_intel": "clean",
        "note": "Routine business-hours access.",
    }


ROLE_CATEGORIES = {
    "security_admin": None,
    "analyst": {"database", "web", "collaboration", "compute", "storage", "api", "orchestration"},
    "developer": {"compute", "orchestration", "storage", "web", "collaboration", "api"},
    "finance": {"database", "web", "storage", "api", "collaboration"},
    "contractor": {"collaboration", "web"},
}


def _normal_policies() -> list[dict]:
    with database.get_db() as conn:
        return database.rows(conn, "SELECT * FROM policies WHERE enabled = 1")


def _allowed_resources(user: dict, resources: list[dict]) -> list[dict]:
    categories = ROLE_CATEGORIES.get(user["role"], set())
    if categories is None:
        return resources
    return [r for r in resources if r["category"] in categories]


def _suitable_device(resource: dict, owned: list[dict], policies: list[dict], rng: random.Random) -> dict:
    """Normal users pick a device that satisfies the policy for the target.

    This models realistic behaviour (staff use the managed laptop for sensitive
    systems) rather than forcing every legitimate session through a challenge.
    """
    required = risk._policy_requirements(policies, resource)["required_trust"]
    compliant = [d for d in owned if d["trust_score"] >= required]
    return rng.choice(compliant or owned)


def run_normal(
    count: int = 20,
    *,
    persist: bool = True,
    seed: int | None = None,
    spread_hours: float = 0.0,
    actor_id: int | None = None,
) -> list[dict[str, Any]]:
    users, resources, devices = _inventory()
    interactive = [u for u in users.values() if u["role"] != "service"]
    resource_pool = list(resources.values())
    policies = _normal_policies()
    rng = _normal_rng(seed)
    now = datetime.now(timezone.utc)
    results = []
    for _ in range(max(1, count)):
        user = rng.choice(interactive)
        owned = devices.get(str(user["id"])) or []
        allowed = _allowed_resources(user, resource_pool) or resource_pool
        resource = rng.choice(allowed)
        device = _suitable_device(resource, owned, policies, rng)
        timestamp = None
        if spread_hours > 0:
            offset = timedelta(minutes=rng.uniform(0, spread_hours * 60))
            timestamp = (now - offset).isoformat(timespec="seconds")
        result = risk.evaluate(
            user["id"],
            device["id"],
            resource["id"],
            normal_context(user, device, resource, rng),
            persist=persist,
            ground_truth=0,
            scenario="normal",
            timestamp=timestamp,
            actor_id=actor_id,
        )
        results.append(result)
    return results


def bootstrap_history() -> int:
    """Populate a believable baseline of normal activity on first run."""
    with database.get_db() as conn:
        count = conn.execute("SELECT COUNT(*) AS n FROM events").fetchone()["n"]
    if count:
        return 0
    results = run_normal(80, persist=True, spread_hours=24, seed=11)
    return len(results)
