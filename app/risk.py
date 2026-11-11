"""Risk-adaptive access control engine.

Every access request is evaluated against six contextual signals. Each signal
is normalised to 0-1, multiplied by a configurable weight, and summed into a
0-100 risk score. Organisation policies can escalate the score and enforce a
minimum decision, and a small set of hard rules (suspended identity, malicious
IP, destroyed device trust) block unconditionally.

The response is fully explainable: per-signal points, the anomaly attribution,
the policies that matched, and a ranked list of reasons.
"""

from __future__ import annotations

import json
import math
import secrets
import threading
import time
from datetime import datetime, timezone
from typing import Any

from . import config, database, anomaly

SIGNAL_LABELS = {
    "behaviour": "Behavioural anomaly",
    "device": "Device posture",
    "identity": "Identity assurance",
    "resource": "Resource sensitivity",
    "request": "Request context",
    "session": "Session context",
}

# City presets used by the console and simulator. Distance is computed from the
# baseline home location; impossible travel is derived from this value.
GEO_PRESETS = {
    "Bengaluru, IN": {"city": "Bengaluru", "country": "IN", "lat": 12.9716, "lon": 77.5946},
    "Chennai, IN": {"city": "Chennai", "country": "IN", "lat": 13.0827, "lon": 80.2707},
    "Mumbai, IN": {"city": "Mumbai", "country": "IN", "lat": 19.0760, "lon": 72.8777},
    "Singapore, SG": {"city": "Singapore", "country": "SG", "lat": 1.3521, "lon": 103.8198},
    "London, UK": {"city": "London", "country": "GB", "lat": 51.5072, "lon": -0.1276},
    "Frankfurt, DE": {"city": "Frankfurt", "country": "DE", "lat": 50.1109, "lon": 8.6821},
    "Ashburn, US": {"city": "Ashburn", "country": "US", "lat": 39.0438, "lon": -77.4874},
    "Lagos, NG": {"city": "Lagos", "country": "NG", "lat": 6.5244, "lon": 3.3792},
    "Sao Paulo, BR": {"city": "Sao Paulo", "country": "BR", "lat": -23.5505, "lon": -46.6333},
}

DEFAULT_CONTEXT = {
    "geo": "Bengaluru, IN",
    "hour": None,
    "requests_last_5m": 4,
    "failed_attempts_24h": 0,
    "bytes_out_mb": 12,
    "session_minutes": 24,
    "concurrent_sessions": 1,
    "new_device": False,
    "mfa_verified": True,
    "threat_intel": "clean",
    "source_ip": "",
    "note": "",
}

CITY_COORDS = GEO_PRESETS
HOME = config.HOME_GEO


def haversine_km(lat1: float, lon1: float, lat2: float, lon2: float) -> float:
    radius = 6371.0
    phi1, phi2 = math.radians(lat1), math.radians(lat2)
    d_phi = math.radians(lat2 - lat1)
    d_lambda = math.radians(lon2 - lon1)
    a = math.sin(d_phi / 2) ** 2 + math.cos(phi1) * math.cos(phi2) * math.sin(d_lambda / 2) ** 2
    return round(2 * radius * math.asin(math.sqrt(a)), 1)


def geo_details(name: str) -> dict[str, Any]:
    preset = CITY_COORDS.get(name) or CITY_COORDS["Bengaluru, IN"]
    distance = haversine_km(HOME["lat"], HOME["lon"], preset["lat"], preset["lon"])
    return {**preset, "label": name, "distance_km": distance}


def _clamp(value: float, low: float = 0.0, high: float = 1.0) -> float:
    return max(low, min(high, value))


def _severity_rank(decision: str) -> int:
    try:
        return config.DECISION_ORDER.index(decision)
    except ValueError:
        return 0


def _max_decision(*decisions: str) -> str:
    return max(decisions, key=_severity_rank)


def normalise_context(raw: dict[str, Any] | None) -> dict[str, Any]:
    ctx = dict(DEFAULT_CONTEXT)
    if raw:
        for key in DEFAULT_CONTEXT:
            if key in raw and raw[key] is not None:
                ctx[key] = raw[key]
    if ctx.get("hour") is None:
        ctx["hour"] = datetime.now().hour
    try:
        ctx["hour"] = int(ctx["hour"]) % 24
    except (TypeError, ValueError):
        ctx["hour"] = datetime.now().hour
    for key in ("requests_last_5m", "failed_attempts_24h", "bytes_out_mb",
                "session_minutes", "concurrent_sessions"):
        try:
            ctx[key] = max(0.0, float(ctx[key]))
        except (TypeError, ValueError):
            ctx[key] = float(DEFAULT_CONTEXT[key])
    ctx["new_device"] = bool(ctx.get("new_device"))
    ctx["mfa_verified"] = bool(ctx.get("mfa_verified"))
    if ctx.get("geo") not in CITY_COORDS:
        ctx["geo"] = "Bengaluru, IN"
    ctx["geolocation"] = geo_details(ctx["geo"])
    ctx["threat_intel"] = str(ctx.get("threat_intel", "clean")).lower()
    if ctx["threat_intel"] not in {"clean", "suspicious", "malicious"}:
        ctx["threat_intel"] = "clean"
    return ctx


def build_features(context: dict[str, Any], device: dict, resource: dict) -> dict[str, float]:
    geo = context["geolocation"]
    return {
        "hour": float(context["hour"]),
        "requests_last_5m": float(context["requests_last_5m"]),
        "geo_distance_km": float(geo["distance_km"]),
        "failed_attempts_24h": float(context["failed_attempts_24h"]),
        "device_trust": float(device["trust_score"]),
        "bytes_out_mb": float(context["bytes_out_mb"]),
        "session_minutes": float(context["session_minutes"]),
        "sensitivity": float(anomaly.SENSITIVITY_LEVEL.get(resource["sensitivity"], 2)),
        "new_device": 1.0 if context["new_device"] else 0.0,
    }


def _policy_requirements(policies: list[dict], resource: dict) -> dict[str, Any]:
    matching = [
        p for p in policies
        if p["enabled"] and p["resource_category"] in (resource["category"], "*")
    ]
    specific = [p for p in matching if p["resource_category"] == resource["category"]]
    required_trust = max((p["required_device_trust"] for p in matching), default=0)
    mfa_required = any(bool(p["mfa_required"]) for p in matching)
    role_policies = [p for p in specific if p["allowed_roles"].strip()]
    allowed_roles: set[str] = set()
    for policy in role_policies:
        allowed_roles.update(r.strip() for r in policy["allowed_roles"].split(",") if r.strip())
    return {
        "matching": matching,
        "specific": specific,
        "required_trust": required_trust,
        "mfa_required": mfa_required,
        "allowed_roles": allowed_roles,
        "role_restricted": bool(role_policies),
    }


def _signal_breakdown(
    user: dict, device: dict, resource: dict, context: dict,
    anomaly_result: dict, weights: dict,
) -> list[dict[str, Any]]:
    # Behaviour -----------------------------------------------------------
    behaviour = anomaly_result["score"]

    # Device --------------------------------------------------------------
    device_factor = (1.0 - device["trust_score"] / 100.0) * 0.75
    if not device["managed"]:
        device_factor += 0.15
    if not device["compliant"]:
        device_factor += 0.15
    if context["new_device"]:
        device_factor += 0.15
    device_factor = _clamp(device_factor)

    # Identity ------------------------------------------------------------
    identity_factor = 0.0
    if user["status"] != "active":
        identity_factor += 0.50
    if user["mfa_enabled"]:
        if not context["mfa_verified"]:
            identity_factor += 0.45
    else:
        identity_factor += 0.22
    if user["role"] in {"security_admin", "admin"}:
        identity_factor += 0.15
    if user["role"] in {"contractor", "service"}:
        identity_factor += 0.18
    identity_factor = _clamp(identity_factor)

    # Resource sensitivity -------------------------------------------------
    resource_factor = config.SENSITIVITY_SCORE.get(resource["sensitivity"], 0.4)

    # Request context -------------------------------------------------------
    geo = context["geolocation"]
    distance = geo["distance_km"]
    request_factor = 0.0
    if context["hour"] < 7 or context["hour"] > 21:
        request_factor += 0.20
    request_factor += min(context["failed_attempts_24h"] / 8.0, 1.0) * 0.28
    request_factor += min(context["requests_last_5m"] / 40.0, 1.0) * 0.24
    request_factor += min(distance / 4000.0, 1.0) * 0.34
    if geo["country"] != HOME["country"]:
        request_factor += 0.12
    if context["threat_intel"] == "malicious":
        request_factor += 0.55
    elif context["threat_intel"] == "suspicious":
        request_factor += 0.25
    request_factor = _clamp(request_factor)

    # Session ----------------------------------------------------------------
    session_factor = min(context["concurrent_sessions"] / 5.0, 1.0) * 0.40
    if context["session_minutes"] > 120:
        session_factor += min((context["session_minutes"] - 120) / 360.0, 1.0) * 0.30
    if context["new_device"]:
        session_factor += 0.18
    session_factor = _clamp(session_factor)

    factors = {
        "behaviour": behaviour,
        "device": device_factor,
        "identity": identity_factor,
        "resource": resource_factor,
        "request": request_factor,
        "session": session_factor,
    }

    breakdown = []
    for key, factor in factors.items():
        weight = float(weights.get(key, 0))
        breakdown.append(
            {
                "key": key,
                "label": SIGNAL_LABELS[key],
                "factor": round(factor, 4),
                "weight": round(weight, 2),
                "points": round(factor * weight, 1),
            }
        )
    return breakdown


def evaluate(
    user_id: int,
    device_id: int,
    resource_id: int,
    context: dict[str, Any] | None = None,
    *,
    persist: bool = True,
    ground_truth: int = 0,
    scenario: str = "live",
    action: str = "access",
    timestamp: str | None = None,
) -> dict[str, Any]:
    started = time.perf_counter()
    with database.get_db() as conn:
        user = database.row(conn, "SELECT * FROM users WHERE id = ?", (user_id,))
        device = database.row(conn, "SELECT * FROM devices WHERE id = ?", (device_id,))
        resource = database.row(conn, "SELECT * FROM resources WHERE id = ?", (resource_id,))
        policies = database.rows(conn, "SELECT * FROM policies ORDER BY id")
        if not user or not device or not resource:
            raise ValueError("Unknown user, device or resource")
        if device["user_id"] != user["id"]:
            raise ValueError("Device does not belong to the selected user")

        ctx = normalise_context(context)
        if not ctx["source_ip"]:
            ctx["source_ip"] = f"10.{user['id'] % 250}.{device['id'] % 250}.{20 + resource['id'] % 200}"

        model = anomaly.get_model()
        features = build_features(ctx, device, resource)
        anomaly_result = model.score(features)
        cfg = database.engine_config()
        weights = cfg["weights"]
        thresholds = cfg["thresholds"]

        signals = _signal_breakdown(user, device, resource, ctx, anomaly_result, weights)
        base_risk = round(sum(s["points"] for s in signals), 1)

        reasons: list[dict[str, str]] = []
        escalations = 0.0
        min_decision = "ALLOW"

        # Anomaly attribution ------------------------------------------------
        for factor in anomaly_result["top_factors"][:2]:
            reasons.append(
                {
                    "severity": "high" if anomaly_result["is_anomaly"] else "medium",
                    "text": f"{factor['label']} is {factor['z']}σ above the user's baseline "
                            f"({factor['value']} vs {factor['baseline']}).",
                }
            )
        for hit in anomaly_result["rule_hits"]:
            reasons.append({"severity": "high", "text": hit["reason"] + "."})

        # Organisational policies --------------------------------------------
        req = _policy_requirements(policies, resource)
        policy_notes: list[str] = []
        for policy in req["matching"]:
            policy_notes.append(policy["name"])
            if policy["effect"] != "enforce":
                continue
            if req["role_restricted"] and user["role"] not in req["allowed_roles"]:
                escalations += 18.0
                min_decision = _max_decision(min_decision, "RESTRICT")
                reasons.append(
                    {
                        "severity": "high",
                        "text": f"Least privilege: role '{user['role']}' is not permitted to "
                                f"access {resource['category']} resources under policy "
                                f"'{policy['name']}'.",
                    }
                )
                break
        if req["mfa_required"] and user["mfa_enabled"] and not ctx["mfa_verified"]:
            escalations += 20.0
            min_decision = _max_decision(min_decision, "CHALLENGE")
            reasons.append(
                {
                    "severity": "medium",
                    "text": "Policy requires step-up MFA, which has not been completed for this session.",
                }
            )
        if device["trust_score"] < req["required_trust"]:
            escalations += 15.0
            min_decision = _max_decision(min_decision, "CHALLENGE")
            reasons.append(
                {
                    "severity": "medium",
                    "text": f"Device trust {device['trust_score']:.0f} is below the policy "
                            f"requirement of {req['required_trust']:.0f}.",
                }
            )

        # Hard controls --------------------------------------------------------
        hard_block = False
        if user["status"] != "active":
            hard_block = True
            reasons.append({"severity": "critical", "text": f"Identity status is '{user['status']}'."})
        if device["trust_score"] < 20:
            hard_block = True
            reasons.append({"severity": "critical", "text": "Device trust is critically low."})
        if ctx["threat_intel"] == "malicious":
            hard_block = True
            reasons.append({"severity": "critical", "text": "Source IP is listed as malicious in threat intelligence."})

        risk = round(min(100.0, base_risk + escalations), 1)
        if risk < thresholds["allow_max"]:
            decision = "ALLOW"
        elif risk < thresholds["challenge_max"]:
            decision = "CHALLENGE"
        elif risk < thresholds["restrict_max"]:
            decision = "RESTRICT"
        else:
            decision = "BLOCK"
        decision = _max_decision(decision, min_decision)
        if hard_block:
            decision = "BLOCK"

        if not reasons:
            reasons.append(
                {
                    "severity": "low",
                    "text": "Identity, device posture, behaviour and request context are consistent "
                            "with the user's baseline.",
                }
            )

        latency_ms = round((time.perf_counter() - started) * 1000, 2)
        result = {
            "decision": decision,
            "risk_score": risk,
            "base_risk": base_risk,
            "anomaly_score": anomaly_result["score"],
            "anomaly": anomaly_result,
            "signals": signals,
            "reasons": reasons,
            "thresholds": thresholds,
            "weights": weights,
            "policy": {
                "matched": [p["name"] for p in req["matching"]],
                "required_trust": req["required_trust"],
                "mfa_required": req["mfa_required"],
                "role_restricted": req["role_restricted"],
                "escalation_points": round(escalations, 1),
            },
            "context": ctx,
            "features": features,
            "latency_ms": latency_ms,
            "user": _public_user(user),
            "device": _public_device(device),
            "resource": _public_resource(resource),
            "ts": timestamp or database.utcnow(),
        }

        if persist:
            event_id = _persist_event(
                conn, user, device, resource, result, ground_truth, scenario, action
            )
            result["event_id"] = event_id
            if decision in ("RESTRICT", "BLOCK"):
                _raise_alert(conn, result, event_id)

        result["challenge"] = None
        if persist and decision == "CHALLENGE":
            result["challenge"] = _issue_challenge(result["event_id"], user["id"])

    return result


class ChallengeError(ValueError):
    """Step-up verification failure; ``status_code`` is the HTTP status to use."""

    status_code = 400


class ChallengeLimitError(ChallengeError):
    """Too many incorrect codes, for one challenge or for the identity."""

    status_code = 429

    def __init__(self, message: str, retry_after: int | None = None):
        super().__init__(message)
        self.retry_after = retry_after


# One message for unknown, expired, used and cancelled challenges, so a caller
# cannot tell which of those states a challenge id is in.
INVALID_CHALLENGE = "Challenge expired or already used"

# Serialises challenge state changes: the app runs as one process whose sync
# endpoints execute in a thread pool.
_CHALLENGE_LOCK = threading.Lock()


def _purge_expired_challenges(now: float) -> None:
    for token in [key for key, entry in CHALLENGES.items() if entry["expires"] < now]:
        CHALLENGES.pop(token, None)


def _issue_challenge(event_id: int, user_id: int) -> dict[str, Any]:
    token = secrets.token_urlsafe(24)
    now = time.time()
    with _CHALLENGE_LOCK:
        _purge_expired_challenges(now)
        CHALLENGES[token] = {
            "event_id": event_id,
            "user_id": user_id,
            "expires": now + config.CHALLENGE_TTL_SECONDS,
            "used": False,
            "failed_attempts": 0,
        }
    return {
        "id": token,
        "expires_in": config.CHALLENGE_TTL_SECONDS,
        "method": "TOTP",
        "max_attempts": config.MFA_MAX_ATTEMPTS_PER_CHALLENGE,
    }


def _identity_retry_after(oldest_failure: str | None) -> int:
    """Seconds until the oldest counted failure leaves the throttle window."""
    try:
        oldest = datetime.fromisoformat(oldest_failure) if oldest_failure else None
    except ValueError:
        oldest = None
    if oldest is None:
        return config.MFA_USER_FAILURE_WINDOW_SECONDS
    elapsed = (datetime.now(timezone.utc) - oldest).total_seconds()
    return max(1, int(config.MFA_USER_FAILURE_WINDOW_SECONDS - elapsed) + 1)


def verify_challenge(token: str, code: str, *, actor_id: int | None = None) -> dict[str, Any]:
    """Complete a step-up challenge with a TOTP code and re-evaluate the request.

    Raises ChallengeError (400) for unknown, expired, used or cancelled
    challenges and for incorrect codes, and ChallengeLimitError (429) when
    the challenge or the identity has run out of attempts. ``actor_id`` is the
    signed-in user submitting the code, recorded with each attempt.
    """
    from .security import consume_totp

    with _CHALLENGE_LOCK:
        entry = CHALLENGES.get(token) if isinstance(token, str) else None
        if not entry or entry["used"] or entry["expires"] < time.time():
            if entry is not None:
                CHALLENGES.pop(token, None)
            raise ChallengeError(INVALID_CHALLENGE)
        with database.get_db() as conn:
            user = database.row(conn, "SELECT * FROM users WHERE id = ?", (entry["user_id"],))
            event = database.row(conn, "SELECT * FROM events WHERE id = ?", (entry["event_id"],))
        if not user or not event:
            CHALLENGES.pop(token, None)
            raise ChallengeError(INVALID_CHALLENGE)

        # Identity-wide budget: creating new challenges cannot reset it.
        failures, oldest = database.recent_mfa_failures(user["id"], config.MFA_USER_FAILURE_WINDOW_SECONDS)
        if failures >= config.MFA_USER_MAX_FAILURES:
            retry_after = _identity_retry_after(oldest)
            raise ChallengeLimitError(
                "Too many incorrect verification codes for this identity. "
                f"Try again in {max(1, -(-retry_after // 60))} minute(s).",
                retry_after=retry_after,
            )

        # consume_totp also rejects a time step already accepted for this user, so
        # a code observed once cannot complete a second challenge.
        if not consume_totp(user["id"], user["mfa_secret"], code):
            entry["failed_attempts"] += 1
            database.record_mfa_attempt(user["id"], False, actor_id)
            remaining = config.MFA_MAX_ATTEMPTS_PER_CHALLENGE - entry["failed_attempts"]
            if remaining <= 0:
                CHALLENGES.pop(token, None)
                raise ChallengeLimitError(
                    "Too many incorrect verification codes. This challenge has been cancelled; "
                    "submit a new access request."
                )
            raise ChallengeError(f"Incorrect verification code. {remaining} attempt(s) remaining.")
        entry["used"] = True
        database.record_mfa_attempt(user["id"], True, actor_id)

    context = json.loads(event["context"])
    context["mfa_verified"] = True
    re_evaluated = evaluate(
        event["user_id"],
        event["device_id"],
        event["resource_id"],
        context,
        persist=False,
        ground_truth=event["ground_truth"],
        scenario=event["scenario"],
    )
    reason = {
        "severity": "low",
        "text": "Step-up MFA satisfied; the request was re-evaluated with the new context.",
    }
    with database.get_db() as conn:
        conn.execute(
            """UPDATE events SET decision = ?, risk_score = ?, base_risk = ?, anomaly_score = ?,
                   signals = ?, reasons = ?, context = ?, latency_ms = ?, outcome = ?
               WHERE id = ?""",
            (
                re_evaluated["decision"],
                re_evaluated["risk_score"],
                re_evaluated["base_risk"],
                re_evaluated["anomaly_score"],
                json.dumps(re_evaluated["signals"]),
                json.dumps(re_evaluated["reasons"] + [reason]),
                json.dumps(re_evaluated["context"]),
                re_evaluated["latency_ms"],
                "step_up_verified",
                event["id"],
            ),
        )
    re_evaluated["event_id"] = event["id"]
    re_evaluated["reasons"] = re_evaluated["reasons"] + [reason]
    re_evaluated["step_up"] = True
    return re_evaluated


def _persist_event(conn, user, device, resource, result, ground_truth, scenario, action) -> int:
    cursor = conn.execute(
        """INSERT INTO events
           (ts, user_id, device_id, resource_id, action, decision, risk_score,
            anomaly_score, base_risk, signals, reasons, context, source_ip, geo,
            latency_ms, ground_truth, scenario, outcome)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        (
            result["ts"],
            user["id"],
            device["id"],
            resource["id"],
            action,
            result["decision"],
            result["risk_score"],
            result["anomaly_score"],
            result["base_risk"],
            json.dumps(result["signals"]),
            json.dumps(result["reasons"]),
            json.dumps(result["context"]),
            result["context"]["source_ip"],
            result["context"]["geolocation"]["label"],
            result["latency_ms"],
            int(ground_truth),
            scenario,
            "evaluated",
        ),
    )
    return int(cursor.lastrowid)


def _raise_alert(conn, result: dict, event_id: int) -> None:
    severity = "critical" if result["decision"] == "BLOCK" else "high"
    top_reason = result["reasons"][0]["text"] if result["reasons"] else ""
    conn.execute(
        """INSERT INTO alerts (ts, severity, title, detail, event_id, status)
           VALUES (?, ?, ?, ?, ?, 'open')""",
        (
            result["ts"],
            severity,
            f"{result['decision'].title()}: {result['user']['name']} → {result['resource']['name']}",
            f"Risk {result['risk_score']:.0f}/100 · anomaly {result['anomaly_score']:.2f}. {top_reason}",
            event_id,
        ),
    )


def _public_user(user: dict) -> dict:
    return {
        "id": user["id"],
        "name": user["name"],
        "email": user["email"],
        "role": user["role"],
        "department": user["department"],
        "status": user["status"],
        "mfa_enabled": bool(user["mfa_enabled"]),
    }


def _public_device(device: dict) -> dict:
    return {
        "id": device["id"],
        "name": device["name"],
        "kind": device["kind"],
        "os": device["os"],
        "managed": bool(device["managed"]),
        "compliant": bool(device["compliant"]),
        "trust_score": device["trust_score"],
    }


def _public_resource(resource: dict) -> dict:
    return {
        "id": resource["id"],
        "name": resource["name"],
        "zone": resource["zone"],
        "service": resource["service"],
        "category": resource["category"],
        "sensitivity": resource["sensitivity"],
        "owner": resource["owner"],
    }


# In-memory step-up challenges. Suitable for the single-process local
# prototype; a production deployment would use a shared cache.
CHALLENGES: dict[str, dict[str, Any]] = {}
