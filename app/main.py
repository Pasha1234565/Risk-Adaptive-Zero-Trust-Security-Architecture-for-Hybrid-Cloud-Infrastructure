"""FastAPI application: pages, JSON APIs and the request lifecycle.

The server plays three roles from the architecture:

* Policy Decision Point (PDP) - ``/api/access/evaluate`` calls the risk engine;
* Policy Enforcement Point (PEP) - ``/api/access/preview`` only releases a
  resource if the recorded decision permits it;
* Security operations console - pages for monitoring, simulation, evaluation
  and administration.
"""

from __future__ import annotations

import ipaddress
import json
import logging
import re
import time
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
from typing import Annotated, Any, Literal

from fastapi import FastAPI, HTTPException, Path, Query, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from . import __version__, anomaly, config, database, evaluation, mfa_crypto, risk, security, seed, simulator

API_TITLE = "Risk-Adaptive Zero-Trust Security Architecture for Hybrid Cloud"

logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    seed.seed_identity()
    database.purge_expired_revocations()
    risk.purge_old_challenges()
    if config.DEMO_TOTP_ENABLED:
        logger.warning(
            "ZT_ENABLE_DEMO_TOTP is on: the demo TOTP helper reveals step-up codes to "
            "signed-in loopback clients. Never enable it in a real deployment."
        )
    anomaly.get_model()
    simulator.bootstrap_history()
    with database.get_db() as conn:
        existing = conn.execute("SELECT COUNT(*) AS n FROM eval_runs").fetchone()["n"]
    if not existing and database.claim_once("baseline_evaluation_claimed_at"):
        evaluation.run_evaluation("Baseline (seeded)", persist_run=True)
    yield


# One documented location for the API docs and schema. FastAPI's default /docs
# and /redoc pages load assets from a CDN plus an inline script, which the
# Content-Security-Policy below blocks, so they are disabled and replaced by
# /api/docs (local assets); the schema moves next to it under /api/.
API_DOCS_URL = "/api/docs"
OPENAPI_URL = "/api/openapi.json"

# Applied to every response, including the API docs page.
CONTENT_SECURITY_POLICY = (
    "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; "
    "img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'self'"
)

app = FastAPI(
    title=API_TITLE,
    version=__version__,
    lifespan=lifespan,
    docs_url=None,
    redoc_url=None,
    openapi_url=OPENAPI_URL,
)
app.mount("/static", StaticFiles(directory=str(config.STATIC_DIR)), name="static")
templates = Jinja2Templates(directory=str(config.TEMPLATES_DIR))
templates.env.globals["version"] = __version__


@app.middleware("http")
async def security_headers(request: Request, call_next):
    response = await call_next(request)
    return _apply_security_headers(response, request.url.path)


# ---------------------------------------------------------------------------
# Error responses
# ---------------------------------------------------------------------------

# Largest value SQLite can store in an INTEGER column; larger ids would raise
# OverflowError inside the driver instead of a clean "not found".
MAX_DB_INT = 2**63 - 1
DbId = Annotated[int, Field(ge=-MAX_DB_INT, le=MAX_DB_INT)]


def _safe_loc_part(part: Any) -> str:
    # Locations can contain field names chosen by the client (unknown keys),
    # so they are reduced to a short, inert form before being returned.
    return re.sub(r"[^A-Za-z0-9_\-]", "_", str(part))[:40]


def _error_location(loc: list[str]) -> str:
    parts = [part for part in loc if part != "body"]
    return ".".join(parts) or "body"


@app.exception_handler(RequestValidationError)
async def validation_error_handler(request: Request, exc: RequestValidationError):
    """422 with a readable ``detail`` and a list of field errors.

    Pydantic's default body echoes the rejected ``input`` (and ``ctx``); only
    the location, message and error type are returned here, so a malformed
    request never reflects its own content back.
    """
    errors = []
    for error in exc.errors():
        loc = [_safe_loc_part(part) for part in error.get("loc", ())]
        if error.get("type") == "extra_forbidden" and loc:
            loc[-1] = "unknown_field"  # the name itself came from the client
        errors.append({"loc": loc, "msg": str(error.get("msg", "")), "type": str(error.get("type", ""))})
    first = errors[0] if errors else {"loc": [], "msg": "Invalid request"}
    summary = f"Invalid request: {_error_location(first['loc'])}: {first['msg']}"
    return JSONResponse(status_code=422, content={"detail": summary, "errors": errors})


def _apply_security_headers(response, path: str):
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("X-Frame-Options", "DENY")
    response.headers.setdefault("Referrer-Policy", "no-referrer")
    response.headers.setdefault("Permissions-Policy", "geolocation=(), microphone=(), camera=()")
    response.headers.setdefault("Content-Security-Policy", CONTENT_SECURITY_POLICY)
    if path.startswith("/api/"):
        response.headers.setdefault("Cache-Control", "no-store")
    return response


@app.exception_handler(Exception)
async def unhandled_error_handler(request: Request, exc: Exception):
    """Last resort: log the traceback server-side, return a generic 500.

    Starlette runs this handler outside the middleware stack, so the security
    headers are applied here explicitly.
    """
    logger.error("Unhandled error on %s %s", request.method, request.url.path, exc_info=exc)
    response = JSONResponse(status_code=500, content={"detail": "Internal server error"})
    return _apply_security_headers(response, request.url.path)


# ---------------------------------------------------------------------------
# Authentication helpers
# ---------------------------------------------------------------------------


def _bearer_token(request: Request) -> str | None:
    header = request.headers.get("authorization", "")
    if header.lower().startswith("bearer "):
        return header[7:].strip() or None
    return None


def _request_token(request: Request) -> str | None:
    """Session token for this request; the cookie takes precedence over Bearer."""
    return request.cookies.get(config.SESSION_COOKIE) or _bearer_token(request)


# Headers set by reverse proxies. Behind a proxy the TCP peer is the proxy, so a
# request carrying any of these is never treated as coming from this machine.
_FORWARDING_HEADERS = ("forwarded", "x-forwarded-for", "x-forwarded-host", "x-real-ip")


def _is_loopback_address(value: str | None) -> bool:
    try:
        return ipaddress.ip_address((value or "").strip("[]")).is_loopback
    except ValueError:
        return False


def is_local_request(request: Request) -> bool:
    """True only for a direct request from this machine to a loopback host.

    Requires a loopback TCP peer, no proxy forwarding headers, and a loopback
    Host header (which also rejects DNS-rebinding style host names).
    """
    if not request.client or not _is_loopback_address(request.client.host):
        return False
    if any(name in request.headers for name in _FORWARDING_HEADERS):
        return False
    hostname = (request.url.hostname or "").lower()
    return hostname == "localhost" or _is_loopback_address(hostname)


def demo_totp_available(request: Request) -> bool:
    return config.DEMO_TOTP_ENABLED and is_local_request(request)


def current_principal(request: Request) -> tuple[dict[str, Any], str] | None:
    """Return ``(user, session_id)`` for a valid session, else None.

    The session id is the token's ``jti``. It stays server-side (it is never
    added to the user dict returned by APIs) and is used to bind step-up
    challenges to the session that requested them.
    """
    token = _request_token(request)
    if not token:
        return None
    payload = security.verify_session_token(token)
    if not payload:
        return None
    user = _active_user(payload)
    return (user, payload["jti"]) if user else None


def current_user(request: Request) -> dict[str, Any] | None:
    principal = current_principal(request)
    return principal[0] if principal else None


def require_principal(request: Request) -> tuple[dict[str, Any], str]:
    principal = current_principal(request)
    if not principal:
        raise HTTPException(status_code=401, detail="Authentication required")
    return principal


def _active_user(payload: dict[str, Any]) -> dict[str, Any] | None:
    try:
        user_id = int(payload.get("sub", 0))
    except (TypeError, ValueError):
        return None
    with database.get_db() as conn:
        user = database.row(
            conn,
            "SELECT id, email, name, role, department, status, is_admin, mfa_enabled "
            "FROM users WHERE id = ?",
            (user_id,),
        )
    if not user or user["status"] != "active":
        return None
    user["is_admin"] = bool(user["is_admin"])
    user["mfa_enabled"] = bool(user["mfa_enabled"])
    return user


def require_user(request: Request) -> dict[str, Any]:
    user = current_user(request)
    if not user:
        raise HTTPException(status_code=401, detail="Authentication required")
    return user


def require_admin(request: Request) -> dict[str, Any]:
    user = require_user(request)
    if not user["is_admin"]:
        raise HTTPException(status_code=403, detail="Administrator privileges required")
    return user


SIMULATION_FORBIDDEN = (
    "Acting for another identity or running simulations requires the security "
    "administrator or SOC analyst role."
)


def can_simulate(user: dict[str, Any]) -> bool:
    """Server-side rule for evaluating on behalf of other identities."""
    return bool(user["is_admin"]) or user["role"] in config.SIMULATION_ROLES


def inventory_scope(user: dict[str, Any]) -> str:
    """Visibility of identities, devices, events and alerts for ``user``.

    ``full`` for security administrators, ``soc`` for SOC analysts (both see
    every identity's records), ``self`` for every other role.
    """
    if user["is_admin"] or user["role"] == "security_admin":
        return "full"
    if can_simulate(user):
        return "soc"
    return "self"


def _own_records_only(user: dict[str, Any]) -> bool:
    return inventory_scope(user) == "self"


TRIAGE_FORBIDDEN = "Alert triage requires the security administrator or SOC analyst role."


def require_simulation_operator(request: Request) -> tuple[dict[str, Any], str]:
    user, session_id = require_principal(request)
    if not can_simulate(user):
        raise HTTPException(status_code=403, detail=SIMULATION_FORBIDDEN)
    return user, session_id


def _page(request: Request, template: str, context: dict[str, Any] | None = None):
    user = current_user(request)
    if not user:
        return RedirectResponse("/login", status_code=303)
    payload = {
        "request": request,
        "user": user,
        "environment": config.ENVIRONMENT,
        "version": __version__,
        "active": template.replace(".html", ""),
        "demo_totp_available": demo_totp_available(request),
        "can_simulate": can_simulate(user),
    }
    payload.update(context or {})
    return templates.TemplateResponse(request, template, payload)


# ---------------------------------------------------------------------------
# Auth API
# ---------------------------------------------------------------------------


class LoginPayload(BaseModel):
    email: str = Field(min_length=3, max_length=120)
    password: str = Field(min_length=1, max_length=200)


def _recent_failures(email: str, window_seconds: int = 300) -> int:
    cutoff = (datetime.now(timezone.utc) - timedelta(seconds=window_seconds)).isoformat(timespec="seconds")
    with database.get_db() as conn:
        last_success = database.row(
            conn,
            "SELECT ts FROM login_attempts WHERE email = ? AND success = 1 ORDER BY id DESC LIMIT 1",
            (email,),
        )
        since = cutoff
        if last_success and str(last_success["ts"]) > since:
            since = str(last_success["ts"])
        row = database.row(
            conn,
            "SELECT COUNT(*) AS n, MAX(ts) AS last FROM login_attempts "
            "WHERE email = ? AND success = 0 AND ts > ?",
            (email, since),
        )
    return int(row["n"]) if row else 0


def failed_logins_24h(email: str) -> int:
    cutoff = (datetime.now(timezone.utc) - timedelta(hours=24)).isoformat(timespec="seconds")
    with database.get_db() as conn:
        row = database.row(
            conn,
            "SELECT COUNT(*) AS n FROM login_attempts WHERE email = ? AND success = 0 AND ts > ?",
            (email, cutoff),
        )
    return int(row["n"]) if row else 0


@app.post("/api/auth/login")
def login(payload: LoginPayload, request: Request):
    email = payload.email.strip().lower()
    failures = _recent_failures(email)
    if failures >= config.MAX_LOGIN_FAILURES:
        raise HTTPException(
            status_code=429,
            detail=f"Too many failed attempts. Try again in {config.LOGIN_LOCK_SECONDS // 60} minutes.",
        )
    ip = request.client.host if request.client else ""
    with database.get_db() as conn:
        user = database.row(conn, "SELECT * FROM users WHERE email = ?", (email,))
    if not user or not security.verify_password(payload.password, user["password_hash"]):
        with database.get_db() as conn:
            conn.execute(
                "INSERT INTO login_attempts (email, ts, success, source_ip) VALUES (?, ?, 0, ?)",
                (email, database.utcnow(), ip),
            )
        remaining = max(0, config.MAX_LOGIN_FAILURES - failures - 1)
        raise HTTPException(
            status_code=401,
            detail=f"Invalid email or password. {remaining} attempt(s) remaining.",
        )
    if user["status"] != "active":
        raise HTTPException(status_code=403, detail="This identity is suspended.")
    with database.get_db() as conn:
        conn.execute(
            "INSERT INTO login_attempts (email, ts, success, source_ip) VALUES (?, ?, 1, ?)",
            (email, database.utcnow(), ip),
        )
    token = security.issue_token(user["id"])
    response = JSONResponse(
        {
            "user": {
                "id": user["id"],
                "name": user["name"],
                "email": user["email"],
                "role": user["role"],
                "is_admin": bool(user["is_admin"]),
            },
            "redirect": "/",
        }
    )
    response.set_cookie(
        config.SESSION_COOKIE,
        token,
        max_age=config.SESSION_TTL_SECONDS,
        httponly=True,
        samesite="lax",
        path="/",
    )
    return response


@app.post("/api/auth/logout")
def logout(request: Request):
    # Revoke every session token presented (cookie and/or Bearer) server-side,
    # so a copied token cannot be replayed after sign-out. Logout stays
    # idempotent: a missing or invalid token still returns ok.
    presented = {request.cookies.get(config.SESSION_COOKIE), _bearer_token(request)}
    for token in presented - {None, ""}:
        security.revoke_session_token(token)
    response = JSONResponse({"ok": True})
    response.delete_cookie(config.SESSION_COOKIE, path="/")
    return response


@app.get("/api/auth/me")
def me(request: Request):
    user = require_user(request)
    with database.get_db() as conn:
        cards = database.rows(
            conn,
            "SELECT id, name, kind, managed, compliant, trust_score FROM devices WHERE user_id = ?",
            (user["id"],),
        )
    return {"user": user, "devices": cards}


@app.get("/api/auth/totp", include_in_schema=config.DEMO_TOTP_ENABLED)
def current_totp(request: Request):
    """Local demo helper that shows the current step-up code for the user.

    Disabled unless ZT_ENABLE_DEMO_TOTP is true; when disabled it is
    indistinguishable from an unknown route. When enabled it is served only to
    direct loopback clients. In a real deployment the code exists only on the
    enrolled authenticator and step-up uses /api/access/challenge alone.
    """
    if not config.DEMO_TOTP_ENABLED:
        raise HTTPException(status_code=404, detail="Not Found")
    if not is_local_request(request):
        raise HTTPException(
            status_code=403,
            detail="The demo TOTP helper is only available to loopback clients on this machine.",
        )
    user = require_user(request)
    with database.get_db() as conn:
        selected = database.row(conn, "SELECT mfa_secret, mfa_enabled FROM users WHERE id = ?", (user["id"],))
    if not selected or not selected["mfa_enabled"]:
        raise HTTPException(status_code=400, detail="MFA is not enabled for this identity")
    # Replay protection accepts each 30-second step once per user, so tell the
    # console when the current code has already been spent.
    try:
        secret = mfa_crypto.decrypt_secret(selected["mfa_secret"], user["id"])
    except (mfa_crypto.MfaKeyError, mfa_crypto.SecretDecryptionError) as exc:
        logger.error("Demo TOTP helper cannot decrypt the MFA secret of user %s: %s", user["id"], exc)
        raise HTTPException(status_code=503, detail=risk.UNAVAILABLE_MESSAGE) from exc
    last_accepted = database.last_totp_counter(user["id"])
    return {
        "code": security.totp_code(secret),
        "seconds_remaining": security.totp_seconds_remaining(),
        "already_used": last_accepted is not None and last_accepted >= security.current_totp_counter(),
        "note": "Demo only: in production this code lives on the enrolled authenticator.",
    }


# ---------------------------------------------------------------------------
# Context / inventory
# ---------------------------------------------------------------------------


def _permitted_resources(role: str, resources: list[dict], policies: list[dict]) -> list[dict]:
    """Resources whose enabled role-restricting policies admit ``role`` (the
    same rule the PDP applies as its least-privilege check)."""
    permitted = []
    for resource in resources:
        requirements = risk._policy_requirements(policies, resource)
        if not requirements["role_restricted"] or role in requirements["allowed_roles"]:
            permitted.append(resource)
    return permitted


@app.get("/api/context/inventory")
def inventory(request: Request):
    """Identities, devices and resources for the access console, scoped by role.

    * full (security administrators) and soc (SOC analysts): every identity
      and device, because they triage events and run simulations for other
      identities, and every resource. Administrative records (policies,
      account flags, timestamps) stay in the admin-only /api/admin/inventory.
    * self (every other role, including service accounts): the caller's own
      identity and devices, and only the resources its role is permitted by
      policy. Service identities appear in no role-restricted policy, so they
      get the smallest set.

    Password hashes, MFA secrets, device fingerprints and session data are
    never selected.
    """
    user = require_user(request)
    scope = inventory_scope(user)
    with database.get_db() as conn:
        user_sql = "SELECT id, name, email, role, department, status, mfa_enabled FROM users"
        device_sql = "SELECT id, user_id, name, kind, os, managed, compliant, trust_score FROM devices"
        if scope == "self":
            users = database.rows(conn, user_sql + " WHERE id = ?", (user["id"],))
            devices = database.rows(conn, device_sql + " WHERE user_id = ? ORDER BY id", (user["id"],))
        else:
            users = database.rows(conn, user_sql + " ORDER BY id")
            devices = database.rows(conn, device_sql + " ORDER BY id")
        resources = database.rows(
            conn, "SELECT id, name, zone, service, category, sensitivity, owner, description FROM resources ORDER BY zone, name"
        )
        if scope == "self":
            policies = database.rows(conn, "SELECT * FROM policies ORDER BY id")
            resources = _permitted_resources(user["role"], resources, policies)
    for device in devices:
        device["managed"] = bool(device["managed"])
        device["compliant"] = bool(device["compliant"])
    for item in users:
        item["mfa_enabled"] = bool(item["mfa_enabled"])
        item["devices"] = [d for d in devices if d["user_id"] == item["id"]]
    return {
        "scope": scope,
        "users": users,
        "resources": resources,
        "geo_presets": list(risk.GEO_PRESETS.keys()),
        "defaults": {
            "geo": "Bengaluru, IN",
            "hour": datetime.now().hour,
        },
    }


@app.get("/api/topology")
def topology(request: Request):
    require_user(request)
    with database.get_db() as conn:
        resources = database.rows(
            conn, "SELECT id, name, zone, service, category, sensitivity FROM resources ORDER BY name"
        )
    return {
        "zones": {
            "private": [r for r in resources if r["zone"] == "private"],
            "public": [r for r in resources if r["zone"] == "public"],
        },
        "boundary": [
            {"name": "Identity Provider (IdP)", "role": "Authenticates users and devices", "icon": "id"},
            {"name": "Policy Decision Point (PDP)", "role": "Scores risk and decides access", "icon": "policy"},
            {"name": "Policy Enforcement Point (PEP)", "role": "Grants, limits or denies the resource", "icon": "shield"},
        ],
    }


# ---------------------------------------------------------------------------
# Access evaluation (PDP) and protected resource (PEP)
# ---------------------------------------------------------------------------


_FINITE = {"allow_inf_nan": False}


class AccessContext(BaseModel):
    """Request context for an evaluation. Every field is optional (defaults in
    risk.DEFAULT_CONTEXT); unknown fields, wrong types, out-of-range numbers,
    unknown locations and threat levels are rejected with 422."""

    model_config = ConfigDict(extra="forbid")

    geo: str | None = Field(default=None, max_length=64)
    hour: int | None = Field(default=None, ge=0, le=23)
    requests_last_5m: float | None = Field(default=None, ge=0, le=100_000, **_FINITE)
    failed_attempts_24h: float | None = Field(default=None, ge=0, le=100_000, **_FINITE)
    bytes_out_mb: float | None = Field(default=None, ge=0, le=10_000_000, **_FINITE)
    session_minutes: float | None = Field(default=None, ge=0, le=100_000, **_FINITE)
    concurrent_sessions: float | None = Field(default=None, ge=0, le=10_000, **_FINITE)
    new_device: bool | None = None
    mfa_verified: bool | None = None
    threat_intel: Literal["clean", "suspicious", "malicious"] | None = None
    source_ip: str | None = Field(default=None, max_length=64)
    note: str | None = Field(default=None, max_length=500)

    @field_validator("geo")
    @classmethod
    def _known_geo(cls, value: str | None) -> str | None:
        if value is not None and value not in risk.GEO_PRESETS:
            raise ValueError("Unknown location; use one of the geo_presets from /api/context/inventory")
        return value

    @field_validator("source_ip")
    @classmethod
    def _ip_address(cls, value: str | None) -> str | None:
        if value:
            try:
                ipaddress.ip_address(value)
            except ValueError as exc:
                raise ValueError("source_ip must be an IPv4 or IPv6 address") from exc
        return value


class AccessPayload(BaseModel):
    # Subject to evaluate. Omitted means the signed-in user; any other value is
    # accepted only from simulation roles (see can_simulate). Unknown top-level
    # fields are ignored (actor fields in the body must have no effect).
    user_id: DbId | None = None
    device_id: DbId
    resource_id: DbId
    context: AccessContext = Field(default_factory=AccessContext)


class ChallengePayload(BaseModel):
    """Answer to a step-up challenge: a TOTP ``code`` for a live challenge, or
    a ``simulated_outcome`` for a simulation challenge. Exactly one is allowed."""

    challenge_id: str = Field(min_length=8, max_length=200)
    code: str | None = Field(default=None, min_length=6, max_length=6)
    simulated_outcome: Literal["success", "failure"] | None = None

    @model_validator(mode="after")
    def _exactly_one_answer(self) -> "ChallengePayload":
        if (self.code is None) == (self.simulated_outcome is None):
            raise ValueError("Provide either code or simulated_outcome")
        return self


@app.post("/api/access/evaluate")
def evaluate_access(payload: AccessPayload, request: Request):
    # The actor always comes from the authenticated session. The evaluated
    # subject defaults to the actor; a different subject is a simulation and
    # needs a simulation role, enforced here rather than in the browser.
    actor, session_id = require_principal(request)
    subject_id = actor["id"] if payload.user_id is None else payload.user_id
    simulated = subject_id != actor["id"]
    if simulated and not can_simulate(actor):
        raise HTTPException(status_code=403, detail=SIMULATION_FORBIDDEN)
    with database.get_db() as conn:
        subject = database.row(conn, "SELECT email FROM users WHERE id = ?", (subject_id,))
    context = payload.context.model_dump(exclude_none=True)
    if subject:
        context.setdefault("failed_attempts_24h", failed_logins_24h(subject["email"]))
    try:
        result = risk.evaluate(
            subject_id,
            payload.device_id,
            payload.resource_id,
            context,
            persist=True,
            ground_truth=0,
            scenario="live",
            actor_id=actor["id"],
            session_id=session_id,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    result["actor"] = {"id": actor["id"], "name": actor["name"], "role": actor["role"]}
    result["simulated"] = simulated
    return result


@app.post("/api/access/challenge")
def complete_challenge(payload: ChallengePayload, request: Request):
    # Ownership comes from the authenticated session, never from the request
    # body: only the user and session that triggered the challenge may answer it.
    user, session_id = require_principal(request)
    # Only simulation operators may record simulated outcomes. (Simulation
    # challenges are only ever issued to operators, and verify_challenge also
    # requires the issuing actor and session.)
    if payload.simulated_outcome is not None and not can_simulate(user):
        raise HTTPException(status_code=403, detail=SIMULATION_FORBIDDEN)
    try:
        return risk.verify_challenge(
            payload.challenge_id,
            payload.code,
            actor_id=user["id"],
            session_id=session_id,
            simulated_outcome=payload.simulated_outcome,
        )
    except risk.ChallengeLimitError as exc:
        headers = {"Retry-After": str(exc.retry_after)} if exc.retry_after else None
        raise HTTPException(status_code=exc.status_code, detail=str(exc), headers=headers) from exc
    except risk.ChallengeError as exc:
        raise HTTPException(status_code=exc.status_code, detail=str(exc)) from exc


class PreviewPayload(BaseModel):
    event_id: int = Field(ge=1, le=MAX_DB_INT)


@app.post("/api/access/preview")
def preview_resource(payload: PreviewPayload, request: Request):
    user = require_user(request)
    event_id = payload.event_id
    with database.get_db() as conn:
        event = database.row(
            conn,
            """SELECT e.*, r.name AS resource_name, r.zone, r.service, r.category,
                      r.sensitivity, r.owner, r.description
               FROM events e JOIN resources r ON r.id = e.resource_id WHERE e.id = ?""",
            (event_id,),
        )
    if not event:
        raise HTTPException(status_code=404, detail="Access decision not found")
    if not user["is_admin"] and user["role"] not in ("analyst", "security_admin") and event["user_id"] != user["id"]:
        raise HTTPException(status_code=403, detail="Not permitted to view this resource")
    if event["decision"] not in ("ALLOW", "RESTRICT"):
        raise HTTPException(
            status_code=403,
            detail=f"Policy enforcement point denied the request (decision: {event['decision']}).",
        )
    started = time.perf_counter()
    scope = "full" if event["decision"] == "ALLOW" else "read-only"
    records = _resource_records(event, masked=event["decision"] == "RESTRICT")
    latency = round((time.perf_counter() - started) * 1000, 2)
    return {
        "resource": {
            "name": event["resource_name"],
            "zone": event["zone"],
            "service": event["service"],
            "category": event["category"],
            "sensitivity": event["sensitivity"],
            "owner": event["owner"],
            "description": event["description"],
        },
        "scope": scope,
        "decision": event["decision"],
        "records": records,
        "service_latency_ms": latency,
        "notice": "Synthetic sample records for the local prototype; no production data is used.",
    }


def _resource_records(event: dict, *, masked: bool = False) -> list[dict[str, Any]]:
    category = event["category"]
    if category == "database":
        rows = [
            {"invoice": "INV-20418", "account": "Northwind Logistics", "amount": 18400.00, "status": "paid"},
            {"invoice": "INV-20419", "account": "Cobalt Analytics", "amount": 7200.50, "status": "pending"},
            {"invoice": "INV-20420", "account": "Meridian Health", "amount": 31100.00, "status": "paid"},
        ]
    elif category == "storage":
        rows = [
            {"object": "analytics/2026/10/events.parquet", "size_mb": 2480, "classification": "internal"},
            {"object": "exports/customer_churn.parquet", "size_mb": 860, "classification": "confidential"},
            {"object": "archive/ledger-2025.tar.gz", "size_mb": 5120, "classification": "restricted"},
        ]
    elif category == "orchestration":
        rows = [
            {"namespace": "payments", "pods": 18, "status": "healthy"},
            {"namespace": "notifications", "pods": 6, "status": "healthy"},
            {"namespace": "platform-system", "pods": 12, "status": "degraded"},
        ]
    elif category == "identity":
        rows = [
            {"principal": "svc-backup", "role": "storage-writer", "last_rotation": "2026-09-14"},
            {"principal": "platform-admins", "role": "cluster-admin", "last_rotation": "2026-10-02"},
        ]
    else:
        rows = [
            {"record": "sample-001", "classification": "internal", "status": "available"},
            {"record": "sample-002", "classification": "internal", "status": "available"},
        ]
    if masked:
        masked_rows = []
        for item in rows:
            masked_rows.append(
                {
                    key: ("••••" if key in {"account", "amount", "object", "principal"} else value)
                    for key, value in item.items()
                }
            )
        return masked_rows
    return rows


# ---------------------------------------------------------------------------
# Monitoring APIs
# ---------------------------------------------------------------------------


@app.get("/api/events")
def list_events(
    request: Request,
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0, le=MAX_DB_INT),
    decision: str | None = Query(None, max_length=64),
    scenario: str | None = Query(None, max_length=64),
    truth: Literal["all", "attack", "normal"] | None = None,
    user_id: int | None = Query(None, ge=1, le=MAX_DB_INT),
):
    viewer = require_user(request)
    clauses: list[str] = []
    params: list[Any] = []
    # Non-SOC roles see only decisions about their own identity (including
    # simulations an operator ran against it).
    if _own_records_only(viewer):
        clauses.append("e.user_id = ?")
        params.append(viewer["id"])
    if decision and decision != "ALL":
        values = [d.strip().upper() for d in decision.split(",") if d.strip()]
        if not values or any(value not in config.DECISION_ORDER for value in values):
            raise HTTPException(
                status_code=422,
                detail="Invalid request: decision: use ALL or a comma-separated list of "
                       + ", ".join(config.DECISION_ORDER),
            )
        clauses.append(f"e.decision IN ({','.join('?' for _ in values)})")
        params.extend(values)
    if scenario and scenario != "all":
        clauses.append("e.scenario = ?")
        params.append(scenario)
    if truth == "attack":
        clauses.append("e.ground_truth = 1")
    elif truth == "normal":
        clauses.append("e.ground_truth = 0")
    if user_id:
        clauses.append("e.user_id = ?")
        params.append(user_id)
    where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
    with database.get_db() as conn:
        total = conn.execute(f"SELECT COUNT(*) AS n FROM events e {where}", params).fetchone()["n"]
        rows = database.rows(
            conn,
            f"""SELECT e.*, u.name AS user_name, u.email AS user_email, u.role AS user_role,
                       a.name AS actor_name, a.email AS actor_email,
                       d.name AS device_name, r.name AS resource_name, r.zone AS resource_zone,
                       r.sensitivity AS resource_sensitivity, r.category AS resource_category
                FROM events e
                LEFT JOIN users u ON u.id = e.user_id
                LEFT JOIN users a ON a.id = e.actor_user_id
                LEFT JOIN devices d ON d.id = e.device_id
                LEFT JOIN resources r ON r.id = e.resource_id
                {where}
                ORDER BY e.ts DESC, e.id DESC LIMIT ? OFFSET ?""",
            params + [limit, offset],
        )
    for item in rows:
        item["signals"] = _safe_json(item["signals"], [])
        item["reasons"] = _safe_json(item["reasons"], [])
        item["context"] = _safe_json(item["context"], {})
        item["ground_truth"] = bool(item["ground_truth"])
        item["simulated"] = _is_simulated(item)
    return {"events": rows, "total": total, "limit": limit, "offset": offset}


@app.get("/api/events/{event_id}")
def get_event(request: Request, event_id: int = Path(ge=1, le=MAX_DB_INT)):
    viewer = require_user(request)
    with database.get_db() as conn:
        item = database.row(
            conn,
            """SELECT e.*, u.name AS user_name, u.email AS user_email, u.role AS user_role,
                      a.name AS actor_name, a.email AS actor_email,
                      d.name AS device_name, d.trust_score AS device_trust,
                      r.name AS resource_name, r.zone AS resource_zone,
                      r.sensitivity AS resource_sensitivity, r.category AS resource_category
               FROM events e
               LEFT JOIN users u ON u.id = e.user_id
               LEFT JOIN users a ON a.id = e.actor_user_id
               LEFT JOIN devices d ON d.id = e.device_id
               LEFT JOIN resources r ON r.id = e.resource_id
               WHERE e.id = ?""",
            (event_id,),
        )
    # Another identity's event is reported exactly like a missing one, so ids
    # cannot be used to probe other users' activity.
    if not item or (_own_records_only(viewer) and item["user_id"] != viewer["id"]):
        raise HTTPException(status_code=404, detail="Event not found")
    for key in ("signals", "reasons", "context"):
        item[key] = _safe_json(item[key], [] if key != "context" else {})
    item["ground_truth"] = bool(item["ground_truth"])
    item["simulated"] = _is_simulated(item)
    return item


@app.get("/api/alerts")
def list_alerts(
    request: Request,
    status: Literal["open", "acknowledged", "all"] = "open",
    limit: int = Query(50, ge=1, le=500),
):
    viewer = require_user(request)
    clauses: list[str] = [] if status == "all" else ["a.status = ?"]
    params: list[Any] = [] if status == "all" else [status]
    own_only = _own_records_only(viewer)
    if own_only:
        clauses.append("e.user_id = ?")
        params.append(viewer["id"])
    where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
    with database.get_db() as conn:
        alerts = database.rows(
            conn,
            f"""SELECT a.*, e.decision, e.risk_score, e.anomaly_score, e.user_id,
                       u.name AS user_name, r.name AS resource_name
                FROM alerts a
                LEFT JOIN events e ON e.id = a.event_id
                LEFT JOIN users u ON u.id = e.user_id
                LEFT JOIN resources r ON r.id = e.resource_id
                {where}
                ORDER BY a.ts DESC LIMIT ?""",
            params + [limit],
        )
        open_count = conn.execute(
            "SELECT COUNT(*) AS n FROM alerts a LEFT JOIN events e ON e.id = a.event_id "
            "WHERE a.status = 'open'" + (" AND e.user_id = ?" if own_only else ""),
            [viewer["id"]] if own_only else [],
        ).fetchone()["n"]
    return {"alerts": alerts, "open_count": open_count, "scope": "self" if own_only else "all"}


@app.post("/api/alerts/{alert_id}/ack")
def acknowledge_alert(request: Request, alert_id: int = Path(ge=1, le=MAX_DB_INT)):
    user = require_user(request)
    if not can_simulate(user):
        raise HTTPException(status_code=403, detail=TRIAGE_FORBIDDEN)
    with database.get_db() as conn:
        found = conn.execute("SELECT id FROM alerts WHERE id = ?", (alert_id,)).fetchone()
        if not found:
            raise HTTPException(status_code=404, detail="Alert not found")
        conn.execute("UPDATE alerts SET status = 'acknowledged' WHERE id = ?", (alert_id,))
    return {"ok": True, "id": alert_id}


# ---------------------------------------------------------------------------
# Dashboard
# ---------------------------------------------------------------------------


@app.get("/api/dashboard")
def dashboard(request: Request):
    viewer = require_user(request)
    cutoff = (datetime.now(timezone.utc) - timedelta(hours=24)).isoformat(timespec="seconds")
    # Non-SOC roles get the same panels computed over their own events only.
    own_only = _own_records_only(viewer)
    mine = " AND user_id = ?" if own_only else ""
    mine_e = " AND e.user_id = ?" if own_only else ""
    me_param: list[Any] = [viewer["id"]] if own_only else []
    with database.get_db() as conn:
        stats = database.row(
            conn,
            f"""SELECT COUNT(*) AS total,
                      SUM(CASE WHEN decision = 'ALLOW' THEN 1 ELSE 0 END) AS allowed,
                      SUM(CASE WHEN decision = 'CHALLENGE' THEN 1 ELSE 0 END) AS challenged,
                      SUM(CASE WHEN decision = 'RESTRICT' THEN 1 ELSE 0 END) AS restricted,
                      SUM(CASE WHEN decision = 'BLOCK' THEN 1 ELSE 0 END) AS blocked,
                      AVG(risk_score) AS avg_risk,
                      AVG(latency_ms) AS avg_latency
               FROM events WHERE ts >= ?{mine}""",
            [cutoff] + me_param,
        )
        totals = database.row(conn, f"SELECT COUNT(*) AS total FROM events WHERE 1 = 1{mine}", me_param)
        open_alerts = conn.execute(
            f"SELECT COUNT(*) AS n FROM alerts a LEFT JOIN events e ON e.id = a.event_id "
            f"WHERE a.status = 'open'{mine_e}",
            me_param,
        ).fetchone()["n"]
        risk_rows = database.rows(
            conn,
            f"SELECT risk_score FROM events WHERE ts >= ?{mine} ORDER BY id DESC LIMIT 1000",
            [cutoff] + me_param,
        )
        recent = database.rows(
            conn,
            f"""SELECT e.id, e.ts, e.decision, e.risk_score, e.anomaly_score, e.scenario,
                      e.ground_truth, e.user_id, e.actor_user_id, e.outcome,
                      u.name AS user_name, r.name AS resource_name,
                      r.zone AS resource_zone, d.name AS device_name
               FROM events e LEFT JOIN users u ON u.id = e.user_id
               LEFT JOIN resources r ON r.id = e.resource_id
               LEFT JOIN devices d ON d.id = e.device_id
               WHERE 1 = 1{mine_e}
               ORDER BY e.ts DESC, e.id DESC LIMIT 8""",
            me_param,
        )
        alerts = database.rows(
            conn,
            f"""SELECT a.id, a.ts, a.severity, a.title, a.detail, a.status
               FROM alerts a LEFT JOIN events e ON e.id = a.event_id
               WHERE a.status = 'open'{mine_e} ORDER BY a.ts DESC LIMIT 5""",
            me_param,
        )
        latest_eval = conn.execute(
            "SELECT id, ts, metrics FROM eval_runs ORDER BY id DESC LIMIT 1"
        ).fetchone()
        events_by_hour = database.rows(
            conn,
            f"""SELECT substr(ts, 12, 2) AS hour, COUNT(*) AS n,
                      SUM(CASE WHEN decision != 'ALLOW' THEN 1 ELSE 0 END) AS elevated
               FROM events WHERE ts >= ?{mine} GROUP BY substr(ts, 12, 2) ORDER BY hour""",
            [cutoff] + me_param,
        )
    for item in recent:
        item["simulated"] = _is_simulated(item)
    bins = [0, 0, 0, 0, 0]
    for row in risk_rows:
        index = min(4, int(float(row["risk_score"]) // 20))
        bins[index] += 1
    detection = {}
    if latest_eval:
        try:
            detection = json.loads(latest_eval["metrics"]).get("detection", {})
        except json.JSONDecodeError:
            detection = {}
    return {
        "scope": "self" if own_only else "all",
        "stats": {
            "events_24h": stats["total"] or 0,
            "events_total": totals["total"] or 0,
            "allowed": stats["allowed"] or 0,
            "challenged": stats["challenged"] or 0,
            "restricted": stats["restricted"] or 0,
            "blocked": stats["blocked"] or 0,
            "avg_risk": round(float(stats["avg_risk"] or 0), 1),
            "avg_latency_ms": round(float(stats["avg_latency"] or 0), 2),
            "open_alerts": open_alerts,
            "detection_accuracy": detection.get("accuracy"),
            "false_positive_rate": detection.get("false_positive_rate"),
        },
        "risk_bins": [
            {"label": "0-19", "count": bins[0]},
            {"label": "20-39", "count": bins[1]},
            {"label": "40-59", "count": bins[2]},
            {"label": "60-79", "count": bins[3]},
            {"label": "80-100", "count": bins[4]},
        ],
        "decisions": [
            {"decision": "ALLOW", "count": stats["allowed"] or 0},
            {"decision": "CHALLENGE", "count": stats["challenged"] or 0},
            {"decision": "RESTRICT", "count": stats["restricted"] or 0},
            {"decision": "BLOCK", "count": stats["blocked"] or 0},
        ],
        "events_by_hour": events_by_hour,
        "recent": recent,
        "alerts": alerts,
        "model": anomaly.get_model().metadata(),
        "latest_eval_id": latest_eval["id"] if latest_eval else None,
    }


def _is_simulated(event: dict[str, Any]) -> bool:
    """True for simulator traffic and for evaluations an operator ran on behalf
    of another identity; such events never reflect a real sign-in or MFA check."""
    actor = event.get("actor_user_id")
    return event.get("scenario") != "live" or (actor is not None and actor != event.get("user_id"))


def _safe_json(value: Any, fallback: Any) -> Any:
    if isinstance(value, (dict, list)):
        return value
    try:
        return json.loads(value)
    except (TypeError, json.JSONDecodeError):
        return fallback


# ---------------------------------------------------------------------------
# Simulation and evaluation APIs
# ---------------------------------------------------------------------------


class ScenarioPayload(BaseModel):
    scenario_id: str = Field(max_length=64)
    variants: int = Field(default=3, ge=1, le=5)


class NormalPayload(BaseModel):
    count: int = Field(default=20, ge=1, le=200)


class EvaluationPayload(BaseModel):
    name: str = Field(default="Manual evaluation", max_length=120)
    normal_samples: int = Field(default=140, ge=20, le=500)
    variants: int = Field(default=3, ge=1, le=5)


@app.get("/api/sim/scenarios")
def list_scenarios(request: Request):
    require_user(request)
    return {"scenarios": simulator.SCENARIOS}


@app.post("/api/sim/scenario")
def run_scenario(payload: ScenarioPayload, request: Request):
    operator, session_id = require_simulation_operator(request)
    if payload.scenario_id not in simulator.SCENARIO_MAP:
        raise HTTPException(status_code=422, detail="Invalid request: scenario_id: unknown scenario; "
                                                    "see /api/sim/scenarios")
    try:
        results = simulator.run_scenario(
            payload.scenario_id, variants=payload.variants, persist=True,
            actor_id=operator["id"], session_id=session_id,
        )
    except (ValueError, StopIteration) as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return {
        "scenario": simulator.SCENARIO_MAP[payload.scenario_id]["name"],
        "results": results,
        "summary": _summarise_results(results),
    }


@app.post("/api/sim/normal")
def run_normal(payload: NormalPayload, request: Request):
    operator, session_id = require_simulation_operator(request)
    results = simulator.run_normal(
        payload.count, persist=True, seed=None, actor_id=operator["id"], session_id=session_id
    )
    return {"results": results, "summary": _summarise_results(results)}


@app.post("/api/sim/evaluation")
def run_evaluation(payload: EvaluationPayload, request: Request):
    require_simulation_operator(request)
    metrics = evaluation.run_evaluation(
        payload.name, normal_samples=payload.normal_samples, variants=payload.variants
    )
    return metrics


def _summarise_results(results: list[dict[str, Any]]) -> dict[str, Any]:
    counts = {key: 0 for key in ("ALLOW", "CHALLENGE", "RESTRICT", "BLOCK")}
    for result in results:
        counts[result["decision"]] = counts.get(result["decision"], 0) + 1
    return {
        "total": len(results),
        "decisions": counts,
        "max_risk": max((r["risk_score"] for r in results), default=0),
        "avg_latency_ms": round(
            sum(r["latency_ms"] for r in results) / max(1, len(results)), 2
        ),
        "detected": sum(1 for r in results if r["decision"] != "ALLOW"),
    }


@app.get("/api/evaluation/runs")
def evaluation_runs(request: Request, limit: int = Query(20, ge=1, le=100)):
    require_user(request)
    return {"runs": evaluation.list_runs(limit)}


@app.get("/api/evaluation/runs/{run_id}")
def evaluation_run(request: Request, run_id: int = Path(ge=1, le=MAX_DB_INT)):
    require_user(request)
    metrics = evaluation.get_run(run_id)
    if not metrics:
        raise HTTPException(status_code=404, detail="Evaluation run not found")
    return metrics


# ---------------------------------------------------------------------------
# Administration APIs
# ---------------------------------------------------------------------------


@app.get("/api/admin/inventory")
def admin_inventory(request: Request):
    require_admin(request)
    with database.get_db() as conn:
        users = database.rows(
            conn,
            "SELECT id, name, email, role, department, status, is_admin, mfa_enabled, created_at FROM users ORDER BY id",
        )
        devices = database.rows(
            conn,
            "SELECT id, user_id, name, kind, os, managed, compliant, trust_score, last_seen FROM devices ORDER BY id",
        )
        resources = database.rows(
            conn,
            "SELECT id, name, zone, service, category, sensitivity, owner, description FROM resources ORDER BY zone, name",
        )
        policies = database.rows(conn, "SELECT * FROM policies ORDER BY id")
        counts = database.row(
            conn,
            """SELECT (SELECT COUNT(*) FROM events) AS events,
                      (SELECT COUNT(*) FROM alerts) AS alerts,
                      (SELECT COUNT(*) FROM eval_runs) AS evaluations,
                      (SELECT COUNT(*) FROM login_attempts) AS login_attempts""",
        )
    for user in users:
        user["is_admin"] = bool(user["is_admin"])
        user["mfa_enabled"] = bool(user["mfa_enabled"])
        user["devices"] = [d for d in devices if d["user_id"] == user["id"]]
    return {
        "users": users,
        "devices": devices,
        "resources": resources,
        "policies": policies,
        "counts": counts,
        "model": anomaly.get_model().metadata(),
        "engine": database.engine_config(),
        "version": __version__,
    }


class TrainPayload(BaseModel):
    # Same ranges as the admin console form; values outside them are rejected
    # (422) instead of being silently clamped.
    samples: int = Field(default=1200, ge=200, le=5000)
    contamination: float = Field(default=0.04, ge=0.01, le=0.15, allow_inf_nan=False)


@app.post("/api/admin/model/train")
def train_model(request: Request, payload: TrainPayload | None = None):
    require_admin(request)
    payload = payload or TrainPayload()
    model = anomaly.retrain(samples=payload.samples, contamination=payload.contamination)
    return {"model": model.metadata(), "trained": True}


class SettingsPayload(BaseModel):
    thresholds: dict[Literal["allow_max", "challenge_max", "restrict_max"],
                     Annotated[float, Field(allow_inf_nan=False)]]


@app.put("/api/admin/settings")
def update_settings(payload: SettingsPayload, request: Request):
    require_admin(request)
    current = database.engine_config()["thresholds"]
    updated = dict(current)
    for key in ("allow_max", "challenge_max", "restrict_max"):
        if key in payload.thresholds:
            updated[key] = float(payload.thresholds[key])
    if not (1 <= updated["allow_max"] < updated["challenge_max"] < updated["restrict_max"] <= 99):
        raise HTTPException(
            status_code=400,
            detail="Thresholds must satisfy 1 ≤ allow < challenge < restrict ≤ 99.",
        )
    database.set_setting("thresholds", updated)
    database.set_setting("threshold_updated_at", database.utcnow())
    return {"thresholds": database.engine_config()["thresholds"]}


@app.post("/api/admin/policies/{policy_id}/toggle")
def toggle_policy(request: Request, policy_id: int = Path(ge=1, le=MAX_DB_INT)):
    require_admin(request)
    with database.get_db() as conn:
        policy = database.row(conn, "SELECT id, enabled FROM policies WHERE id = ?", (policy_id,))
        if not policy:
            raise HTTPException(status_code=404, detail="Policy not found")
        conn.execute(
            "UPDATE policies SET enabled = ? WHERE id = ?",
            (0 if policy["enabled"] else 1, policy_id),
        )
    return {"id": policy_id, "enabled": not bool(policy["enabled"])}


@app.get("/api/health")
def health():
    return {
        "status": "ok",
        "version": __version__,
        "environment": config.ENVIRONMENT,
        "database": str(config.DB_PATH.name),
        "time": database.utcnow(),
    }


# ---------------------------------------------------------------------------
# Pages
# ---------------------------------------------------------------------------


@app.get("/login")
def login_page(request: Request):
    if current_user(request):
        return RedirectResponse("/", status_code=303)
    demo_accounts = [
        {"name": u["name"], "email": u["email"], "password": u["password"], "role": u["role"]}
        for u in seed.DEMO_USERS
    ]
    return templates.TemplateResponse(
        request,
        "login.html",
        {
            "demo_accounts": demo_accounts,
            "environment": config.ENVIRONMENT,
            "version": __version__,
            "error": request.query_params.get("error"),
        },
    )


@app.get(API_DOCS_URL, include_in_schema=False)
def api_docs_page(request: Request):
    """Swagger UI built from pinned local assets so the default CSP applies."""
    return templates.TemplateResponse(
        request, "api_docs.html", {"title": API_TITLE, "openapi_url": OPENAPI_URL}
    )


@app.get("/")
def dashboard_page(request: Request):
    return _page(request, "dashboard.html", {"section": "Overview"})


@app.get("/access")
def access_page(request: Request):
    return _page(request, "access.html", {"section": "Access console"})


@app.get("/monitoring")
def monitoring_page(request: Request):
    return _page(request, "monitoring.html", {"section": "Monitoring"})


@app.get("/simulation")
def simulation_page(request: Request):
    return _page(request, "simulation.html", {"section": "Attack simulation"})


@app.get("/evaluation")
def evaluation_page(request: Request):
    return _page(request, "evaluation.html", {"section": "Evaluation"})


@app.get("/architecture")
def architecture_page(request: Request):
    return _page(request, "architecture.html", {"section": "Architecture"})


@app.get("/admin")
def admin_page(request: Request):
    user = current_user(request)
    if not user:
        return RedirectResponse("/login", status_code=303)
    if not user["is_admin"]:
        return RedirectResponse("/", status_code=303)
    return _page(request, "admin.html", {"section": "Administration"})
