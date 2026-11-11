"""Runtime configuration.

All values can be overridden with environment variables so the prototype can
run from any directory and can be pointed at a throw-away database in tests.
"""

from __future__ import annotations

import os
from pathlib import Path

def env_flag(name: str, default: bool = False) -> bool:
    """Read a boolean environment variable.

    Only an explicit ``1``/``true``/``yes``/``on`` (case-insensitive) enables a
    flag; any other value counts as false.
    """
    value = os.environ.get(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


BASE_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = Path(os.environ.get("ZT_DATA_DIR", BASE_DIR / "data"))
STATIC_DIR = BASE_DIR / "app" / "static"
TEMPLATES_DIR = BASE_DIR / "app" / "templates"

DB_PATH = Path(os.environ.get("ZT_DB_PATH", DATA_DIR / "zerotrust.db"))
MODEL_PATH = Path(os.environ.get("ZT_MODEL_PATH", DATA_DIR / "behaviour_model.joblib"))
SECRET_PATH = Path(os.environ.get("ZT_SECRET_PATH", DATA_DIR / "signing.key"))

SESSION_COOKIE = "zt_session"
SESSION_TTL_SECONDS = 8 * 60 * 60
SESSION_SECRET = os.environ.get("ZT_SESSION_SECRET", "")

# Password hashing work factor. Kept deliberately explicit because the cost is
# measured as "authentication overhead" in the evaluation.
PBKDF2_ITERATIONS = int(os.environ.get("ZT_PBKDF2_ITERATIONS", "120000"))
PBKDF2_ALGORITHM = "sha256"

# Local demonstration helper (GET /api/auth/totp) that reveals the current TOTP
# step-up code to the signed-in user, because the demo identities have no
# enrolled phone. Disabled unless ZT_ENABLE_DEMO_TOTP is explicitly true, and
# even then served only to direct loopback clients. Never enable it in a real
# deployment: it lets anyone holding a password also pass step-up MFA.
DEMO_TOTP_ENABLED = env_flag("ZT_ENABLE_DEMO_TOTP", default=False)

MAX_LOGIN_FAILURES = 5
LOGIN_LOCK_SECONDS = 300

# Default risk engine configuration. Stored in the settings table so it can be
# tuned from the admin console without a code change.
DEFAULT_THRESHOLDS = {
    "allow_max": 40.0,
    "challenge_max": 60.0,
    "restrict_max": 80.0,
}

DEFAULT_WEIGHTS = {
    "behaviour": 30.0,
    "device": 20.0,
    "identity": 12.0,
    "resource": 14.0,
    "request": 14.0,
    "session": 10.0,
}

SENSITIVITY_SCORE = {
    "low": 0.15,
    "medium": 0.40,
    "high": 0.70,
    "critical": 1.00,
}

DECISION_ORDER = ["ALLOW", "CHALLENGE", "RESTRICT", "BLOCK"]

DECISION_META = {
    "ALLOW": {
        "label": "Allow",
        "severity": "low",
        "summary": "Request satisfies policy. Session is granted with least privilege.",
    },
    "CHALLENGE": {
        "label": "Challenge",
        "severity": "medium",
        "summary": "Step-up authentication is required before access is granted.",
    },
    "RESTRICT": {
        "label": "Restrict",
        "severity": "high",
        "summary": "Limited, read-only access with elevated monitoring.",
    },
    "BLOCK": {
        "label": "Block",
        "severity": "critical",
        "summary": "Request denied and the session is terminated.",
    },
}

# Trusted corporate networks / office location used by the behaviour baseline.
HOME_GEO = {"city": "Bengaluru", "country": "IN", "lat": 12.9716, "lon": 77.5946}
OFFICE_GEO = {"city": "Chennai", "country": "IN", "lat": 13.0827, "lon": 80.2707}

# Environment label shown in the UI.
ENVIRONMENT = os.environ.get("ZT_ENV_LABEL", "Local Prototype")
