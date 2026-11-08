"""Test fixtures.

The environment is configured before importing the application so the test run
uses an isolated data directory, a cheap PBKDF2 work factor and a fixed signing
key. The demo inventory is still seeded by the application lifespan.
"""

from __future__ import annotations

import os
import tempfile
from pathlib import Path

TEST_DIR = Path(tempfile.mkdtemp(prefix="zt-prototype-tests-"))
os.environ["ZT_DATA_DIR"] = str(TEST_DIR)
os.environ["ZT_DB_PATH"] = str(TEST_DIR / "test.db")
os.environ["ZT_MODEL_PATH"] = str(TEST_DIR / "model.joblib")
os.environ["ZT_SECRET_PATH"] = str(TEST_DIR / "signing.key")
os.environ["ZT_SESSION_SECRET"] = "tests-only-session-secret"
os.environ["ZT_PBKDF2_ITERATIONS"] = "1000"

import pytest  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from app.main import app  # noqa: E402

ADMIN = ("admin@hybridcloud.io", "Admin#2026")
ANALYST = ("analyst@hybridcloud.io", "Analyst#2026")


@pytest.fixture(scope="session")
def client():
    with TestClient(app) as test_client:
        yield test_client


def login(client: TestClient, email: str, password: str):
    return client.post("/api/auth/login", json={"email": email, "password": password})
