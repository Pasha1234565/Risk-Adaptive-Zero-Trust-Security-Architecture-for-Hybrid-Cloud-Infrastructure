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
# Exercise the real default (demo TOTP helper off) even if the developer's shell
# exported the flag; tests that need the helper enable it explicitly.
os.environ.pop("ZT_ENABLE_DEMO_TOTP", None)

import pytest  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from app.main import app  # noqa: E402

ADMIN = ("admin@hybridcloud.io", "Admin#2026")
ANALYST = ("analyst@hybridcloud.io", "Analyst#2026")


# autouse: the application lifespan seeds the demo inventory, trains the model
# and creates the schema. Engine-level tests that never request ``client`` still
# need that state, so start the app once per session regardless of test order.
@pytest.fixture(scope="session", autouse=True)
def client():
    with TestClient(app) as test_client:
        yield test_client


def login(client: TestClient, email: str, password: str):
    return client.post("/api/auth/login", json={"email": email, "password": password})


@pytest.fixture
def make_client(client):
    """Factory for independent clients (own cookie jar) on the started app.

    Depends on ``client`` so the lifespan has already run; extra keyword
    arguments are passed to ``TestClient`` (for example ``client=`` to set the
    simulated peer address).
    """
    created: list[TestClient] = []

    def factory(**kwargs) -> TestClient:
        kwargs.setdefault("follow_redirects", False)
        instance = TestClient(app, **kwargs)
        created.append(instance)
        return instance

    yield factory
    for instance in created:
        instance.close()
