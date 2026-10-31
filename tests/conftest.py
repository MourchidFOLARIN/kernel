"""Fixtures pytest : base SQLite isolée, client HTTP, seed."""
import os
from pathlib import Path

import pytest

TEST_DB = Path("/tmp/kernel_test.db")
os.environ["KERNEL_DB"] = str(TEST_DB)
os.environ["SECRET_KEY"] = "test-secret-key-kernel-etape1"
os.environ["DEMO_MODE"] = "true"

from app.database import SessionLocal, engine, init_db  # noqa: E402
from app.main import app  # noqa: E402
from app.seed import seed  # noqa: E402
from app.security import CSRF_COOKIE  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402


@pytest.fixture(autouse=True)
def _fresh_db():
    engine.dispose()
    if TEST_DB.exists():
        TEST_DB.unlink()
    init_db()
    db = SessionLocal()
    try:
        seed(db)
    finally:
        db.close()
    yield
    engine.dispose()
    if TEST_DB.exists():
        TEST_DB.unlink()


@pytest.fixture
def client():
    with TestClient(app) as c:
        r = c.get("/")
        assert r.status_code == 200
        yield c


def csrf_headers(client: TestClient) -> dict:
    seed_val = client.cookies.get(CSRF_COOKIE)
    assert seed_val, "cookie CSRF manquant"
    from itsdangerous import URLSafeSerializer
    from app import config
    token = URLSafeSerializer(config.SECRET_KEY, salt="kernel-csrf").dumps(seed_val)
    return {"X-CSRF-Token": token, "Content-Type": "application/json"}
