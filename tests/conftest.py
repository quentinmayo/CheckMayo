import os
import tempfile
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

tmp = tempfile.TemporaryDirectory(prefix="checkmayo-tests-")
os.environ["DATABASE_URL"] = "sqlite:///" + str(Path(tmp.name) / "test.db")
os.environ["CHECKMAYO_STATE_DIR"] = tmp.name
os.environ["PUBLIC_URL"] = "http://localhost:8000"
os.environ["CHECKMAYO_ADMIN_EMAIL"] = "admin@example.test"
os.environ["CHECKMAYO_ADMIN_PASSWORD"] = "bootstrap-test-password-only"
from app.db import Base, engine
from app.main import app


@pytest.fixture
def client(monkeypatch):
    monkeypatch.setenv("CHECKMAYO_MODE", "controller")
    Base.metadata.drop_all(engine)
    with TestClient(app, base_url="http://localhost:8000", headers={"Origin": "http://localhost:8000"}) as client:
        yield client


def account(client, email="owner@example.test"):
    data = {"email": email, "password": "test-password-for-fixture"}
    assert client.post("/api/auth/signup", json=data).status_code == 201
    assert client.post("/api/auth/login", json=data).status_code == 200
    return client.get("/api/me").json()["workspaces"][0]["id"]
