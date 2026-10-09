import hashlib
from datetime import timedelta
from pathlib import Path

import pytest
from conftest import account
from sqlalchemy import select

from app.db import Credential, Job, Session, now
from app.packages import runtime_compose, validate_compose
from app.security import digest
from runner.agent import safe_report

SOURCE = Path("scanners/gitleaks.yaml").read_text()


def package(client, wid, **overrides):
    data = {"name": "Test scanner", "version": "1.0", "description": "fixture", "compose": SOURCE, **overrides}
    response = client.post(f"/api/workspaces/{wid}/packages", json=data)
    assert response.status_code == 201, response.text
    return response.json()


def runner(client, wid, name="Runner"):
    response = client.post(f"/api/workspaces/{wid}/runners", json={"name": name, "labels": ["test"]})
    assert response.status_code == 201, response.text
    return response.json()


def poll(client, token):
    return client.post("/api/runner/poll", headers={"Authorization": "Bearer " + token})


def queue(client, wid, pid, label=""):
    response = client.post(
        f"/api/workspaces/{wid}/jobs",
        json={"package_id": pid, "repository": "https://github.com/quentinmayo/CheckMayo", "label": label},
    )
    assert response.status_code == 201, response.text
    return response.json()["id"]


def test_tenant_boundary_private_reports_and_runner_leases(client):
    a = account(client)
    p = package(client, a)
    r = runner(client, a)
    jid = queue(client, a, p["id"])
    job = poll(client, r["token"]).json()["job"]
    assert job["id"] == jid
    assert poll(client, r["token"]).json()["job"] is None
    b = account(client, "other@example.test")
    r2 = runner(client, b, "Other runner")
    assert client.get(f"/api/workspaces/{a}/packages").status_code == 404
    assert client.get(f"/api/packages/{p['id']}/download").status_code == 404
    assert client.get(f"/api/workspaces/{a}/jobs/{jid}/report").status_code == 404
    body = {"lease": job["lease"], "status": "completed", "report": "[]"}
    assert (
        client.post(
            f"/api/runner/jobs/{jid}/complete", headers={"Authorization": "Bearer " + r2["token"]}, json=body
        ).status_code
        == 409
    )
    assert (
        client.post(
            f"/api/runner/jobs/{jid}/complete", headers={"Authorization": "Bearer " + r["token"]}, json=body
        ).status_code
        == 200
    )
    assert (
        client.post(
            f"/api/runner/jobs/{jid}/complete", headers={"Authorization": "Bearer " + r["token"]}, json=body
        ).status_code
        == 409
    )


def test_cookie_csrf_and_key_scope_revocation(client):
    a = account(client)
    assert client.post(f"/api/workspaces/{a}/keys", headers={"Origin": "https://evil.example"}).status_code == 403
    assert client.post(f"/api/workspaces/{a}/keys", headers={"Origin": ""}).status_code == 403
    key = client.post(f"/api/workspaces/{a}/keys").json()["token"]
    headers = {"Authorization": "Bearer " + key}
    b = client.post("/api/workspaces", json={"name": "Second workspace"}).json()["id"]
    assert client.get(f"/api/workspaces/{a}/jobs", headers=headers).status_code == 200
    assert client.get(f"/api/workspaces/{b}/jobs", headers=headers).status_code == 403
    assert len(client.get("/api/me", headers=headers).json()["workspaces"]) == 1
    key_id = client.get(f"/api/workspaces/{a}/keys").json()[0]["id"]
    assert client.delete(f"/api/workspaces/{a}/keys/{key_id}").status_code == 200
    assert client.get(f"/api/workspaces/{a}/jobs", headers=headers).status_code == 401
    with Session() as db:
        c = db.scalar(select(Credential).where(Credential.digest == digest(key)))
        assert c.digest != key


def test_community_review_and_immutable_versions(client):
    wid = account(client)
    p = package(client, wid, visibility="community")
    assert p["id"] not in [x["id"] for x in client.get("/api/registry").json()]
    assert client.post(f"/api/admin/packages/{p['id']}/approve").status_code == 403
    assert client.get(f"/api/admin/packages/{p['id']}/source").status_code == 403
    assert client.post(f"/api/admin/packages/{p['id']}/withdraw").status_code == 403
    data = {"name": "Test scanner", "version": "1.0", "description": "changed", "compose": SOURCE}
    assert client.post(f"/api/workspaces/{wid}/packages", json=data).status_code == 409
    assert (
        client.post(
            "/api/auth/login", json={"email": "admin@example.test", "password": "bootstrap-test-password-only"}
        ).status_code
        == 200
    )
    source = client.get(f"/api/admin/packages/{p['id']}/source").json()
    assert source == {"compose": SOURCE, "sha256": p["sha256"]}
    assert client.post(f"/api/admin/packages/{p['id']}/approve").status_code == 200
    assert p["id"] in [x["id"] for x in client.get("/api/registry").json()]
    assert client.post(f"/api/admin/packages/{p['id']}/withdraw").status_code == 200
    assert p["id"] not in [x["id"] for x in client.get("/api/registry").json()]
    assert client.get(f"/api/admin/packages/{p['id']}/source").json() == source


def test_viewer_cannot_change_settings_or_triage(client):
    wid = account(client)
    account(client, "viewer@example.test")
    client.post("/api/auth/login", json={"email": "owner@example.test", "password": "test-password-for-fixture"})
    assert (
        client.post(
            f"/api/workspaces/{wid}/members", json={"email": "viewer@example.test", "role": "viewer"}
        ).status_code
        == 200
    )
    client.post("/api/auth/login", json={"email": "viewer@example.test", "password": "test-password-for-fixture"})
    assert client.get(f"/api/workspaces/{wid}/jobs").status_code == 200
    assert client.put(f"/api/workspaces/{wid}/settings", json={}).status_code == 403
    assert (
        client.post(
            f"/api/workspaces/{wid}/packages",
            json={"name": "Test", "version": "1", "description": "x", "compose": SOURCE},
        ).status_code
        == 403
    )


def test_expired_and_cancelled_leases_reject_completion(client):
    wid = account(client)
    p = package(client, wid)
    r = runner(client, wid)
    jid = queue(client, wid, p["id"])
    job = poll(client, r["token"]).json()["job"]
    with Session() as db:
        db.get(Job, jid).lease_expires = now() - timedelta(seconds=1)
        db.commit()
    assert (
        client.post(
            f"/api/runner/jobs/{jid}/complete",
            headers={"Authorization": "Bearer " + r["token"]},
            json={"lease": job["lease"], "status": "completed"},
        ).status_code
        == 409
    )
    assert client.post(f"/api/workspaces/{wid}/jobs/{jid}/cancel").status_code == 200
    assert (
        client.post(
            f"/api/runner/jobs/{jid}/heartbeat",
            headers={"Authorization": "Bearer " + r["token"]},
            json={"lease": job["lease"]},
        ).status_code
        == 409
    )


def test_runner_location_selection_and_disable(client):
    wid = account(client)
    p = package(client, wid)
    r = runner(client, wid)
    queue(client, wid, p["id"], "aws")
    assert poll(client, r["token"]).json()["job"] is None
    jid = queue(client, wid, p["id"], "test")
    assert poll(client, r["token"]).json()["job"]["id"] == jid
    client.post(f"/api/workspaces/{wid}/runners/{r['id']}/toggle")
    assert poll(client, r["token"]).status_code == 401


@pytest.mark.parametrize(
    "fragment",
    [
        "    privileged: true\n",
        "    build: .\n",
        "    devices: [/dev/sda]\n",
        "    ports: [8080:80]\n",
        "    env_file: .env\n",
        "    network_mode: host\n",
        '    volumes: ["/var/run/docker.sock:/var/run/docker.sock"]\n',
        '    volumes: ["/etc:/src:ro"]\n',
        '    user: "0:0"\n',
        "    security_opt: [seccomp:unconfined]\n",
        "    cap_add: [SYS_ADMIN]\n",
        '    environment: {TOKEN: "secret"}\n',
    ],
)
def test_host_escape_fields_are_rejected(fragment):
    source = "services:\n  scanner:\n    image: alpine:3.23\n" + fragment
    with pytest.raises(ValueError):
        validate_compose(source)


def test_package_digest_and_runtime_limits():
    _, sha = validate_compose(SOURCE)
    assert sha == hashlib.sha256(SOURCE.encode()).hexdigest()
    runtime, _ = validate_compose(runtime_compose(SOURCE))
    scanner = runtime["services"]["scanner"]
    assert scanner["mem_limit"] == "512m" and scanner["pids_limit"] == 128
    assert scanner["network_mode"] == "none" and scanner["read_only"] is True
    with pytest.raises(ValueError):
        validate_compose(SOURCE, "../../etc/passwd")


def test_report_symlink_and_path_escape(tmp_path):
    reports = tmp_path / "reports"
    reports.mkdir()
    outside = tmp_path / "secret"
    outside.write_text("do not read")
    (reports / "report.json").symlink_to(outside)
    with pytest.raises(ValueError):
        safe_report(reports, "report.json")
    with pytest.raises(ValueError):
        safe_report(reports, "../secret")


def test_registry_host_disables_execution_and_network_integrations(client, monkeypatch):
    wid = account(client)
    monkeypatch.setenv("CHECKMAYO_MODE", "registry")
    assert client.post(f"/api/workspaces/{wid}/runners", json={"name": "Test"}).status_code == 403
    assert (
        client.put(
            f"/api/workspaces/{wid}/integrations/ollama",
            json={"config": {"url": "http://localhost:11434", "model": "x"}},
        ).status_code
        == 403
    )
    assert (
        client.post(
            f"/api/workspaces/{wid}/schedules",
            json={"package_id": 1, "repository": "https://github.com/quentinmayo/CheckMayo", "cron": "* * * * *"},
        ).status_code
        == 403
    )


def test_ai_is_opt_in(client):
    wid = account(client)
    assert client.post(f"/api/workspaces/{wid}/ai/summarize", json={"text": "Ticket"}).status_code == 403


def test_login_rate_limit(client):
    for _ in range(30):
        client.post("/api/auth/logout")
    assert (
        client.post(
            "/api/auth/login", json={"email": "none@example.test", "password": "invalid-test-password"}
        ).status_code
        == 429
    )
