import hashlib
import hmac
import json
import secrets
import shutil
from pathlib import Path

import pytest
from conftest import account
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from sqlalchemy import select
from test_security import package, poll, queue, runner

from app.config import decrypt
from app.db import Integration, Session
from app.findings import parse_report
from app.policy import evaluate_policy


@pytest.fixture
def github(client):
    wid = account(client)
    p = package(client, wid)
    private = (
        rsa.generate_private_key(public_exponent=65537, key_size=2048)
        .private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
        .decode()
    )
    config = {
        "app_id": "123",
        "installation_id": "456",
        "private_key": private,
        "webhook_secret": secrets.token_hex(32),
        "repository": "quentinmayo/CheckMayo",
        "package_id": p["id"],
        "label": "",
    }
    assert client.put(f"/api/workspaces/{wid}/integrations/github", json={"config": config}).status_code == 200
    return wid, config


def test_github_signature_installation_forks_and_replay(client, github):
    wid, config = github
    payload = {
        "action": "opened",
        "installation": {"id": 456},
        "repository": {"full_name": config["repository"]},
        "pull_request": {"head": {"repo": {"full_name": config["repository"]}, "sha": "a" * 40}},
    }

    def deliver(value, delivery="test-delivery", signature=True):
        raw = json.dumps(value).encode()
        headers = {"x-github-delivery": delivery, "x-github-event": "pull_request"}
        if signature:
            headers["x-hub-signature-256"] = (
                "sha256=" + hmac.new(config["webhook_secret"].encode(), raw, hashlib.sha256).hexdigest()
            )
        return client.post(f"/api/hooks/github/{wid}", content=raw, headers=headers)

    assert deliver(payload, signature=False).status_code == 401
    first = deliver(payload)
    assert first.status_code == 200 and first.json()["queued"]
    assert deliver(payload).json()["duplicate"]
    payload["pull_request"]["head"]["repo"]["full_name"] = "attacker/fork"
    assert deliver(payload, "fork").json()["ignored"]
    payload["installation"]["id"] = 999
    assert deliver(payload, "wrong-install").status_code == 403


def test_integration_secrets_encrypted_not_returned(client, github):
    wid, config = github
    with Session() as db:
        row = db.scalar(select(Integration).where(Integration.workspace_id == wid))
        assert config["private_key"] not in row.encrypted
        assert json.loads(decrypt(row.encrypted)) == config
    response = client.get(f"/api/workspaces/{wid}/integrations").text
    assert config["webhook_secret"] not in response and "private_key" not in response


def test_findings_deduplicate_with_tenant_boundary(client):
    wid = account(client)
    p = package(client, wid)
    r = runner(client, wid)
    report = json.dumps(
        [
            {
                "RuleID": "rule",
                "Description": "secret risk",
                "File": "main.py",
                "StartLine": 10,
                "Secret": "must not appear in normalized finding",
            }
        ]
    )
    for _ in range(2):
        jid = queue(client, wid, p["id"])
        job = poll(client, r["token"]).json()["job"]
        assert (
            client.post(
                f"/api/runner/jobs/{jid}/complete",
                headers={"Authorization": "Bearer " + r["token"]},
                json={"lease": job["lease"], "status": "completed", "report": report},
            ).status_code
            == 200
        )
    findings = client.get(f"/api/workspaces/{wid}/findings").json()
    assert len(findings) == 1 and findings[0]["severity"] == "High"
    assert "Secret" not in findings[0] and "must not appear" not in json.dumps(findings)
    other = account(client, "second@example.test")
    assert (
        client.post(
            f"/api/workspaces/{other}/findings/{findings[0]['id']}/triage", json={"status": "resolved"}
        ).status_code
        == 404
    )


def test_supported_native_report_shapes():
    assert (
        parse_report(
            json.dumps(
                {
                    "results": [
                        {
                            "check_id": "rule",
                            "extra": {"message": "unsafe eval", "severity": "WARNING"},
                            "path": "x.py",
                            "start": {"line": 2},
                        }
                    ]
                }
            )
        )[0]["severity"]
        == "Medium"
    )
    assert (
        parse_report(
            json.dumps(
                {
                    "Results": [
                        {
                            "Target": "Dockerfile",
                            "Misconfigurations": [{"ID": "AVD-1", "Title": "root", "Severity": "HIGH"}],
                        }
                    ]
                }
            )
        )[0]["rule"]
        == "AVD-1"
    )
    assert (
        parse_report(
            json.dumps({"runs": [{"results": [{"ruleId": "r1", "message": {"text": "risk"}, "level": "error"}]}]})
        )[0]["severity"]
        == "High"
    )
    assert parse_report("unknown format") == []


@pytest.mark.skipif(not shutil.which("opa"), reason="OPA binary unavailable")
def test_opa_critical_policy_and_forbidden_network():
    source = Path("policies/triage.rego").read_text()
    assert (
        evaluate_policy(source, {"finding": {"severity": "Critical"}, "asset": {"internet_facing": True}})["result"][
            "action"
        ]
        == "block"
    )
    from fastapi import HTTPException

    with pytest.raises(HTTPException):
        evaluate_policy(
            'package checkmayo.triage\nimport rego.v1\nresult := http.send({"method":"GET","url":"https://example.com"})',
            {},
        )


def test_saved_policy_can_be_disabled(client):
    import shutil

    if not shutil.which("opa"):
        pytest.skip("OPA required for real policy validation")
    wid = account(client)
    body = {"source": Path("policies/triage.rego").read_text(), "input": {}, "enabled": False}
    assert client.put(f"/api/workspaces/{wid}/policy", json=body).status_code == 200
    saved = client.get(f"/api/workspaces/{wid}/policy").json()
    assert saved["enabled"] is False
    assert saved["version"] == 1
    body["enabled"] = True
    assert client.put(f"/api/workspaces/{wid}/policy", json=body).status_code == 200
    assert client.get(f"/api/workspaces/{wid}/policy").json()["enabled"] is True
