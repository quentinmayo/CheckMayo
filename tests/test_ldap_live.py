"""Opt-in live LDAPS checks. Run CHECKMAYO_TEST_LDAP=1 pytest tests/test_ldap_live.py."""

import ipaddress
import os
import secrets
import shutil
import socket
import subprocess
import tempfile
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

import httpx
import pytest
from conftest import account
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from test_security import package, poll, queue, runner

pytestmark = pytest.mark.skipif(os.getenv("CHECKMAYO_TEST_LDAP") != "1", reason="Opt-in Docker LDAPS test")


def command(*args, **kwargs):
    result = subprocess.run(args, capture_output=True, text=True, timeout=180, **kwargs)
    if result.returncode:
        raise RuntimeError(f"Directory test command failed: {args[0]} (exit {result.returncode})")
    return result.stdout.strip()


def free_port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


@pytest.fixture(scope="module")
def directory():
    if not shutil.which("docker"):
        pytest.fail("Docker required for requested live directory test")
    folder = Path(tempfile.mkdtemp(prefix="checkmayo-ldap-"))
    folder.chmod(0o700)
    container = "checkmayo-ldap-" + secrets.token_hex(5)
    password = secrets.token_urlsafe(24)
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Disposable CheckMayo LDAP CA")])
    current = datetime.now(timezone.utc)
    ca = (
        x509.CertificateBuilder().subject_name(issuer).issuer_name(issuer).public_key(key.public_key())
        .serial_number(x509.random_serial_number()).not_valid_before(current - timedelta(minutes=1))
        .not_valid_after(current + timedelta(days=1))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True).sign(key, hashes.SHA256())
    )
    leaf_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    leaf = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")]))
        .issuer_name(issuer).public_key(leaf_key.public_key()).serial_number(x509.random_serial_number())
        .not_valid_before(current - timedelta(minutes=1)).not_valid_after(current + timedelta(days=1))
        .add_extension(x509.SubjectAlternativeName([
            x509.DNSName("localhost"), x509.IPAddress(ipaddress.ip_address("127.0.0.1"))
        ]), critical=False).sign(key, hashes.SHA256())
    )
    for filename, content in {
        "ca.crt": ca.public_bytes(serialization.Encoding.PEM),
        "server.crt": leaf.public_bytes(serialization.Encoding.PEM),
        "server.key": leaf_key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                              serialization.NoEncryption()),
    }.items():
        (folder / filename).write_bytes(content)
        (folder / filename).chmod(0o600)
    web, ldaps = free_port(), free_port()
    config = {
        "UID": str(os.getuid()), "GID": str(os.getgid()), "LLDAP_JWT_SECRET": secrets.token_hex(32),
        "LLDAP_KEY_SEED": secrets.token_hex(32), "LLDAP_LDAP_BASE_DN": "dc=example,dc=test",
        "LLDAP_LDAP_USER_PASS": password, "LLDAP_LDAP_USER_EMAIL": "ldap-admin@example.test",
        "LLDAP_LDAPS_OPTIONS__ENABLED": "true", "LLDAP_LDAPS_OPTIONS__CERT_FILE": "/data/server.crt",
        "LLDAP_LDAPS_OPTIONS__KEY_FILE": "/data/server.key",
    }
    env_file = folder / "directory.env"
    env_file.write_text("".join(f"{k}={v}\n" for k, v in config.items()))
    env_file.chmod(0o600)
    try:
        command("docker", "run", "-d", "--name", container, "--label", "project=checkmayo-disposable-test",
                "--memory", "256m", "--cpus", "0.5", "--pids-limit", "128", "--env-file", str(env_file),
                "-p", f"127.0.0.1:{web}:17170", "-p", f"127.0.0.1:{ldaps}:6360",
                "-v", f"{folder}:/data", "lldap/lldap:v0.6.3")
        base = f"http://127.0.0.1:{web}"
        token = None
        for _ in range(60):
            try:
                response = httpx.post(base + "/auth/simple/login", json={"username": "admin", "password": password})
                if response.status_code == 200:
                    token = response.json()["token"]
                    break
            except httpx.TransportError:
                pass
            time.sleep(1)
        assert token, "Disposable directory failed to initialize"
        for username in ["owner", "adminuser", "operator", "viewer"]:
            response = httpx.post(base + "/api/graphql", headers={"Authorization": "Bearer " + token}, json={
                "query": "mutation($user: CreateUserInput!) {createUser(user: $user) {id}}",
                "variables": {"user": {"id": username, "email": username + "@directory.example.test"}},
            })
            assert response.status_code == 200 and not response.json().get("errors"), "Directory user creation failed"
            payload = password + "\n" + token + "\n"
            command("docker", "exec", "-i", container, "sh", "-c",
                    'read -r LLDAP_USER_PASSWORD; export LLDAP_USER_PASSWORD; read -r ldap_test_token; '
                    'exec /app/lldap_set_password --base-url http://localhost:17170 '
                    '--token "$ldap_test_token" --username "$1"', "set-password", username, input=payload)
        yield {"url": f"ldaps://localhost:{ldaps}", "ca": str(folder / "ca.crt"), "password": password}
    finally:
        subprocess.run(["docker", "rm", "-f", container], capture_output=True, check=False, timeout=30)
        shutil.rmtree(folder)


@pytest.fixture
def ldap_config(directory, monkeypatch):
    for key, value in {
        "LDAP_URL": directory["url"], "LDAP_CA_FILE": directory["ca"],
        "LDAP_BIND_DN": "cn=admin,ou=people,dc=example,dc=test",
        "LDAP_BIND_PASSWORD": directory["password"], "LDAP_BASE_DN": "ou=people,dc=example,dc=test",
        "LDAP_USER_FILTER": "(uid={username})",
    }.items():
        monkeypatch.setenv(key, value)
    return directory


def ldap_signin(client, directory, username):
    response = client.post("/api/auth/ldap", json={"username": username, "password": directory["password"]})
    assert response.status_code == 200, response.text
    return client.get("/api/me").json()


def test_live_ldaps_identity_boundaries(client, ldap_config, monkeypatch):
    directory = ldap_config
    for username in ["owner", "viewer"]:
        me = ldap_signin(client, directory, username)
        assert me["email"] == username + "@directory.example.test"
        assert me["site_admin"] is False
    assert client.post("/api/auth/ldap", json={"username": "viewer", "password": "incorrect"}).status_code == 401
    assert client.post("/api/auth/ldap", json={"username": "admin)(uid=*)", "password": directory["password"]}).status_code == 401
    monkeypatch.delenv("LDAP_CA_FILE")
    assert client.post("/api/auth/ldap", json={"username": "viewer", "password": directory["password"]}).status_code == 401
    monkeypatch.setenv("LDAP_URL", directory["url"].replace("ldaps:", "ldap:"))
    assert client.post("/api/auth/ldap", json={"username": "viewer", "password": directory["password"]}).status_code == 503


@pytest.mark.parametrize("role,username,write,admin", [
    ("owner", "owner", True, True), ("admin", "adminuser", True, True),
    ("operator", "operator", True, False), ("viewer", "viewer", False, False),
])
def test_live_directory_roles(client, ldap_config, role, username, write, admin):
    foreign = account(client, "unrelated@example.test")
    me = ldap_signin(client, ldap_config, username)
    if role == "owner":
        wid = me["workspaces"][0]["id"]
    else:
        wid = account(client)
        assert client.post(f"/api/workspaces/{wid}/members", json={
            "email": me["email"], "role": role,
        }).status_code == 200
    # Prepare a report while signed in as the workspace owner, then test role access.
    fixture_package = package(client, wid, name="Role report fixture")
    fixture_runner = runner(client, wid)
    job_id = queue(client, wid, fixture_package["id"])
    lease = poll(client, fixture_runner["token"]).json()["job"]["lease"]
    assert client.post(f"/api/runner/jobs/{job_id}/complete", headers={
        "Authorization": "Bearer " + fixture_runner["token"],
    }, json={"lease": lease, "status": "completed", "report": '[{"RuleID":"fixture","File":"test.py"}]'}).status_code == 200
    ldap_signin(client, ldap_config, username)
    assert client.get(f"/api/workspaces/{wid}/jobs").status_code == 200
    assert client.get(f"/api/workspaces/{foreign}/jobs").status_code == 404
    assert client.get(f"/api/workspaces/{wid}/jobs/{job_id}/report").status_code == 200
    assert client.get(f"/api/workspaces/{foreign}/jobs/{job_id}/report").status_code == 404
    finding = client.get(f"/api/workspaces/{wid}/findings").json()[0]
    assert client.post(f"/api/workspaces/{wid}/findings/{finding['id']}/triage", json={
        "status": "accepted_risk",
    }).status_code == (200 if write else 403)
    publish_response = client.post(f"/api/workspaces/{wid}/packages", json={
        "name": "Directory role fixture", "version": "1.0", "description": "Disposable access test",
        "compose": Path("scanners/gitleaks.yaml").read_text(),
    })
    assert publish_response.status_code == (201 if write else 403)
    starter = client.get("/api/registry").json()[0]
    assert client.post(f"/api/workspaces/{wid}/jobs", json={
        "package_id": starter["id"], "repository": "https://github.com/quentinmayo/CheckMayo",
    }).status_code == (201 if write else 403)
    assert client.put(f"/api/workspaces/{wid}/settings", json={}).status_code == (200 if admin else 403)
    assert client.post(f"/api/workspaces/{wid}/runners", json={"name": "Directory test runner"}).status_code == (201 if admin else 403)
    assert client.post(f"/api/workspaces/{wid}/keys").status_code == (200 if admin else 403)
    assert client.post(f"/api/workspaces/{wid}/members", json={
        "email": "unrelated@example.test", "role": "viewer",
    }).status_code == (200 if admin else 403)
    assert client.get("/api/admin/packages/pending").status_code == 403
