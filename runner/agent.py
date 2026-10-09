#!/usr/bin/env python3
"""Outbound-only runner. Install on a dedicated, disposable Linux scanner host."""

import argparse
import hashlib
import os
import re
import signal
import subprocess
import tempfile
import threading
import time
from pathlib import Path

import httpx

from app.packages import runtime_compose, validate_compose
from app.security import github_repository


def safe_report(root, relative):
    candidate = root / relative
    if candidate.is_symlink():
        raise ValueError("Report symlinks are not allowed")
    path = candidate.resolve()
    if root.resolve() not in path.parents or not path.is_file() or path.is_symlink():
        raise ValueError("Report must be a regular file inside its report directory")
    if path.stat().st_size > 5_000_000:
        raise ValueError("Report exceeds 5 MB")
    return path.read_text(errors="replace")


class Agent:
    def __init__(self, url, token, trusted, directory, timeout=900):
        self.client = httpx.Client(
            base_url=url.rstrip("/"),
            headers={"Authorization": "Bearer " + token},
            timeout=30,
            follow_redirects=False,
            trust_env=False,
        )
        self.trusted = set(trusted)
        self.directory = Path(directory).resolve()
        self.directory.mkdir(parents=True, exist_ok=True)
        self.timeout = timeout

    def run(self, job):
        cancelled = threading.Event()
        finished = threading.Event()
        jid, lease = job["id"], job["lease"]

        def heartbeat():
            while not finished.wait(20):
                try:
                    result = self.client.post(f"/api/runner/jobs/{jid}/heartbeat", json={"lease": lease})
                    if result.status_code != 200:
                        cancelled.set()
                        return
                except httpx.HTTPError:
                    cancelled.set()
                    return

        pulse = threading.Thread(target=heartbeat, daemon=True)
        pulse.start()
        status, report = "failed", ""
        try:
            source = job["compose"]
            sha = hashlib.sha256(source.encode()).hexdigest()
            if sha != job["sha256"] or sha not in self.trusted:
                raise ValueError("Scanner digest is not trusted locally")
            validate_compose(source, job["report_path"])
            github_repository(job["repository"])
            if not re.fullmatch(r"[A-Za-z0-9_./-]{1,200}", job["ref"]) or job["ref"].startswith("-"):
                raise ValueError("Invalid Git ref")
            with tempfile.TemporaryDirectory(prefix="scan-", dir=self.directory) as tmp:
                root = Path(tmp)
                src, reports = root / "source", root / "reports"
                reports.mkdir()
                reports.chmod(0o777)
                # Scanner subprocesses receive no controller token, SSH keys,
                # cloud credentials, .env files, or host environment variables.
                env = {
                    "PATH": os.environ.get("PATH", "/usr/local/bin:/usr/bin:/bin"),
                    "HOME": str(root),
                    "GIT_TERMINAL_PROMPT": "0",
                    "SOURCE_DIR": str(src),
                    "REPORT_DIR": str(reports),
                    "HTTP_PROXY": "",
                    "HTTPS_PROXY": "",
                    "NO_PROXY": "",
                }
                settings = job.get("settings", {})
                proxy = settings.get("proxy", "")
                if proxy:
                    env.update(HTTP_PROXY=proxy, HTTPS_PROXY=proxy, NO_PROXY=settings.get("no_proxy", ""))
                git_env = dict(env)
                credential = self.client.post(f"/api/runner/jobs/{jid}/github-token", json={"lease": lease})
                if credential.status_code == 200:
                    # Token stays in askpass process environment; never in args,
                    # repository URL, Compose document, report, or log.
                    askpass = root / "askpass.sh"
                    askpass.write_text(
                        '#!/bin/sh\ncase "$1" in *Username*) printf "%s" x-access-token;; *) printf "%s" "$CHECKMAYO_GIT_TOKEN";; esac\n'
                    )
                    askpass.chmod(0o700)
                    git_env.update(GIT_ASKPASS=str(askpass), CHECKMAYO_GIT_TOKEN=credential.json()["token"])
                result = subprocess.run(
                    [
                        "git",
                        "-c",
                        "protocol.file.allow=never",
                        "clone",
                        "--no-checkout",
                        "--depth=1",
                        "--",
                        job["repository"],
                        str(src),
                    ],
                    env=git_env,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    timeout=120,
                )
                if result.returncode:
                    raise RuntimeError("Repository clone failed")
                # No hooks, submodules, LFS helpers, or repository code are run.
                result = subprocess.run(
                    [
                        "git",
                        "-C",
                        str(src),
                        "-c",
                        "protocol.file.allow=never",
                        "fetch",
                        "--depth=1",
                        "origin",
                        job["ref"],
                    ],
                    env=git_env,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    timeout=120,
                )
                if result.returncode:
                    raise RuntimeError("Git ref fetch failed")
                subprocess.run(
                    ["git", "-C", str(src), "-c", "core.hooksPath=/dev/null", "checkout", "--detach", "FETCH_HEAD"],
                    env=git_env,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    timeout=30,
                    check=True,
                )
                git_env.pop("CHECKMAYO_GIT_TOKEN", None)
                if (root / "askpass.sh").exists():
                    (root / "askpass.sh").unlink()
                # Docker registry auth is operator-owned on this dedicated VM.
                env["DOCKER_CONFIG"] = os.getenv("CHECKMAYO_DOCKER_CONFIG", str(Path.home() / ".docker"))
                compose = root / "compose.yaml"
                compose.write_text(
                    runtime_compose(source, registry=settings.get("registry", ""), cpus="1.0", memory="512m")
                )
                project = "checkmayo-" + str(jid)
                base = ["docker", "compose", "--project-name", project, "--file", str(compose)]
                try:
                    pulled = subprocess.run(
                        base + ["pull"],
                        env=env,
                        cwd=root,
                        stdin=subprocess.DEVNULL,
                        stdout=subprocess.DEVNULL,
                        stderr=subprocess.DEVNULL,
                        timeout=180,
                    )
                    if pulled.returncode:
                        raise RuntimeError("Image pull failed")
                    process = subprocess.Popen(
                        base + ["up", "--abort-on-container-exit", "--exit-code-from", "scanner"],
                        env=env,
                        cwd=root,
                        stdin=subprocess.DEVNULL,
                        stdout=subprocess.DEVNULL,
                        stderr=subprocess.DEVNULL,
                        start_new_session=True,
                    )
                    started = time.monotonic()
                    while process.poll() is None:
                        if cancelled.wait(1) or time.monotonic() - started > self.timeout:
                            os.killpg(process.pid, signal.SIGTERM)
                            try:
                                process.wait(10)
                            except subprocess.TimeoutExpired:
                                os.killpg(process.pid, signal.SIGKILL)
                                process.wait()
                            raise RuntimeError("Job cancelled or timed out")
                    report = safe_report(reports, job["report_path"])
                    # Most scanners use a nonzero code for findings. Presence of
                    # a valid report is the completion contract, not a clean scan.
                    status = "completed"
                finally:
                    subprocess.run(
                        base + ["down", "--volumes", "--remove-orphans"],
                        env=env,
                        cwd=root,
                        stdin=subprocess.DEVNULL,
                        stdout=subprocess.DEVNULL,
                        stderr=subprocess.DEVNULL,
                        timeout=60,
                    )
        except Exception as error:
            print(f"Job {jid}: {type(error).__name__}; inspect runner configuration locally", flush=True)
        finally:
            finished.set()
            pulse.join(timeout=2)
        if not cancelled.is_set():
            self.client.post(
                f"/api/runner/jobs/{jid}/complete", json={"lease": lease, "status": status, "report": report}
            ).raise_for_status()
        return status

    def poll(self):
        response = self.client.post("/api/runner/poll")
        response.raise_for_status()
        job = response.json().get("job")
        if job:
            self.run(job)
        return bool(job)


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--url", default=os.getenv("CHECKMAYO_URL", ""))
    p.add_argument("--token-file", type=Path, required=True)
    p.add_argument("--trust-digest", action="append", default=[])
    p.add_argument("--trust-file", type=Path)
    p.add_argument("--workdir", default="/var/lib/checkmayo-runner")
    p.add_argument("--once", action="store_true")
    args = p.parse_args()
    if not args.url.startswith(("https://", "http://localhost:", "http://127.0.0.1:")):
        p.error("Controller URL must use HTTPS (HTTP allowed only on loopback)")
    if args.token_file.stat().st_mode & 0o077:
        p.error("Token file must have mode 600")
    trusted = args.trust_digest + (args.trust_file.read_text().splitlines() if args.trust_file else [])
    agent = Agent(args.url, args.token_file.read_text().strip(), trusted, args.workdir)
    while True:
        try:
            agent.poll()
        except httpx.HTTPError:
            print("Controller unavailable or credential disabled; retrying", flush=True)
        if args.once:
            break
        time.sleep(10)


if __name__ == "__main__":
    main()
