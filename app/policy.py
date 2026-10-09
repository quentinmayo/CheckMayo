"""Pure, bounded Rego evaluation using an administrator-provided OPA binary."""

import json
import shutil
import subprocess
import sys
import tempfile
import threading
from pathlib import Path

from fastapi import HTTPException

slot = threading.BoundedSemaphore(1)


def evaluate_policy(source, data):
    if not source.lstrip().startswith("package checkmayo.triage"):
        raise HTTPException(422, "Policy must use package checkmayo.triage and define result")
    encoded = json.dumps(data).encode()
    if len(encoded) > 1_000_000:
        raise HTTPException(413, "Policy input exceeds 1 MB")
    opa = shutil.which("opa")
    if not opa:
        raise HTTPException(503, "Install the OPA binary or use the provided controller image")
    if not slot.acquire(blocking=False):
        raise HTTPException(429, "Policy evaluator busy")
    try:
        with tempfile.TemporaryDirectory(prefix="checkmayo-policy-") as folder:
            root = Path(folder)
            (root / "policy.rego").write_text(source)
            (root / "input.json").write_bytes(encoded)
            env = {
                "PATH": "/usr/local/bin:/usr/bin:/bin",
                "HOME": folder,
                "TMPDIR": folder,
                "GOMAXPROCS": "1",
                "GOMEMLIMIT": "128MiB",
            }
            capabilities = Path(__file__).with_name("opa-capabilities.json")
            if not capabilities.exists():
                raise HTTPException(503, "Restricted OPA capabilities are unavailable")
            args = [
                sys.executable,
                str(Path(__file__).with_name("policy_process.py")),
                opa,
                "eval",
                "--format=json",
                "--capabilities",
                str(capabilities),
                "--data",
                str(root / "policy.rego"),
                "--input",
                str(root / "input.json"),
                "data.checkmayo.triage.result",
            ]
            with (root / "output").open("w+b") as output:
                result = subprocess.run(
                    args,
                    cwd=root,
                    env=env,
                    stdin=subprocess.DEVNULL,
                    stdout=output,
                    stderr=subprocess.DEVNULL,
                    timeout=8,
                )
                output.seek(0)
                content = output.read(1_000_001)
            if result.returncode or len(content) > 1_000_000:
                raise HTTPException(422, "Policy is invalid or exceeded execution limits")
            body = json.loads(content)
            rows = body.get("result", [])
            return {"result": rows[0]["expressions"][0]["value"] if rows else None}
    except subprocess.TimeoutExpired:
        raise HTTPException(422, "Policy execution exceeded eight seconds")
    finally:
        slot.release()
