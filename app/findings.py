import hashlib
import json

from fastapi import APIRouter, HTTPException, Request
from sqlalchemy import select

from app.db import Audit, Finding, Package, Policy, Session, now
from app.schemas import PolicyInput
from app.security import owner_access, workspace_access

router = APIRouter()


def parse_report(report):
    try:
        data = json.loads(report)
    except (ValueError, RecursionError):
        return []
    rows = []
    if isinstance(data, list):  # Gitleaks
        for f in data[:10000]:
            if not isinstance(f, dict):
                continue
            rows.append(
                {
                    "title": str(f.get("Description", f.get("RuleID", "Exposed secret"))),
                    "rule": str(f.get("RuleID", "secret")),
                    "severity": "High",
                    "path": str(f.get("File", "")),
                    "line": f.get("StartLine", 0),
                }
            )
    elif isinstance(data, dict) and "results" in data and isinstance(data["results"], list):  # Semgrep
        for f in data["results"][:10000]:
            extra = f.get("extra", {})
            rows.append(
                {
                    "title": str(extra.get("message", f.get("check_id", "Finding"))),
                    "rule": str(f.get("check_id", "")),
                    "severity": {"ERROR": "High", "WARNING": "Medium", "INFO": "Low"}.get(
                        extra.get("severity"), "Info"
                    ),
                    "path": str(f.get("path", "")),
                    "line": f.get("start", {}).get("line", 0),
                }
            )
    elif isinstance(data, dict) and isinstance(data.get("Results"), list):  # Trivy
        for target in data["Results"][:1000]:
            for f in (target.get("Vulnerabilities", []) or []) + (target.get("Misconfigurations", []) or []):
                rows.append(
                    {
                        "title": str(f.get("Title", f.get("VulnerabilityID", f.get("ID", "Finding")))),
                        "rule": str(f.get("VulnerabilityID", f.get("ID", ""))),
                        "severity": str(f.get("Severity", "Info")).title(),
                        "path": str(target.get("Target", "")),
                        "line": 0,
                    }
                )
                if len(rows) >= 10000:
                    return rows
    elif isinstance(data, dict) and isinstance(data.get("runs"), list):  # SARIF
        for run in data["runs"][:100]:
            for f in run.get("results", [])[:10000]:
                location = (f.get("locations") or [{}])[0].get("physicalLocation", {})
                rows.append(
                    {
                        "title": str(f.get("message", {}).get("text", "Finding")),
                        "rule": str(f.get("ruleId", "")),
                        "severity": {"error": "High", "warning": "Medium", "note": "Low"}.get(f.get("level"), "Info"),
                        "path": str(location.get("artifactLocation", {}).get("uri", "")),
                        "line": location.get("region", {}).get("startLine", 0),
                    }
                )
                if len(rows) >= 10000:
                    return rows
    return rows[:10000]


def ingest_findings(db, job):
    package = db.get(Package, job.package_id)
    try:
        rows = parse_report(job.report)
    except (AttributeError, TypeError, ValueError):
        # Unknown or malformed report shapes are retained as downloadable reports;
        # they are never treated as zero vulnerabilities for policy purposes.
        return
    for row in rows:
        line = row["line"] if isinstance(row["line"], int) and 0 <= row["line"] <= 2_000_000 else 0
        fingerprint = hashlib.sha256(
            json.dumps([job.repository, package.name, row["rule"], row["path"], line]).encode()
        ).hexdigest()
        existing = db.scalar(
            select(Finding).where(Finding.workspace_id == job.workspace_id, Finding.fingerprint == fingerprint)
        )
        if existing:
            existing.job_id = job.id
            existing.seen = now()
            continue
        db.add(
            Finding(
                workspace_id=job.workspace_id,
                job_id=job.id,
                fingerprint=fingerprint,
                scanner=package.name,
                title=row["title"][:300],
                severity=row["severity"][:20],
                rule=row["rule"][:200],
                path=row["path"][:500],
                line=line,
            )
        )


@router.get("/api/workspaces/{wid}/findings")
def findings(wid: int, request: Request):
    with Session() as db:
        workspace_access(request, db, wid)
        return [
            {
                k: getattr(f, k)
                for k in ("id", "job_id", "title", "severity", "scanner", "rule", "path", "line", "status", "seen")
            }
            for f in db.scalars(
                select(Finding).where(Finding.workspace_id == wid).order_by(Finding.id.desc()).limit(500)
            )
        ]


@router.post("/api/workspaces/{wid}/findings/{fid}/triage")
async def triage(wid: int, fid: int, request: Request):
    data = await request.json()
    status = data.get("status")
    if status not in ("open", "accepted_risk", "false_positive", "resolved"):
        raise HTTPException(422, "Use open, accepted_risk, false_positive or resolved")
    with Session() as db:
        user, _ = workspace_access(request, db, wid, True)
        finding = db.get(Finding, fid)
        if not finding or finding.workspace_id != wid:
            raise HTTPException(404, "Finding not found")
        finding.status = status
        db.add(Audit(workspace_id=wid, user_id=user.id, action="finding.triage", detail=f"{fid}:{status}"))
        db.commit()
    return {"status": status}


@router.get("/api/workspaces/{wid}/policy")
def policy_get(wid: int, request: Request):
    with Session() as db:
        workspace_access(request, db, wid)
        row = db.scalar(select(Policy).where(Policy.workspace_id == wid))
        return (
            {"source": row.source, "version": row.version, "enabled": row.enabled}
            if row
            else {"source": "", "version": 0, "enabled": False}
        )


@router.put("/api/workspaces/{wid}/policy")
def policy_put(wid: int, data: PolicyInput, request: Request):
    import os

    if os.getenv("CHECKMAYO_MODE", "controller") == "registry":
        raise HTTPException(403, "Store and evaluate policies on your own controller")
    from app.policy import evaluate_policy

    with Session() as db:
        user = owner_access(request, db, wid)
        evaluate_policy(data.source, data.input)
        row = db.scalar(select(Policy).where(Policy.workspace_id == wid))
        if row:
            row.source = data.source
            row.version += 1
        else:
            row = Policy(workspace_id=wid, source=data.source)
            db.add(row)
        row.enabled = data.enabled
        db.add(Audit(workspace_id=wid, user_id=user.id, action="policy.save"))
        db.commit()
        return {"saved": True, "version": row.version}


@router.post("/api/workspaces/{wid}/findings/{fid}/policy")
async def policy_finding(wid: int, fid: int, request: Request):
    from app.policy import evaluate_policy

    body = await request.json()
    with Session() as db:
        owner_access(request, db, wid)
        finding = db.get(Finding, fid)
        policy = db.scalar(select(Policy).where(Policy.workspace_id == wid, Policy.enabled.is_(True)))
        if not finding or finding.workspace_id != wid:
            raise HTTPException(404, "Finding not found")
        if not policy:
            raise HTTPException(409, "Save a triage policy first")
        return evaluate_policy(
            policy.source,
            {
                "finding": {
                    "title": finding.title,
                    "severity": finding.severity,
                    "status": finding.status,
                    "scanner": finding.scanner,
                },
                "asset": body.get("asset", {}),
            },
        )
