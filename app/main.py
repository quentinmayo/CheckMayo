import asyncio
import hmac
import json
import os
import secrets
from contextlib import asynccontextmanager
from datetime import timedelta
from pathlib import Path

from croniter import croniter
from fastapi import FastAPI, HTTPException, Request, Response
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from sqlalchemy import func, or_, select, update
from sqlalchemy.exc import IntegrityError

from app.config import encrypt
from app.db import (
    Audit,
    Base,
    Credential,
    Integration,
    Job,
    Member,
    Package,
    Runner,
    Schedule,
    Session,
    User,
    Workspace,
    engine,
    now,
)
from app.packages import validate_compose
from app.schemas import (
    Account,
    CompleteInput,
    IntegrationInput,
    JobInput,
    MemberInput,
    PackageInput,
    RunnerInput,
    ScheduleInput,
    WorkspaceInput,
)
from app.security import authenticate, digest, endpoint, issue, owner_access, passwords, runner_access, workspace_access

STATIC = Path(__file__).parent / "static"


def audit(db, workspace_id, user_id, action, detail=""):
    if workspace_id is not None:
        db.add(Audit(workspace_id=workspace_id, user_id=user_id, action=action, detail=detail[:250]))


def public_package(p):
    return {
        k: getattr(p, k)
        for k in (
            "id",
            "name",
            "version",
            "description",
            "category",
            "sha256",
            "visibility",
            "approved",
            "report_path",
            "scan_type",
            "workspace_id",
        )
    }


def visible_package(db, workspace_id, package_id):
    p = db.get(Package, package_id)
    if not p or not (p.workspace_id == workspace_id or (p.visibility == "community" and p.approved)):
        raise HTTPException(404, "Scanner package not found")
    return p


def new_workspace(db, user, name, kind="personal"):
    workspace = Workspace(name=name, owner_id=user.id, kind=kind)
    db.add(workspace)
    db.flush()
    db.add(Member(workspace_id=workspace.id, user_id=user.id, role="owner"))
    return workspace


def seed(db):
    email = os.getenv("CHECKMAYO_ADMIN_EMAIL")
    password = os.getenv("CHECKMAYO_ADMIN_PASSWORD")
    admin = db.scalar(select(User).where(User.email == email.lower())) if email else None
    if email and password and not admin:
        if len(password) < 16:
            raise RuntimeError("Administrator bootstrap password must have at least 16 characters")
        admin = User(email=email.lower(), password=passwords.hash(password), site_admin=True)
        db.add(admin)
        db.flush()
        new_workspace(db, admin, "CheckMayo community", "organization")
        db.commit()
    if admin:
        # Withdraw the broken starter without changing its immutable Compose source or digest.
        db.execute(
            update(Package)
            .where(
                Package.workspace_id.is_(None),
                Package.name == "Semgrep starter",
                Package.version == "1.180.0",
            )
            .values(approved=False)
        )
        for path in (Path(__file__).parent.parent / "scanners").glob("*.json"):
            manifest = json.loads(path.read_text())
            existing = db.scalar(
                select(Package).where(
                    Package.name == manifest["name"],
                    Package.version == manifest["version"],
                    Package.workspace_id.is_(None),
                )
            )
            if not existing:
                source = path.with_suffix(".yaml").read_text()
                _, sha = validate_compose(source, manifest["report_path"])
                db.add(
                    Package(
                        author_id=admin.id,
                        workspace_id=None,
                        compose=source,
                        sha256=sha,
                        visibility="community",
                        approved=True,
                        **manifest,
                    )
                )
        db.commit()


async def tick():
    while True:
        await asyncio.sleep(15)
        with Session() as db:
            # Requeue expired leases, using an atomic transition so late completion cannot win.
            db.execute(
                update(Job)
                .where(Job.status == "running", Job.lease_expires < now())
                .values(status="queued", runner_id=None, lease=None, lease_expires=None)
            )
            for schedule in db.scalars(
                select(Schedule).where(Schedule.enabled.is_(True), Schedule.next_run <= now())
            ).all():
                # A conditional update prevents duplicate cron dispatch across replicas.
                next_run = croniter(schedule.cron, now()).get_next(type(now()))
                claimed = db.execute(
                    update(Schedule)
                    .where(Schedule.id == schedule.id, Schedule.next_run == schedule.next_run)
                    .values(next_run=next_run)
                ).rowcount
                if claimed:
                    db.add(
                        Job(
                            workspace_id=schedule.workspace_id,
                            package_id=schedule.package_id,
                            repository=schedule.repository,
                            ref=schedule.ref,
                            label=schedule.label,
                            trigger="cron",
                        )
                    )
            db.commit()


@asynccontextmanager
async def lifespan(_):
    Base.metadata.create_all(engine)
    with Session() as db:
        seed(db)
    task = asyncio.create_task(tick())
    yield
    task.cancel()
    try:
        await task
    except asyncio.CancelledError:
        pass


app = FastAPI(
    title="CheckMayo API",
    version="0.1.0",
    description="Bring your scanners. Own your security program.",
    lifespan=lifespan,
)
app.mount("/static", StaticFiles(directory=STATIC), name="static")


@app.middleware("http")
async def guards(request, call_next):
    if request.method == "POST" and request.url.path.startswith("/api/auth/"):
        from app.limits import auth_limit

        if not auth_limit(request):
            return Response(
                '{"detail":"Too many attempts. Try again later."}',
                status_code=429,
                media_type="application/json",
                headers={"Retry-After": "60"},
            )
    if int(request.headers.get("content-length", "0") or 0) > 6_000_000:
        return Response(status_code=413)
    # Count streamed data too: Content-Length is not trusted.
    received = 0
    original_receive = request._receive

    async def limited_receive():
        nonlocal received
        message = await original_receive()
        received += len(message.get("body", b""))
        if received > 6_000_000:
            raise HTTPException(413, "Request too large")
        return message

    request._receive = limited_receive
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Referrer-Policy"] = "same-origin"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
    if request.url.path in ("/", "/app"):
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; style-src 'self'; script-src 'self'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'"
        )
    if request.url.path.startswith("/api"):
        response.headers["Cache-Control"] = "no-store"
    return response


@app.get("/", include_in_schema=False)
@app.get("/app", include_in_schema=False)
def home():
    return FileResponse(STATIC / "index.html")


@app.get("/health")
def health():
    with Session() as db:
        db.execute(select(1))
    return {"status": "ok", "version": "0.1.0"}


@app.get("/api/config")
def config():
    return {
        "signup": os.getenv("CHECKMAYO_SIGNUP", "true") == "true",
        "mode": os.getenv("CHECKMAYO_MODE", "controller"),
        "oidc": bool(os.getenv("OIDC_CLIENT_ID")),
        "ldap": bool(os.getenv("LDAP_URL")),
        "donation_url": os.getenv("CHECKMAYO_DONATION_URL", ""),
        "repository": "https://github.com/quentinmayo/CheckMayo",
    }


@app.post("/api/auth/signup", status_code=201)
def signup(data: Account):
    if os.getenv("CHECKMAYO_SIGNUP", "true") != "true":
        raise HTTPException(403, "Registration is disabled; ask a workspace administrator")
    with Session() as db:
        user = User(email=data.email, password=passwords.hash(data.password))
        try:
            db.add(user)
            db.flush()
            new_workspace(db, user, data.email.split("@")[0] + "'s workspace")
            db.commit()
        except IntegrityError:
            db.rollback()
            raise HTTPException(409, "Account already exists")
    return {"registered": True}


@app.post("/api/auth/login")
def login(data: Account, response: Response):
    with Session() as db:
        user = db.scalar(select(User).where(User.email == data.email))
        try:
            valid = passwords.verify(
                user.password if user else passwords.hash("invalid-account-placeholder"), data.password
            )
        except Exception:
            valid = False
        if not user or not valid:
            raise HTTPException(401, "Email or password incorrect")
        token = issue(db, user.id)
        response.set_cookie(
            "checkmayo_session",
            token,
            httponly=True,
            secure=os.getenv("PUBLIC_URL", "").startswith("https://"),
            samesite="lax",
            max_age=43200,
        )
        return {"email": user.email}


@app.post("/api/auth/logout")
def logout(request: Request, response: Response):
    with Session() as db:
        _, credential = authenticate(request, db)
        credential.revoked = True
        db.commit()
    response.delete_cookie("checkmayo_session")
    return {"signed_out": True}


@app.get("/api/me")
def me(request: Request):
    with Session() as db:
        user, credential = authenticate(request, db)
        rows = db.execute(
            select(Workspace, Member.role)
            .join(Member, Workspace.id == Member.workspace_id)
            .where(Member.user_id == user.id)
        ).all()
        if credential.workspace_id is not None:
            rows = [(w, role) for w, role in rows if w.id == credential.workspace_id]
        return {
            "email": user.email,
            "site_admin": user.site_admin,
            "workspaces": [{"id": w.id, "name": w.name, "kind": w.kind, "role": role} for w, role in rows],
        }


@app.post("/api/workspaces", status_code=201)
def workspace_create(data: WorkspaceInput, request: Request):
    with Session() as db:
        user, _ = authenticate(request, db)
        w = new_workspace(db, user, data.name, data.kind)
        db.commit()
        return {"id": w.id}


@app.post("/api/workspaces/{wid}/members")
def member_create(wid: int, data: MemberInput, request: Request):
    with Session() as db:
        actor = owner_access(request, db, wid)
        user = db.scalar(select(User).where(User.email == data.email.lower()))
        if not user:
            raise HTTPException(404, "The person must register before being added")
        member = db.scalar(select(Member).where(Member.workspace_id == wid, Member.user_id == user.id))
        if member and member.role == "owner":
            raise HTTPException(409, "Workspace owner cannot be reassigned here")
        if member:
            member.role = data.role
        else:
            db.add(Member(workspace_id=wid, user_id=user.id, role=data.role))
        audit(db, wid, actor.id, "member.set", str(user.id))
        db.commit()
    return {"saved": True}


@app.get("/api/workspaces/{wid}/keys")
def keys(wid: int, request: Request):
    with Session() as db:
        user = owner_access(request, db, wid)
        return [
            {"id": k.id, "name": k.name, "expires": k.expires, "revoked": k.revoked}
            for k in db.scalars(
                select(Credential).where(
                    Credential.workspace_id == wid, Credential.user_id == user.id, Credential.kind == "api"
                )
            )
        ]


@app.post("/api/workspaces/{wid}/keys")
def key_create(wid: int, request: Request):
    with Session() as db:
        user = owner_access(request, db, wid)
        token = issue(db, user.id, kind="api", workspace_id=wid, name="Workspace API")
        audit(db, wid, user.id, "key.create")
        db.commit()
        return {"token": token, "expires_in_days": 90, "note": "Shown once; store securely"}


@app.delete("/api/workspaces/{wid}/keys/{key_id}")
def key_revoke(wid: int, key_id: int, request: Request):
    with Session() as db:
        owner_access(request, db, wid)
        key = db.get(Credential, key_id)
        if not key or key.workspace_id != wid or key.kind != "api":
            raise HTTPException(404, "Key not found")
        key.revoked = True
        db.commit()
    return {"revoked": True}


@app.get("/api/registry")
def registry(q: str = "", category: str = ""):
    with Session() as db:
        statement = select(Package).where(Package.visibility == "community", Package.approved.is_(True))
        if q:
            statement = statement.where(
                or_(Package.name.ilike("%" + q[:100] + "%"), Package.description.ilike("%" + q[:100] + "%"))
            )
        if category:
            statement = statement.where(Package.category == category[:40])
        return [public_package(p) for p in db.scalars(statement.limit(200))]


@app.get("/api/workspaces/{wid}/packages")
def packages(wid: int, request: Request):
    with Session() as db:
        workspace_access(request, db, wid)
        return [public_package(p) for p in db.scalars(select(Package).where(Package.workspace_id == wid).limit(200))]


@app.post("/api/workspaces/{wid}/packages", status_code=201)
def package_create(wid: int, data: PackageInput, request: Request):
    try:
        _, sha = validate_compose(data.compose, data.report_path)
    except ValueError as error:
        raise HTTPException(422, str(error)) from error
    with Session() as db:
        user, _ = workspace_access(request, db, wid, True)
        if db.scalar(select(func.count()).select_from(Package).where(Package.workspace_id == wid)) >= 200:
            raise HTTPException(409, "Workspace package limit reached")
        duplicate = db.scalar(
            select(Package).where(
                Package.workspace_id == wid, Package.name == data.name, Package.version == data.version
            )
        )
        if duplicate:
            raise HTTPException(409, "Versions are immutable; publish a new version")
        p = Package(workspace_id=wid, author_id=user.id, sha256=sha, **data.model_dump())
        db.add(p)
        audit(db, wid, user.id, "package.publish", sha)
        db.commit()
        return public_package(p)


@app.post("/api/admin/packages/{pid}/approve")
def package_approve(pid: int, request: Request):
    with Session() as db:
        user, credential = authenticate(request, db)
        if not user.site_admin or credential.workspace_id is not None:
            raise HTTPException(403, "Site administrator required")
        p = db.get(Package, pid)
        if not p:
            raise HTTPException(404, "Package not found")
        p.approved = True
        audit(db, p.workspace_id, user.id, "package.approve", p.sha256)
        db.commit()
    return {"approved": True}


@app.post("/api/admin/packages/{pid}/withdraw")
def package_withdraw(pid: int, request: Request):
    with Session() as db:
        user, credential = authenticate(request, db)
        if not user.site_admin or credential.workspace_id is not None:
            raise HTTPException(403, "Site administrator session required")
        package = db.get(Package, pid)
        if not package or package.visibility != "community":
            raise HTTPException(404, "Community package not found")
        package.approved = False
        audit(db, package.workspace_id, user.id, "package.withdraw", package.sha256)
        db.commit()
    return {"approved": False}


@app.get("/api/admin/packages/{pid}/source")
def package_review_source(pid: int, request: Request):
    with Session() as db:
        user, credential = authenticate(request, db)
        if not user.site_admin or credential.workspace_id is not None:
            raise HTTPException(403, "Site administrator session required")
        package = db.get(Package, pid)
        if not package or package.visibility != "community":
            raise HTTPException(404, "Community package not found")
        return {"compose": package.compose, "sha256": package.sha256}


@app.get("/api/packages/{pid}/download")
def package_download(pid: int, request: Request):
    with Session() as db:
        p = db.get(Package, pid)
        if not p:
            raise HTTPException(404, "Package not found")
        if not (p.visibility == "community" and p.approved):
            workspace_access(request, db, p.workspace_id)
        return Response(
            p.compose,
            media_type="application/yaml",
            headers={
                "Content-Disposition": f'attachment; filename="scanner-{p.id}.compose.yaml"',
                "X-Checksum-SHA256": p.sha256,
            },
        )


@app.get("/api/workspaces/{wid}/runners")
def runners(wid: int, request: Request):
    with Session() as db:
        workspace_access(request, db, wid)
        return [
            {
                "id": r.id,
                "name": r.name,
                "location": r.location,
                "labels": json.loads(r.labels),
                "max_jobs": r.max_jobs,
                "enabled": r.enabled,
                "heartbeat": r.heartbeat,
                "online": r.heartbeat > now() - timedelta(seconds=90),
            }
            for r in db.scalars(select(Runner).where(Runner.workspace_id == wid))
        ]


@app.post("/api/workspaces/{wid}/runners", status_code=201)
def runner_create(wid: int, data: RunnerInput, request: Request):
    if os.getenv("CHECKMAYO_MODE", "controller") == "registry":
        raise HTTPException(403, "Deploy your own controller to enroll runners")
    with Session() as db:
        user = owner_access(request, db, wid)
        token = "cmr_" + secrets.token_urlsafe(32)
        runner = Runner(
            workspace_id=wid,
            digest=digest(token),
            **data.model_dump(exclude={"labels"}),
            labels=json.dumps(data.labels),
        )
        db.add(runner)
        audit(db, wid, user.id, "runner.enroll")
        db.commit()
        return {
            "id": runner.id,
            "token": token,
            "note": "Shown once. Runner connects outbound; no inbound VM port required.",
        }


@app.post("/api/workspaces/{wid}/runners/{rid}/toggle")
def runner_toggle(wid: int, rid: int, request: Request):
    with Session() as db:
        user = owner_access(request, db, wid)
        runner = db.get(Runner, rid)
        if not runner or runner.workspace_id != wid:
            raise HTTPException(404, "Runner not found")
        runner.enabled = not runner.enabled
        audit(db, wid, user.id, "runner.toggle", str(rid))
        db.commit()
        return {"enabled": runner.enabled}


@app.post("/api/workspaces/{wid}/jobs", status_code=201)
def job_create(wid: int, data: JobInput, request: Request):
    if os.getenv("CHECKMAYO_MODE", "controller") == "registry":
        raise HTTPException(403, "Run scans from your own controller")
    with Session() as db:
        user, _ = workspace_access(request, db, wid, True)
        visible_package(db, wid, data.package_id)
        job = Job(workspace_id=wid, **data.model_dump())
        db.add(job)
        audit(db, wid, user.id, "job.queue")
        db.commit()
        return {"id": job.id}


@app.get("/api/workspaces/{wid}/jobs")
def jobs(wid: int, request: Request):
    with Session() as db:
        workspace_access(request, db, wid)
        return [
            {
                k: getattr(j, k)
                for k in (
                    "id",
                    "package_id",
                    "repository",
                    "ref",
                    "label",
                    "status",
                    "trigger",
                    "runner_id",
                    "created",
                    "finished",
                    "error",
                )
            }
            for j in db.scalars(select(Job).where(Job.workspace_id == wid).order_by(Job.id.desc()).limit(100))
        ]


@app.get("/api/workspaces/{wid}/jobs/{jid}/report")
def job_report(wid: int, jid: int, request: Request):
    with Session() as db:
        workspace_access(request, db, wid)
        job = db.get(Job, jid)
        if not job or job.workspace_id != wid:
            raise HTTPException(404, "Job not found")
        return Response(
            job.report,
            media_type="application/octet-stream",
            headers={"Content-Disposition": f'attachment; filename="job-{jid}-report"'},
        )


@app.post("/api/workspaces/{wid}/jobs/{jid}/cancel")
def job_cancel(wid: int, jid: int, request: Request):
    with Session() as db:
        user, _ = workspace_access(request, db, wid, True)
        job = db.get(Job, jid)
        if not job or job.workspace_id != wid:
            raise HTTPException(404, "Job not found")
        if job.status not in ("queued", "running"):
            raise HTTPException(409, "Job already finished")
        job.status = "cancelled"
        job.lease = None
        job.finished = now()
        audit(db, wid, user.id, "job.cancel", str(jid))
        db.commit()
    return {"cancelled": True}


@app.post("/api/runner/poll")
def runner_poll(request: Request):
    with Session() as db:
        r = runner_access(request, db)
        # Lock the runner to enforce capacity across simultaneous polls (PostgreSQL).
        db.execute(select(Runner).where(Runner.id == r.id).with_for_update())
        r.heartbeat = now()
        active = db.scalar(select(func.count()).select_from(Job).where(Job.runner_id == r.id, Job.status == "running"))
        if active >= r.max_jobs:
            db.commit()
            return {"job": None}
        labels = json.loads(r.labels)
        candidates = db.scalars(
            select(Job)
            .where(Job.workspace_id == r.workspace_id, Job.status == "queued", Job.label.in_(["", *labels]))
            .order_by(Job.id)
            .limit(20)
        ).all()
        for j in candidates:
            lease = secrets.token_urlsafe(32)
            claimed = db.execute(
                update(Job)
                .where(Job.id == j.id, Job.status == "queued")
                .values(
                    status="running", runner_id=r.id, lease=digest(lease), lease_expires=now() + timedelta(seconds=120)
                )
            ).rowcount
            if not claimed:
                continue
            p = visible_package(db, r.workspace_id, j.package_id)
            settings = json.loads(db.get(Workspace, r.workspace_id).settings)
            db.commit()
            return {
                "job": {
                    "id": j.id,
                    "lease": lease,
                    "repository": j.repository,
                    "ref": j.ref,
                    "compose": p.compose,
                    "sha256": p.sha256,
                    "report_path": p.report_path,
                    "settings": settings,
                }
            }
        db.commit()
        return {"job": None}


def leased_job(db, request, jid, lease):
    runner = runner_access(request, db)
    job = db.get(Job, jid)
    if (
        not job
        or job.runner_id != runner.id
        or job.workspace_id != runner.workspace_id
        or job.status != "running"
        or not job.lease
        or not hmac.compare_digest(job.lease, digest(lease))
        or job.lease_expires <= now()
    ):
        raise HTTPException(409, "Lease expired, cancelled, or not owned by this runner")
    return runner, job


@app.post("/api/runner/jobs/{jid}/heartbeat")
async def runner_heartbeat(jid: int, request: Request):
    data = await request.json()
    with Session() as db:
        r, job = leased_job(db, request, jid, str(data.get("lease", "")))
        r.heartbeat = now()
        job.lease_expires = now() + timedelta(seconds=120)
        db.commit()
    return {"active": True}


@app.post("/api/runner/jobs/{jid}/complete")
def runner_complete(jid: int, data: CompleteInput, request: Request):
    with Session() as db:
        r, job = leased_job(db, request, jid, data.lease)
        job.status = data.status
        job.report = data.report
        job.finished = now()
        job.lease = None
        job.error = "Scanner failed; inspect the isolated runner locally" if data.status == "failed" else ""
        if data.status == "completed":
            from app.findings import ingest_findings

            ingest_findings(db, job)
        audit(db, r.workspace_id, None, "job." + data.status, str(jid))
        db.commit()
    return {"accepted": True}


@app.post("/api/workspaces/{wid}/schedules", status_code=201)
def schedule_create(wid: int, data: ScheduleInput, request: Request):
    if os.getenv("CHECKMAYO_MODE", "controller") == "registry":
        raise HTTPException(403, "Configure schedules on your own controller")
    try:
        if len(data.cron.split()) != 5:
            raise ValueError()
        next_run = croniter(data.cron, now()).get_next(type(now()))
    except (ValueError, KeyError):
        raise HTTPException(422, "Use a valid five-field UTC cron expression")
    with Session() as db:
        user, _ = workspace_access(request, db, wid, True)
        visible_package(db, wid, data.package_id)
        row = Schedule(workspace_id=wid, next_run=next_run, **data.model_dump())
        db.add(row)
        audit(db, wid, user.id, "schedule.create")
        db.commit()
        return {"id": row.id, "next_run_utc": next_run}


@app.get("/api/workspaces/{wid}/schedules")
def schedules(wid: int, request: Request):
    with Session() as db:
        workspace_access(request, db, wid)
        return [
            {k: getattr(s, k) for k in ("id", "package_id", "repository", "cron", "label", "enabled", "next_run")}
            for s in db.scalars(select(Schedule).where(Schedule.workspace_id == wid))
        ]


@app.post("/api/workspaces/{wid}/schedules/{sid}/toggle")
def schedule_toggle(wid: int, sid: int, request: Request):
    with Session() as db:
        workspace_access(request, db, wid, True)
        s = db.get(Schedule, sid)
        if not s or s.workspace_id != wid:
            raise HTTPException(404, "Schedule not found")
        s.enabled = not s.enabled
        if s.enabled:
            s.next_run = croniter(s.cron, now()).get_next(type(now()))
        db.commit()
        return {"enabled": s.enabled}


@app.get("/api/workspaces/{wid}/settings")
def settings(wid: int, request: Request):
    with Session() as db:
        workspace_access(request, db, wid)
        return json.loads(db.get(Workspace, wid).settings)


@app.put("/api/workspaces/{wid}/settings")
async def settings_put(wid: int, request: Request):
    data = await request.json()
    if not isinstance(data, dict) or set(data) - {"registry", "proxy", "no_proxy", "ai_enabled"}:
        raise HTTPException(422, "Unsupported settings")
    if data.get("registry"):
        import re

        if not re.fullmatch(r"[A-Za-z0-9.:-]+(?:/[A-Za-z0-9._/-]+)?", data["registry"]):
            raise HTTPException(422, "Use a registry host and optional mirror prefix")
    if data.get("proxy"):
        try:
            endpoint(data["proxy"], private=True)
        except ValueError as error:
            raise HTTPException(422, str(error))
    if len(json.dumps(data)) > 4000 or ("ai_enabled" in data and not isinstance(data["ai_enabled"], bool)):
        raise HTTPException(422, "Invalid settings")
    with Session() as db:
        user = owner_access(request, db, wid)
        db.get(Workspace, wid).settings = json.dumps(data)
        audit(db, wid, user.id, "settings.update")
        db.commit()
    return {"saved": True}


@app.get("/api/workspaces/{wid}/integrations")
def integrations(wid: int, request: Request):
    with Session() as db:
        owner_access(request, db, wid)
        return [
            {"kind": i.kind, "enabled": i.enabled}
            for i in db.scalars(select(Integration).where(Integration.workspace_id == wid))
        ]


@app.put("/api/workspaces/{wid}/integrations/{kind}")
def integration_put(wid: int, kind: str, data: IntegrationInput, request: Request):
    from app.integrations import validate_integration

    if os.getenv("CHECKMAYO_MODE", "controller") == "registry":
        raise HTTPException(403, "Configure integrations on your own controller")
    try:
        validate_integration(kind, data.config)
    except ValueError as error:
        raise HTTPException(422, str(error))
    with Session() as db:
        user = owner_access(request, db, wid)
        integration = db.scalar(select(Integration).where(Integration.workspace_id == wid, Integration.kind == kind))
        if not integration:
            integration = Integration(workspace_id=wid, kind=kind, encrypted="")
            db.add(integration)
        integration.encrypted = encrypt(json.dumps(data.config))
        integration.enabled = data.enabled
        audit(db, wid, user.id, "integration.configure", kind)
        db.commit()
    return {"saved": True, "secrets": "Encrypted at rest; values are never returned by the API"}


@app.get("/api/workspaces/{wid}/audit")
def audit_list(wid: int, request: Request):
    with Session() as db:
        owner_access(request, db, wid)
        return [
            {"id": a.id, "action": a.action, "detail": a.detail, "created": a.created}
            for a in db.scalars(select(Audit).where(Audit.workspace_id == wid).order_by(Audit.id.desc()).limit(100))
        ]


# Integration and federated identity routes are registered after the core app.
from app.identity import router as identity_router
from app.integrations import router as integration_router

app.include_router(integration_router)
app.include_router(identity_router)
from app.identity import install_identity_middleware

install_identity_middleware(app)
from app.findings import router as findings_router

app.include_router(findings_router)


@app.get("/api/admin/packages/pending")
def pending_packages(request: Request):
    with Session() as db:
        user, credential = authenticate(request, db)
        if not user.site_admin or credential.workspace_id is not None:
            raise HTTPException(403, "Site administrator session required")
        return [
            public_package(p)
            for p in db.scalars(
                select(Package).where(Package.visibility == "community", Package.approved.is_(False)).limit(200)
            )
        ]
