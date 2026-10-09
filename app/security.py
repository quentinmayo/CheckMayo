import hashlib
import os
import secrets
from datetime import timedelta
from urllib.parse import urlparse

from argon2 import PasswordHasher
from fastapi import HTTPException, Request
from sqlalchemy import select

from app.db import Credential, Member, Runner, User, now

passwords = PasswordHasher(time_cost=3, memory_cost=65536, parallelism=2)


def digest(value):
    return hashlib.sha256(value.encode()).hexdigest()


def issue(db, user_id, kind="session", workspace_id=None, name="Browser"):
    token = "cm_" + secrets.token_urlsafe(32)
    db.add(
        Credential(
            user_id=user_id,
            workspace_id=workspace_id,
            name=name,
            digest=digest(token),
            kind=kind,
            expires=now() + timedelta(hours=12) if kind == "session" else now() + timedelta(days=90),
        )
    )
    db.commit()
    return token


def authenticate(request: Request, db):
    authorization = request.headers.get("authorization", "")
    bearer = authorization.startswith("Bearer ")
    token = authorization[7:] if bearer else request.cookies.get("checkmayo_session", "")
    credential = db.scalar(select(Credential).where(Credential.digest == digest(token), Credential.revoked.is_(False)))
    if not credential or (credential.expires and credential.expires <= now()):
        raise HTTPException(401, "Sign in or supply a valid API key")
    if not bearer and request.method not in ("GET", "HEAD", "OPTIONS"):
        expected = os.getenv("PUBLIC_URL", "http://localhost:8000").rstrip("/")
        if request.headers.get("origin", "").rstrip("/") != expected:
            raise HTTPException(403, "Same-origin browser request required")
    return db.get(User, credential.user_id), credential


def workspace_access(request, db, workspace_id, write=False):
    user, credential = authenticate(request, db)
    if credential.workspace_id is not None and credential.workspace_id != workspace_id:
        raise HTTPException(403, "API key is scoped to another workspace")
    membership = db.scalar(select(Member).where(Member.workspace_id == workspace_id, Member.user_id == user.id))
    if not membership:
        raise HTTPException(404, "Workspace not found")
    if write and membership.role not in ("owner", "admin", "operator"):
        raise HTTPException(403, "Write permission required")
    return user, membership


def owner_access(request, db, workspace_id):
    user, membership = workspace_access(request, db, workspace_id, True)
    if membership.role not in ("owner", "admin"):
        raise HTTPException(403, "Workspace administrator required")
    return user


def runner_access(request, db):
    token = request.headers.get("authorization", "").removeprefix("Bearer ")
    runner = db.scalar(select(Runner).where(Runner.digest == digest(token), Runner.enabled.is_(True)))
    if not runner:
        raise HTTPException(401, "Runner credential invalid or disabled")
    return runner


def github_repository(value):
    import re

    if not re.fullmatch(r"https://github\.com/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+(?:\.git)?", value):
        raise ValueError("Use an HTTPS GitHub repository URL without credentials or query parameters")
    return value


def endpoint(value, private=False):
    parsed = urlparse(value)
    if (
        parsed.scheme not in ("https", "http")
        or not parsed.hostname
        or parsed.username
        or parsed.password
        or parsed.query
        or parsed.fragment
    ):
        raise ValueError("Use an HTTP(S) service URL without credentials, query, or fragment")
    if not private and parsed.scheme != "https":
        raise ValueError("Use HTTPS")
    return value.rstrip("/")
