import os
import secrets
import ssl

from authlib.integrations.starlette_client import OAuth
from fastapi import APIRouter, HTTPException, Request, Response
from sqlalchemy import select
from starlette.middleware.sessions import SessionMiddleware

from app.config import encryption_key
from app.db import Identity, Session, User
from app.security import issue, passwords

router = APIRouter()
oauth = OAuth()
if os.getenv("OIDC_CLIENT_ID"):
    oauth.register(
        name="oidc",
        client_id=os.environ["OIDC_CLIENT_ID"],
        client_secret=os.environ["OIDC_CLIENT_SECRET"],
        server_metadata_url=os.environ["OIDC_DISCOVERY_URL"],
        client_kwargs={"scope": "openid email profile"},
    )


def install_identity_middleware(app):
    app.add_middleware(
        SessionMiddleware,
        secret_key=encryption_key().decode(),
        session_cookie="checkmayo_oidc",
        https_only=os.getenv("PUBLIC_URL", "").startswith("https://"),
        same_site="lax",
        max_age=600,
    )


def federated_login(db, provider, subject, email):
    from app.main import new_workspace

    identity = db.scalar(select(Identity).where(Identity.provider == provider, Identity.subject == subject))
    if identity:
        return db.get(User, identity.user_id)
    # A matching email alone never links a new identity to an existing account.
    if db.scalar(select(User).where(User.email == email.lower())):
        raise HTTPException(409, "An account with this email already exists. Use its original sign-in method.")
    user = User(email=email.lower(), password=passwords.hash(secrets.token_urlsafe(48)))
    db.add(user)
    db.flush()
    db.add(Identity(user_id=user.id, provider=provider, subject=subject))
    new_workspace(db, user, email.split("@")[0] + "'s workspace")
    db.commit()
    return user


def session_cookie(response, token):
    response.set_cookie(
        "checkmayo_session",
        token,
        httponly=True,
        secure=os.getenv("PUBLIC_URL", "").startswith("https://"),
        samesite="lax",
        max_age=43200,
    )


@router.get("/api/auth/oidc/start")
async def oidc_start(request: Request):
    if not os.getenv("OIDC_CLIENT_ID"):
        raise HTTPException(404, "OIDC is not configured")
    return await oauth.oidc.authorize_redirect(
        request, os.environ["PUBLIC_URL"].rstrip("/") + "/api/auth/oidc/callback"
    )


@router.get("/api/auth/oidc/callback")
async def oidc_callback(request: Request):
    from fastapi.responses import RedirectResponse

    if not os.getenv("OIDC_CLIENT_ID"):
        raise HTTPException(404, "OIDC is not configured")
    try:
        token = await oauth.oidc.authorize_access_token(request)
        info = token.get("userinfo")
        if not info or info.get("email_verified") is not True or not info.get("sub") or not info.get("iss"):
            raise ValueError()
    except Exception:
        raise HTTPException(401, "OIDC validation failed; verified email required")
    with Session() as db:
        user = federated_login(db, info["iss"], info["sub"], info["email"])
        response = RedirectResponse("/app")
        session_cookie(response, issue(db, user.id))
        return response


@router.post("/api/auth/ldap")
async def ldap_login(request: Request, response: Response):
    from ldap3 import Connection, Server, Tls
    from ldap3.utils.conv import escape_filter_chars

    if not os.getenv("LDAP_URL"):
        raise HTTPException(404, "LDAP is not configured")
    body = await request.json()
    username, password = body.get("username", ""), body.get("password", "")
    if (
        not isinstance(username, str)
        or not isinstance(password, str)
        or not 1 <= len(username) <= 120
        or not 1 <= len(password) <= 128
    ):
        raise HTTPException(422, "Username and password required")
    url = os.environ["LDAP_URL"]
    if not url.startswith("ldaps://"):
        raise HTTPException(503, "LDAP requires LDAPS with certificate verification")
    server = Server(
        url, tls=Tls(validate=ssl.CERT_REQUIRED, ca_certs_file=os.getenv("LDAP_CA_FILE")), connect_timeout=10
    )
    try:
        with Connection(
            server,
            user=os.environ["LDAP_BIND_DN"],
            password=os.environ["LDAP_BIND_PASSWORD"],
            auto_bind=True,
            receive_timeout=10,
        ) as service:
            query = os.getenv("LDAP_USER_FILTER", "(uid={username})").replace(
                "{username}", escape_filter_chars(username)
            )
            service.search(os.environ["LDAP_BASE_DN"], query, attributes=["mail", "entryUUID"])
            if len(service.entries) != 1:
                raise ValueError()
            entry = service.entries[0]
            dn, email = entry.entry_dn, str(entry.mail)
            subject = str(entry.entryUUID) if "entryUUID" in entry else dn
        with Connection(server, user=dn, password=password, auto_bind=True, receive_timeout=10):
            pass
    except Exception:
        raise HTTPException(401, "Directory sign-in failed")
    with Session() as db:
        user = federated_login(db, url, subject, email)
        session_cookie(response, issue(db, user.id))
        return {"email": user.email}
