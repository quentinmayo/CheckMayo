import os
from datetime import datetime, timezone

from sqlalchemy import ForeignKey, String, Text, UniqueConstraint, create_engine, event
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, sessionmaker


class Base(DeclarativeBase):
    pass


def now():
    return datetime.now(timezone.utc).replace(tzinfo=None)


url = os.getenv("DATABASE_URL", "sqlite:///./state/checkmayo.db")
if url.startswith("sqlite"):
    os.makedirs(os.getenv("CHECKMAYO_STATE_DIR", "state"), exist_ok=True)
engine = create_engine(
    url, connect_args={"check_same_thread": False} if url.startswith("sqlite") else {}, pool_pre_ping=True
)
if url.startswith("sqlite"):

    @event.listens_for(engine, "connect")
    def configure_sqlite(connection, _):
        connection.execute("PRAGMA foreign_keys=ON")
        connection.execute("PRAGMA journal_mode=WAL")


Session = sessionmaker(engine, expire_on_commit=False)


class User(Base):
    __tablename__ = "users"
    id: Mapped[int] = mapped_column(primary_key=True)
    email: Mapped[str] = mapped_column(String(254), unique=True)
    password: Mapped[str] = mapped_column(Text)
    site_admin: Mapped[bool] = mapped_column(default=False)
    created: Mapped[datetime] = mapped_column(default=now)


class Workspace(Base):
    __tablename__ = "workspaces"
    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(120))
    owner_id: Mapped[int] = mapped_column(ForeignKey("users.id"))
    kind: Mapped[str] = mapped_column(default="personal")
    settings: Mapped[str] = mapped_column(Text, default="{}")


class Member(Base):
    __tablename__ = "members"
    __table_args__ = (UniqueConstraint("workspace_id", "user_id"),)
    id: Mapped[int] = mapped_column(primary_key=True)
    workspace_id: Mapped[int] = mapped_column(ForeignKey("workspaces.id"))
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"))
    role: Mapped[str] = mapped_column(String(20))


class Credential(Base):
    __tablename__ = "credentials"
    id: Mapped[int] = mapped_column(primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"))
    workspace_id: Mapped[int | None] = mapped_column(ForeignKey("workspaces.id"), nullable=True)
    name: Mapped[str] = mapped_column(String(120))
    digest: Mapped[str] = mapped_column(String(64), unique=True)
    kind: Mapped[str] = mapped_column(String(20))
    expires: Mapped[datetime | None] = mapped_column(nullable=True)
    revoked: Mapped[bool] = mapped_column(default=False)


class Package(Base):
    __tablename__ = "packages"
    id: Mapped[int] = mapped_column(primary_key=True)
    workspace_id: Mapped[int | None] = mapped_column(ForeignKey("workspaces.id"), nullable=True)
    author_id: Mapped[int] = mapped_column(ForeignKey("users.id"))
    name: Mapped[str] = mapped_column(String(100))
    version: Mapped[str] = mapped_column(String(40))
    description: Mapped[str] = mapped_column(Text)
    category: Mapped[str] = mapped_column(String(40), default="SAST")
    compose: Mapped[str] = mapped_column(Text)
    sha256: Mapped[str] = mapped_column(String(64))
    report_path: Mapped[str] = mapped_column(String(200), default="report.json")
    scan_type: Mapped[str] = mapped_column(String(120), default="SARIF")
    visibility: Mapped[str] = mapped_column(default="private")
    approved: Mapped[bool] = mapped_column(default=False)
    created: Mapped[datetime] = mapped_column(default=now)


class Runner(Base):
    __tablename__ = "runners"
    id: Mapped[int] = mapped_column(primary_key=True)
    workspace_id: Mapped[int] = mapped_column(ForeignKey("workspaces.id"))
    name: Mapped[str] = mapped_column(String(120))
    location: Mapped[str] = mapped_column(String(120))
    labels: Mapped[str] = mapped_column(Text, default="[]")
    max_jobs: Mapped[int] = mapped_column(default=1)
    digest: Mapped[str] = mapped_column(String(64), unique=True)
    enabled: Mapped[bool] = mapped_column(default=True)
    heartbeat: Mapped[datetime] = mapped_column(default=now)


class Job(Base):
    __tablename__ = "jobs"
    id: Mapped[int] = mapped_column(primary_key=True)
    workspace_id: Mapped[int] = mapped_column(ForeignKey("workspaces.id"))
    package_id: Mapped[int] = mapped_column(ForeignKey("packages.id"))
    runner_id: Mapped[int | None] = mapped_column(ForeignKey("runners.id"), nullable=True)
    repository: Mapped[str] = mapped_column(String(300))
    ref: Mapped[str] = mapped_column(String(200), default="HEAD")
    label: Mapped[str] = mapped_column(String(120), default="")
    status: Mapped[str] = mapped_column(default="queued")
    trigger: Mapped[str] = mapped_column(default="manual")
    lease: Mapped[str | None] = mapped_column(String(64), nullable=True)
    lease_expires: Mapped[datetime | None] = mapped_column(nullable=True)
    report: Mapped[str] = mapped_column(Text, default="")
    error: Mapped[str] = mapped_column(String(250), default="")
    created: Mapped[datetime] = mapped_column(default=now)
    finished: Mapped[datetime | None] = mapped_column(nullable=True)


class Schedule(Base):
    __tablename__ = "schedules"
    id: Mapped[int] = mapped_column(primary_key=True)
    workspace_id: Mapped[int] = mapped_column(ForeignKey("workspaces.id"))
    package_id: Mapped[int] = mapped_column(ForeignKey("packages.id"))
    repository: Mapped[str] = mapped_column(String(300))
    ref: Mapped[str] = mapped_column(String(200), default="HEAD")
    label: Mapped[str] = mapped_column(String(120), default="")
    cron: Mapped[str] = mapped_column(String(100))
    next_run: Mapped[datetime] = mapped_column()
    enabled: Mapped[bool] = mapped_column(default=True)


class Integration(Base):
    __tablename__ = "integrations"
    __table_args__ = (UniqueConstraint("workspace_id", "kind"),)
    id: Mapped[int] = mapped_column(primary_key=True)
    workspace_id: Mapped[int] = mapped_column(ForeignKey("workspaces.id"))
    kind: Mapped[str] = mapped_column(String(40))
    encrypted: Mapped[str] = mapped_column(Text)
    enabled: Mapped[bool] = mapped_column(default=True)


class Delivery(Base):
    __tablename__ = "deliveries"
    id: Mapped[str] = mapped_column(String(100), primary_key=True)
    created: Mapped[datetime] = mapped_column(default=now)


class Audit(Base):
    __tablename__ = "audit"
    id: Mapped[int] = mapped_column(primary_key=True)
    workspace_id: Mapped[int] = mapped_column(ForeignKey("workspaces.id"))
    user_id: Mapped[int | None] = mapped_column(nullable=True)
    action: Mapped[str] = mapped_column(String(100))
    detail: Mapped[str] = mapped_column(String(250), default="")
    created: Mapped[datetime] = mapped_column(default=now)


class Identity(Base):
    __tablename__ = "identities"
    __table_args__ = (UniqueConstraint("provider", "subject"),)
    id: Mapped[int] = mapped_column(primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"))
    provider: Mapped[str] = mapped_column(String(300))
    subject: Mapped[str] = mapped_column(String(300))


class RateWindow(Base):
    __tablename__ = "rate_windows"
    key: Mapped[str] = mapped_column(String(100), primary_key=True)
    count: Mapped[int] = mapped_column(default=1)
    expires: Mapped[datetime] = mapped_column(index=True)


class Finding(Base):
    __tablename__ = "findings"
    __table_args__ = (UniqueConstraint("workspace_id", "fingerprint"),)
    id: Mapped[int] = mapped_column(primary_key=True)
    workspace_id: Mapped[int] = mapped_column(ForeignKey("workspaces.id"))
    job_id: Mapped[int] = mapped_column(ForeignKey("jobs.id"))
    fingerprint: Mapped[str] = mapped_column(String(64))
    title: Mapped[str] = mapped_column(String(300))
    severity: Mapped[str] = mapped_column(String(20))
    scanner: Mapped[str] = mapped_column(String(100))
    rule: Mapped[str] = mapped_column(String(200))
    path: Mapped[str] = mapped_column(String(500))
    line: Mapped[int] = mapped_column(default=0)
    status: Mapped[str] = mapped_column(default="open")
    seen: Mapped[datetime] = mapped_column(default=now)
    created: Mapped[datetime] = mapped_column(default=now)


class Policy(Base):
    __tablename__ = "policies"
    id: Mapped[int] = mapped_column(primary_key=True)
    workspace_id: Mapped[int] = mapped_column(ForeignKey("workspaces.id"), unique=True)
    source: Mapped[str] = mapped_column(Text)
    version: Mapped[int] = mapped_column(default=1)
    enabled: Mapped[bool] = mapped_column(default=True)
