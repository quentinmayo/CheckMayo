import re

from pydantic import BaseModel, Field, field_validator

from app.security import github_repository


class Account(BaseModel):
    email: str = Field(max_length=254)
    password: str = Field(min_length=12, max_length=128)

    @field_validator("email")
    @classmethod
    def email_valid(cls, value):
        value = value.strip().lower()
        if not re.fullmatch(r"[^\s@]+@[^\s@]+\.[^\s@]+", value):
            raise ValueError("Valid email required")
        return value


class WorkspaceInput(BaseModel):
    name: str = Field(min_length=2, max_length=120)
    kind: str = "personal"

    @field_validator("kind")
    @classmethod
    def kind_valid(cls, value):
        if value not in ("personal", "organization"):
            raise ValueError("Use personal or organization")
        return value


class PackageInput(BaseModel):
    name: str = Field(min_length=2, max_length=100, pattern=r"^[a-zA-Z0-9][a-zA-Z0-9 ._-]+$")
    version: str = Field(max_length=40, pattern=r"^[a-zA-Z0-9_.-]+$")
    description: str = Field(max_length=2000)
    category: str = Field(max_length=40, default="SAST")
    compose: str = Field(max_length=65536)
    report_path: str = Field(max_length=200, default="report.json")
    scan_type: str = Field(max_length=120, default="SARIF")
    visibility: str = "private"

    @field_validator("visibility")
    @classmethod
    def visible(cls, value):
        if value not in ("private", "community"):
            raise ValueError("Use private or community")
        return value


class RunnerInput(BaseModel):
    name: str = Field(min_length=2, max_length=120)
    location: str = Field(max_length=120, default="homelab")
    labels: list[str] = Field(max_length=20, default_factory=list)
    max_jobs: int = Field(ge=1, le=8, default=1)


class JobInput(BaseModel):
    package_id: int
    repository: str = Field(max_length=300)
    ref: str = Field(max_length=200, default="HEAD", pattern=r"^[A-Za-z0-9_./-]+$")
    label: str = Field(max_length=120, default="")
    _repository = field_validator("repository")(github_repository)


class ScheduleInput(JobInput):
    cron: str = Field(max_length=100)


class CompleteInput(BaseModel):
    lease: str
    status: str
    report: str = Field(max_length=5_000_000, default="")

    @field_validator("status")
    @classmethod
    def status_valid(cls, value):
        if value not in ("completed", "failed"):
            raise ValueError("Use completed or failed")
        return value


class IntegrationInput(BaseModel):
    config: dict
    enabled: bool = True


class MemberInput(BaseModel):
    email: str
    role: str

    @field_validator("role")
    @classmethod
    def role_valid(cls, value):
        if value not in ("admin", "operator", "viewer"):
            raise ValueError("Use admin, operator or viewer")
        return value


class PolicyInput(BaseModel):
    source: str = Field(max_length=65536)
    input: dict = Field(default_factory=dict)
