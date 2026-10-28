"""Versioned interchange models. Observations are never proof of compromise."""

from datetime import UTC, datetime
from enum import StrEnum
from typing import Literal
from uuid import uuid4

from pydantic import BaseModel, ConfigDict, Field


def now() -> datetime:
    return datetime.now(UTC)


class Model(BaseModel):
    model_config = ConfigDict(extra="forbid", validate_assignment=True)


class Severity(StrEnum):
    CRITICAL = "Critical"
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"
    INFORMATIONAL = "Informational"


class Service(Model):
    address: str
    port: int = Field(ge=1, le=65535)
    protocol: Literal["tcp"] = "tcp"
    name: str = "unknown"
    product: str = ""
    version: str = ""
    detection: Literal["table", "probed", "unknown"] = "unknown"

    @property
    def key(self) -> str:
        return f"{self.address}|{self.protocol}|{self.port}"


class Finding(Model):
    identifier: str
    title: str
    description: str
    evidence: str
    asset: str
    severity: Severity = Severity.INFORMATIONAL
    confidence: Literal["low", "medium", "high"] = "medium"
    kind: Literal["confirmed", "potential", "information", "inconclusive"] = "information"
    impact: str
    recommendation: str
    references: list[str] = Field(default_factory=list)
    detected_at: datetime = Field(default_factory=now)
    source: str = "nmap"

    @property
    def key(self) -> str:
        return f"{self.identifier}|{self.asset}"


class Scan(Model):
    schema_version: Literal[1] = 1
    id: str = Field(default_factory=lambda: str(uuid4()))
    started_at: datetime = Field(default_factory=now)
    finished_at: datetime | None = None
    profile: Literal["basic", "passive"]
    targets: list[str]
    allowed: list[str]
    authorized: bool = False
    pinned: dict[str, list[str]] = Field(default_factory=dict)
    ports: list[int] = Field(default_factory=list)
    versions: bool = False
    status: Literal["running", "completed", "failed", "cancelled"] = "running"
    services: list[Service] = Field(default_factory=list)
    findings: list[Finding] = Field(default_factory=list)
    commands: list[list[str]] = Field(default_factory=list)
    limitations: list[str] = Field(default_factory=list)
    error: str | None = None

    @property
    def duration_seconds(self) -> float | None:
        if self.finished_at is None:
            return None
        return (self.finished_at - self.started_at).total_seconds()
