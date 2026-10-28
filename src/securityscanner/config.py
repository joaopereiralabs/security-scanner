"""Small validated settings surface; no arbitrary Nmap switches."""

import os
from pathlib import Path

from pydantic import Field

from securityscanner.core.models import Model

DEFAULT_PORTS = [22, 80, 443, 8080, 8443]


class Settings(Model):
    timeout: int = Field(default=90, ge=5, le=300)
    max_rate: int = Field(default=10, ge=1, le=20)


def data_directory() -> Path:
    explicit = os.environ.get("SECURITYSCANNER_DATA_DIR")
    if explicit:
        return Path(explicit).expanduser().resolve()
    base = Path(os.environ.get("XDG_DATA_HOME", str(Path.home() / ".local" / "share")))
    return base / "securityscanner"


def parse_ports(value: str) -> list[int]:
    parts = value.split(",")
    if not 1 <= len(parts) <= 32 or any(not x.isascii() or not x.isdigit() for x in parts):
        raise ValueError("Use 1–32 comma-separated TCP ports; ranges are not accepted.")
    ports = sorted({int(x) for x in parts})
    if any(x < 1 or x > 65535 for x in ports):
        raise ValueError("TCP ports must be between 1 and 65535.")
    return ports
