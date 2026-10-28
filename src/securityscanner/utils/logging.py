import json
import os
from pathlib import Path

from securityscanner.core.models import now


def audit(directory: Path, event: str, scan_id: str, **details: object) -> None:
    directory.mkdir(parents=True, exist_ok=True, mode=0o700)
    record = {"time": now().isoformat(), "event": event, "scan_id": scan_id, **details}
    fd = os.open(directory / "audit.jsonl", os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
    with os.fdopen(fd, "a", encoding="utf-8") as stream:
        stream.write(json.dumps(record, ensure_ascii=True) + "\n")
