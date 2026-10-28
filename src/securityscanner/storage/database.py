import sqlite3
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

from securityscanner.core.models import Scan


class Database:
    def __init__(self, directory: Path):
        directory.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.path = directory / "history.sqlite3"
        # Create private files before connecting, including on a shared parent directory.
        self.path.touch(mode=0o600, exist_ok=True)
        with self.connect() as connection:
            version = connection.execute("PRAGMA user_version").fetchone()[0]
            if version not in (0, 1):
                raise ValueError(
                    "Unsupported history schema; use a compatible SecurityScanner version."
                )
            connection.execute(
                "CREATE TABLE IF NOT EXISTS scans ("
                "id TEXT PRIMARY KEY, started_at TEXT NOT NULL, payload TEXT NOT NULL)"
            )
            connection.execute("PRAGMA user_version=1")

    @contextmanager
    def connect(self) -> Iterator[sqlite3.Connection]:
        connection = sqlite3.connect(self.path, timeout=5)
        try:
            with connection:
                yield connection
        finally:
            connection.close()

    def save(self, scan: Scan) -> None:
        with self.connect() as connection:
            connection.execute(
                "INSERT INTO scans VALUES (?, ?, ?) ON CONFLICT(id) DO UPDATE SET "
                "payload=excluded.payload",
                (scan.id, scan.started_at.isoformat(), scan.model_dump_json()),
            )

    def get(self, identifier: str) -> Scan:
        with self.connect() as connection:
            row = connection.execute(
                "SELECT payload FROM scans WHERE id=?", (identifier,)
            ).fetchone()
        if row is None:
            raise ValueError("Scan ID not found. Run securityscanner history.")
        return Scan.model_validate_json(row[0])

    def history(self, limit: int = 50) -> list[Scan]:
        with self.connect() as connection:
            rows = connection.execute(
                "SELECT payload FROM scans ORDER BY started_at DESC LIMIT ?", (limit,)
            ).fetchall()
        return [Scan.model_validate_json(row[0]) for row in rows]
