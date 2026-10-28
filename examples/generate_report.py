"""Regenerate deterministic documentation reports using explicitly synthetic evidence."""

from datetime import UTC, datetime
from pathlib import Path

from securityscanner.analyzers.findings import analyze
from securityscanner.core.models import Scan
from securityscanner.reports.render import Format, render
from securityscanner.scanners.nmap_scanner import parse_xml

directory = Path(__file__).parent
timestamp = datetime(2026, 1, 1, tzinfo=UTC)
scan = Scan(
    id="SYNTHETIC-EXAMPLE-NOT-A-REAL-AUDIT",
    started_at=timestamp,
    finished_at=timestamp,
    profile="passive",
    targets=[],
    allowed=[],
    status="completed",
    limitations=[
        "SYNTHETIC DOCUMENTATION DATA — not a real audit or an assertion about a real system.",
        "Imported scope, original capture date and authorization are not verified.",
        "No HTTP/TLS analysis or CVE correlation was performed.",
    ],
)
scan.services = parse_xml((directory / "synthetic-nmap.xml").read_bytes())
scan.findings = analyze(scan.services)
for finding in scan.findings:
    finding.detected_at = timestamp
formats: list[Format] = ["html", "json", "markdown"]
for format in formats:
    suffix = "md" if format == "markdown" else format
    (directory / f"synthetic-report.{suffix}").write_text(render(scan, format), encoding="utf-8")
