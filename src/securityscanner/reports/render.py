import html
import os
from pathlib import Path
from typing import Literal

from jinja2 import Environment, FileSystemLoader, select_autoescape

from securityscanner.core.models import Scan, Severity

Format = Literal["html", "json", "markdown"]


def summary(scan: Scan) -> dict[str, int]:
    return {level.value: sum(f.severity == level for f in scan.findings) for level in Severity}


def md(value: object) -> str:
    text = html.escape(str(value), quote=True)
    for char in "\\`*_{}[]()#+-.!|":
        text = text.replace(char, "\\" + char)
    return text.replace("\r", " ").replace("\n", " ")


def render(scan: Scan, format: Format) -> str:
    if format == "json":
        return scan.model_dump_json(indent=2) + "\n"
    if format == "html":
        env = Environment(
            loader=FileSystemLoader(Path(__file__).parent / "templates"),
            autoescape=select_autoescape(["html"]),
        )
        return env.get_template("report.html").render(scan=scan, counts=summary(scan))
    if format != "markdown":
        raise ValueError("Supported formats: html, json, markdown.")
    lines = [
        "# SecurityScanner audit",
        "",
        "João Pereira Labs",
        "",
        f"ID: {md(scan.id)}",
        f"Started: {md(scan.started_at)}",
        f"Finished: {md(scan.finished_at)}",
        f"Duration: {scan.duration_seconds} seconds",
        f"Profile: {scan.profile}; Status: {scan.status}",
        f"Authorization confirmed: {scan.authorized}",
        f"Allowed scope: {md(scan.allowed)}",
        f"Targets: {md(scan.targets)}",
        f"Resolved scope: {md(scan.pinned)}",
        f"Ports: {md(scan.ports)}; Version probes: {scan.versions}",
        "",
        "## Executive summary",
        "",
        f"{len(scan.services)} open TCP services observed.",
        "Open services alone are not confirmed vulnerabilities.",
        md(summary(scan)),
        "",
        "## Services",
        "",
        "| Address | Port | Service | Product | Version | Method |",
        "|---|---|---|---|---|---|",
    ]
    for s in scan.services:
        lines.append(
            "| "
            + " | ".join(
                md(x) for x in (s.address, s.port, s.name, s.product, s.version, s.detection)
            )
            + " |"
        )
    lines += ["", "## Findings", ""]
    for f in sorted(scan.findings, key=lambda x: list(Severity).index(x.severity)):
        lines += [f"### {md(f.severity)} — {md(f.title)}", ""]
        lines += [f"- {key}: {md(value)}" for key, value in f.model_dump().items()]
        lines.append("")
    lines += ["## Limitations and inconclusive checks", ""]
    lines += [f"- {md(x)}" for x in scan.limitations]
    if scan.error:
        lines.append(f"- Error: {md(scan.error)}")
    return "\n".join(lines) + "\n"


def write_report(scan: Scan, format: Format, output: Path) -> None:
    content = render(scan, format)
    # Never overwrite an existing report without the operator choosing another filename.
    fd = os.open(output, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as stream:
        stream.write(content)
