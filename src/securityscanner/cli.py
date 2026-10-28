"""CLI boundary: explicit authorization, clear errors, meaningful exit codes."""

import importlib.metadata
import shutil
import sqlite3
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Annotated, cast

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from securityscanner import __version__
from securityscanner.config import Settings, data_directory, parse_ports
from securityscanner.core.comparison import compare as compare_scans
from securityscanner.core.orchestrator import execute
from securityscanner.reports.render import Format, write_report
from securityscanner.scanners.nmap_scanner import clean
from securityscanner.storage.database import Database

app = typer.Typer(
    invoke_without_command=True,
    no_args_is_help=True,
    help="SecurityScanner — authorized local security auditing.",
)
console = Console(highlight=False)
ERRORS = (ValueError, OSError, sqlite3.Error)


@app.callback()
def main(version: Annotated[bool, typer.Option("--version", is_eager=True)] = False) -> None:
    """SecurityScanner — Security Visibility Through Intelligent Analysis."""
    if version:
        console.print(__version__)
        raise typer.Exit()


def fail(exc: Exception) -> None:
    console.print(f"Error: {exc}", style="red", markup=False)
    raise typer.Exit(2)


@app.command()
def doctor() -> None:
    """Check runtime, dependencies, Nmap and local storage permissions."""
    console.print(
        Panel(
            f"SecurityScanner {__version__}\nJoão Pereira Labs\n"
            "Security Visibility Through Intelligent Analysis",
            border_style="blue",
        )
    )
    table = Table("Check", "Status")
    table.add_row("Python", sys.version.split()[0])
    missing = False
    for name in ["typer", "rich", "pydantic", "defusedxml", "jinja2"]:
        try:
            version = importlib.metadata.version(name)
        except importlib.metadata.PackageNotFoundError:
            version = "MISSING: reinstall with pip install ."
            missing = True
        table.add_row(name, version)
    nmap = shutil.which("nmap")
    table.add_row("Nmap", nmap or "MISSING: sudo apt install nmap (passive remains available)")
    if nmap:
        try:
            result = subprocess.run(
                [nmap, "--version"], capture_output=True, text=True, timeout=5, check=True
            )
            table.add_row("Nmap execution", clean(result.stdout.splitlines()[0]))
        except (OSError, subprocess.SubprocessError, IndexError):
            table.add_row(
                "Nmap execution", "FAILED: verify executable permissions or reinstall Nmap."
            )
            missing = True
    try:
        directory = data_directory()
        db = Database(directory)
        with tempfile.TemporaryFile(dir=directory) as stream:
            stream.write(b"permission check")
        db.history(1)
        table.add_row("Data directory / SQLite", f"Read/write OK: {directory}")
        if sys.platform != "win32" and directory.stat().st_mode & 0o077:
            table.add_row(
                "Permissions", "Directory is shared; consider chmod 700 on the data directory."
            )
    except ERRORS as exc:
        table.add_row("Storage", f"FAILED: {exc}. Set SECURITYSCANNER_DATA_DIR to a writable path.")
        missing = True
    console.print(table)
    console.print("Navigation: scan · profiles · history · report · compare · --help")
    if missing or not nmap:
        raise typer.Exit(1)


@app.command()
def profiles() -> None:
    """List implemented operations and planned profiles."""
    console.print(
        "passive: local Nmap XML import; no DNS, subprocess or target traffic.\n"
        "basic: DNS validation, sequential TCP connect scans on 1–32 specified ports; "
        "optional intensity-0 version probes. Maximum 16 resolved IPs.\n"
        "web: PLANNED for v0.3; unavailable.\n"
        "Default ports: 22,80,443,8080,8443. Concurrency: one host, one port probe. "
        "Default scan rate: 10 packets/s (Nmap scan phase; not a version probe budget)."
    )


@app.command()
def scan(
    target: Annotated[
        list[str] | None, typer.Option(help="Exact IP/hostname; repeat for each host.")
    ] = None,
    allow: Annotated[
        list[str] | None, typer.Option(help="Explicit allowed IP/hostname; repeat.")
    ] = None,
    authorized: Annotated[
        bool, typer.Option(help="Confirm you own or may audit these targets.")
    ] = False,
    profile: str = "basic",
    ports: str = "22,80,443,8080,8443",
    versions: Annotated[
        bool, typer.Option(help="Opt in to active service version probes.")
    ] = False,
    timeout: Annotated[int, typer.Option(min=5, max=300)] = 90,
    max_rate: Annotated[int, typer.Option(min=1, max=20)] = 10,
    import_xml: Annotated[
        Path | None, typer.Option(help="Complete local Nmap XML for passive import.")
    ] = None,
) -> None:
    """Run an explicitly scoped audit or import existing evidence without target traffic."""
    try:
        parsed_ports = parse_ports(ports)
        console.print(
            f"Plan: profile={profile}; targets={target or []}; allowed={allow or []}; "
            f"ports={parsed_ports if profile == 'basic' else []}; versions={versions}; "
            f"deadline={timeout}s/IP; concurrency=1; max-rate={max_rate}.",
            markup=False,
        )
        if profile == "passive":
            console.print("Operation: read local XML only; no DNS or target connections.")
        elif profile == "basic":
            console.print(
                "Operations: validate DNS, revalidate/pin IPs, TCP connect scan, local storage."
            )
            if versions:
                console.print(
                    "Opt-in version probes can send application data; no strict request budget."
                )
        result = execute(
            Database(data_directory()),
            profile=profile,
            targets=target or [],
            allowed=allow or [],
            authorized=authorized,
            ports=parsed_ports,
            settings=Settings(timeout=timeout, max_rate=max_rate),
            versions=versions,
            import_file=import_xml,
        )
        console.print(
            f"Scan {result.id}: {result.status}; {len(result.services)} open TCP services.",
            markup=False,
        )
        for service in result.services:
            console.print(
                f"  {service.address}:{service.port}/tcp {service.name} "
                f"{service.product} {service.version} ({service.detection})",
                markup=False,
            )
        if result.error:
            console.print(result.error, style="yellow", markup=False)
        if result.status != "completed":
            raise typer.Exit(130 if result.status == "cancelled" else 2)
    except ERRORS as exc:
        fail(exc)


@app.command()
def history() -> None:
    """Show the latest 50 local scans."""
    try:
        table = Table("Scan ID", "Started (UTC)", "Profile", "Status", "Services")
        for item in Database(data_directory()).history():
            table.add_row(
                item.id,
                item.started_at.isoformat(),
                item.profile,
                item.status,
                str(len(item.services)),
            )
        console.print(table)
    except ERRORS as exc:
        fail(exc)


@app.command()
def report(
    scan_id: Annotated[str, typer.Option()],
    format: str = "html",
    output: Path | None = None,
) -> None:
    """Export a local scan as HTML, JSON or Markdown; existing files are preserved."""
    try:
        if format not in {"html", "json", "markdown"}:
            raise ValueError("Use --format html, json or markdown.")
        selected = cast(Format, format)
        result = Database(data_directory()).get(scan_id)
        suffix = "md" if selected == "markdown" else selected
        destination = output or Path(f"securityscanner-{result.id}.{suffix}")
        write_report(result, selected, destination)
        console.print(f"Report saved: {destination.resolve()}", markup=False)
    except ERRORS as exc:
        fail(exc)


@app.command()
def compare(scan_a: Annotated[str, typer.Option()], scan_b: Annotated[str, typer.Option()]) -> None:
    """Compare completed scans with matching coverage; absence is not proof of remediation."""
    try:
        db = Database(data_directory())
        console.print_json(data=compare_scans(db.get(scan_a), db.get(scan_b)))
    except ERRORS as exc:
        fail(exc)


@app.command()
def ui() -> None:
    """Show TUI availability (planned for v0.5)."""
    console.print("Textual TUI is planned for v0.5. Use --help for the operational CLI.")
    raise typer.Exit(2)


if __name__ == "__main__":
    app()
