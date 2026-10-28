"""One task at a time; persist lifecycle before and after scanner execution."""

from pathlib import Path

from securityscanner.analyzers.findings import analyze
from securityscanner.config import Settings
from securityscanner.core.models import Scan, now
from securityscanner.core.scope import Scope
from securityscanner.scanners.nmap_scanner import (
    ScanError,
    build_command,
    parse_xml,
    read_xml,
    run_command,
)
from securityscanner.storage.database import Database
from securityscanner.utils.logging import audit


def execute(
    database: Database,
    *,
    profile: str,
    targets: list[str],
    allowed: list[str],
    authorized: bool,
    ports: list[int],
    settings: Settings,
    versions: bool = False,
    import_file: Path | None = None,
) -> Scan:
    if profile not in {"basic", "passive"}:
        raise ValueError(
            "Profile not implemented. Available: basic, passive. Web is planned for v0.3."
        )
    if profile == "passive" and (
        import_file is None or targets or allowed or authorized or versions
    ):
        raise ValueError(
            "Passive requires --import-xml only; omit targets and active scan options."
        )
    if profile == "basic" and import_file is not None:
        raise ValueError("--import-xml requires the passive profile.")
    scan = Scan(
        profile="basic" if profile == "basic" else "passive",
        targets=targets,
        allowed=allowed,
        authorized=authorized,
        ports=ports if profile == "basic" else [],
        versions=versions,
        limitations=[
            "Observations are not proof of compromise. No CVE correlation is performed.",
            "No HTTP/TLS configuration analysis or independent host discovery is implemented.",
        ],
    )
    database.save(scan)
    directory = database.path.parent
    try:
        audit(directory, "started", scan.id, profile=profile)
        if profile == "passive":
            assert import_file is not None
            scan.limitations.append(
                "Imported observations are unverified historical evidence; "
                "import time is not scan time."
            )
            scan.services = parse_xml(read_xml(import_file))
        else:
            scope = Scope(allowed, authorized)
            scan.pinned = scope.approve(targets)
            database.save(scan)
            audit(directory, "scope_approved", scan.id, pins=scan.pinned, allowed=allowed)
            scan.limitations.append(
                "Only explicitly selected TCP ports were tested. "
                "Empty results do not prove a host is down."
            )
            if versions:
                scan.limitations.append(
                    "Version probes are opt-in and intensity 0; Nmap rate limits do not bound all "
                    "version-detection traffic. Banners can be inaccurate "
                    "and contain sensitive text."
                )
            visited: set[str] = set()
            for hostname, addresses in scan.pinned.items():
                for address in addresses:
                    if address in visited:
                        continue
                    scope.revalidate(hostname)
                    command = build_command(address, ports, settings, versions)
                    scan.commands.append(command)
                    database.save(scan)
                    audit(directory, "command", scan.id, argv=command)
                    services = run_command(command, settings.timeout)
                    if any(s.address != address or s.port not in ports for s in services):
                        raise ScanError("Nmap returned an endpoint outside the approved task.")
                    scan.services.extend(services)
                    visited.add(address)
        scan.status = "completed"
    except KeyboardInterrupt:
        scan.status = "cancelled"
        scan.error = "Cancelled by operator; partial results do not establish absence of services."
    except (ValueError, OSError, ScanError) as exc:
        scan.status = "failed"
        scan.error = str(exc)
    finally:
        scan.findings = analyze(scan.services)
        scan.finished_at = now()
        database.save(scan)
        audit(directory, scan.status, scan.id, error=scan.error)
    return scan
