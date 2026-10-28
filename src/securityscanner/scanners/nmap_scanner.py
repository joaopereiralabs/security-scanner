"""Controlled TCP connect scans and defensive XML ingestion."""

import ipaddress
import shutil
import subprocess
import tempfile
from pathlib import Path

from defusedxml import ElementTree
from defusedxml.common import DefusedXmlException
from pydantic import ValidationError

from securityscanner.config import Settings
from securityscanner.core.models import Service
from securityscanner.core.scope import canonical

MAX_XML = 8 * 1024 * 1024


class ScanError(RuntimeError):
    """Scanner failure with an actionable, non-sensitive message."""


def clean(value: str) -> str:
    return "".join(c for c in value if c.isprintable())[:256]


def parse_xml(data: bytes) -> list[Service]:
    if len(data) > MAX_XML:
        raise ScanError("XML exceeds the 8 MiB import limit.")
    try:
        root = ElementTree.fromstring(data, forbid_entities=True, forbid_external=True)
    except (ElementTree.ParseError, DefusedXmlException) as exc:
        raise ScanError("Invalid or unsafe Nmap XML; export a complete -oX result.") from exc
    if root.tag != "nmaprun":
        raise ScanError("Expected an Nmap XML document.")
    finished = root.find("runstats/finished")
    if finished is None or finished.get("exit") != "success":
        raise ScanError("Incomplete or failed Nmap result; absence of ports is not reliable.")
    services: dict[str, Service] = {}
    try:
        for host in root.findall("host"):
            if host.get("timedout") == "true":
                raise ScanError("Nmap host timed out; result is incomplete.")
            for address in host.findall("address"):
                if address.get("addrtype") not in {"ipv4", "ipv6"}:
                    continue
                ip = str(ipaddress.ip_address(address.attrib["addr"]))
                for port in host.findall("ports/port"):
                    state = port.find("state")
                    if port.get("protocol") != "tcp" or state is None:
                        continue
                    if state.get("state") != "open":
                        continue
                    service = port.find("service")
                    fields = {} if service is None else service.attrib
                    method = fields.get("method", "unknown")
                    item = Service(
                        address=ip,
                        port=int(port.attrib["portid"]),
                        name=clean(fields.get("name", "unknown")),
                        product=clean(fields.get("product", "")),
                        version=clean(fields.get("version", "")),
                        detection="probed"
                        if method == "probed"
                        else ("table" if method == "table" else "unknown"),
                    )
                    services[item.key] = item
    except (ValueError, KeyError, ValidationError) as exc:
        raise ScanError("Malformed IP, port or service in Nmap XML.") from exc
    return sorted(services.values(), key=lambda x: (x.address, x.port))


def read_xml(path: Path) -> bytes:
    if not path.is_file():
        raise ScanError("Import must be an existing regular local XML file.")
    with path.open("rb") as stream:
        data = stream.read(MAX_XML + 1)
    if len(data) > MAX_XML:
        raise ScanError("XML exceeds the 8 MiB import limit.")
    return data


def build_command(address: str, ports: list[int], settings: Settings, versions: bool) -> list[str]:
    ip = ipaddress.ip_address(canonical(address))
    if (
        not ports
        or len(ports) > 32
        or any(type(p) is not int or not 1 <= p <= 65535 for p in ports)
    ):
        raise ValueError("Provide 1–32 valid TCP ports.")
    executable = shutil.which("nmap")
    if executable is None:
        raise ScanError("Nmap is missing. On Kali/Debian/Ubuntu: sudo apt install nmap")
    command = [
        executable,
        "-sT",
        "-Pn",
        "-n",
        "--unprivileged",
        "--disable-arp-ping",
        "--max-rate",
        str(settings.max_rate),
        "--max-parallelism",
        "1",
        "--max-retries",
        "1",
        "--host-timeout",
        f"{settings.timeout}s",
        "-p",
        ",".join(map(str, ports)),
        "-oX",
        "-",
    ]
    if versions:
        command += ["-sV", "--version-intensity", "0"]
    if ip.version == 6:
        command += ["-6"]
    return [*command, str(ip)]


def run_command(command: list[str], timeout: int) -> list[Service]:
    # Disk-backed output avoids unbounded pipe buffers. Raw banners never enter history.
    with tempfile.TemporaryFile() as out, tempfile.TemporaryFile() as err:
        try:
            process = subprocess.Popen(command, stdout=out, stderr=err, shell=False)
        except OSError as exc:
            raise ScanError("Unable to start Nmap; run securityscanner doctor.") from exc
        try:
            process.wait(timeout=timeout)
        except (subprocess.TimeoutExpired, KeyboardInterrupt) as exc:
            process.kill()
            process.wait(timeout=5)
            if isinstance(exc, KeyboardInterrupt):
                raise
            raise ScanError(
                "Nmap exceeded its deadline; process was stopped. Reduce scope."
            ) from exc
        if process.returncode:
            raise ScanError(
                f"Nmap exited with code {process.returncode}; check doctor and routing."
            )
        out.seek(0)
        return parse_xml(out.read(MAX_XML + 1))
