import subprocess
from unittest.mock import Mock, patch

import pytest

from securityscanner.config import Settings, parse_ports
from securityscanner.scanners.nmap_scanner import (
    MAX_XML,
    ScanError,
    build_command,
    parse_xml,
    read_xml,
    run_command,
)


def test_parser(xml):
    services = parse_xml(xml)
    assert len(services) == 1
    assert services[0].address == "192.0.2.10"
    assert services[0].port == 443
    assert services[0].product == "Synthetic Example Server"
    assert services[0].detection == "probed"


@pytest.mark.parametrize(
    "data",
    [
        b"<broken",
        b"<x/>",
        b"<nmaprun/>",
        b'<!DOCTYPE nmaprun [<!ENTITY x SYSTEM "file:///etc/passwd">]><nmaprun>&x;</nmaprun>',
        b'<!DOCTYPE nmaprun [<!ENTITY x "boom">]><nmaprun>&x;</nmaprun>',
    ],
)
def test_reject_bad_xml(data):
    with pytest.raises(ScanError):
        parse_xml(data)


@pytest.mark.parametrize(
    ("old", "new"),
    [
        (b'portid="443"', b'portid="70000"'),
        (b'addr="192.0.2.10"', b'addr="invalid"'),
        (b'exit="success"', b'exit="error"'),
        (b"<host>", b'<host timedout="true">'),
    ],
)
def test_malformed_or_incomplete(xml, old, new):
    with pytest.raises(ScanError):
        parse_xml(xml.replace(old, new))


def test_ignores_scripts_and_uncertain_ports(xml):
    data = xml.replace(b"<ports>", b'<script output="secret"/><ports>')
    assert "secret" not in str(parse_xml(data))
    assert parse_xml(xml.replace(b'state="open"', b'state="open|filtered"')) == []
    assert parse_xml(xml.replace(b'protocol="tcp"', b'protocol="udp"')) == []


def test_size_limit(tmp_path):
    path = tmp_path / "large.xml"
    path.write_bytes(b" " * (MAX_XML + 1))
    with pytest.raises(ScanError):
        read_xml(path)


def test_import_rejects_directory(tmp_path):
    with pytest.raises(ScanError, match="regular"):
        read_xml(tmp_path)


@pytest.mark.parametrize("ports", ["", "0", "65536", "1-100", "22;id", "８０", ",80", "80, 81"])
def test_invalid_ports(ports):
    with pytest.raises(ValueError):
        parse_ports(ports)


def test_ports():
    assert parse_ports("443,22,22") == [22, 443]
    with pytest.raises(ValueError):
        parse_ports(",".join(map(str, range(1, 34))))


def test_command_is_pinned_and_fixed():
    with patch("shutil.which", return_value="/usr/bin/nmap"):
        command = build_command("::1", [443], Settings(), True)
    assert command[-1] == "::1"
    assert "-6" in command and "-sT" in command and "-n" in command
    assert "-sV" in command and "--unprivileged" in command
    assert command[command.index("--version-intensity") + 1] == "0"


def test_missing_nmap():
    with patch("shutil.which", return_value=None):
        with pytest.raises(ScanError, match="apt install nmap"):
            build_command("127.0.0.1", [80], Settings(), False)


@pytest.mark.parametrize(
    "interruption", [subprocess.TimeoutExpired("nmap", 5), KeyboardInterrupt()]
)
def test_process_cleanup(interruption):
    process = Mock()
    process.wait.side_effect = [interruption, 0]
    with patch("subprocess.Popen", return_value=process) as popen:
        with pytest.raises(
            KeyboardInterrupt if isinstance(interruption, KeyboardInterrupt) else ScanError
        ):
            run_command(["nmap"], 5)
        assert popen.call_args.kwargs["shell"] is False
    process.kill.assert_called_once()
    assert process.wait.call_count == 2


def test_process_failure():
    process = Mock(returncode=1)
    with patch("subprocess.Popen", return_value=process):
        with pytest.raises(ScanError, match="exited"):
            run_command(["nmap"], 5)
