import subprocess
from unittest.mock import Mock, patch

import pytest
from typer.testing import CliRunner

from securityscanner.analyzers.findings import analyze
from securityscanner.cli import app
from securityscanner.config import Settings
from securityscanner.core.comparison import compare
from securityscanner.core.models import Finding, Scan, Service, Severity
from securityscanner.core.orchestrator import execute
from securityscanner.reports.render import render, write_report
from securityscanner.storage.database import Database


def arguments(tmp_path):
    return {
        "database": Database(tmp_path),
        "profile": "basic",
        "targets": ["127.0.0.1"],
        "allowed": ["127.0.0.1"],
        "authorized": True,
        "ports": [443],
        "settings": Settings(),
    }


def test_out_of_scope_never_executes(tmp_path):
    args = arguments(tmp_path)
    args["targets"] = ["192.0.2.10"]
    with patch("securityscanner.core.orchestrator.run_command") as run:
        result = execute(**args)
    assert result.status == "failed"
    run.assert_not_called()
    assert Database(tmp_path).get(result.id).status == "failed"


def test_missing_authorization_never_executes(tmp_path):
    args = arguments(tmp_path)
    args["authorized"] = False
    with patch("securityscanner.core.orchestrator.run_command") as run:
        result = execute(**args)
    assert result.status == "failed"
    run.assert_not_called()


def test_passive_no_dns_or_process(tmp_path, xml):
    path = tmp_path / "input.xml"
    path.write_bytes(xml)
    args = arguments(tmp_path)
    args.update(profile="passive", targets=[], allowed=[], authorized=False, import_file=path)
    with (
        patch("socket.getaddrinfo", side_effect=AssertionError("DNS forbidden")),
        patch("subprocess.Popen", side_effect=AssertionError("process forbidden")),
    ):
        result = execute(**args)
    assert result.status == "completed"
    assert len(result.services) == 1
    assert not result.commands and not result.pinned
    assert Database(tmp_path).get(result.id) == result
    assert '"event": "completed"' in (tmp_path / "audit.jsonl").read_text()


def test_rebinding_never_executes(tmp_path):
    args = arguments(tmp_path)
    args.update(targets=["example.test"], allowed=["example.test"])
    with (
        patch(
            "securityscanner.core.scope.Scope.addresses",
            side_effect=[
                {"192.0.2.1"},
                {"192.0.2.2"},
            ],
        ),
        patch("securityscanner.core.orchestrator.run_command") as run,
    ):
        result = execute(**args)
    assert result.status == "failed" and "DNS changed" in result.error
    run.assert_not_called()


def test_cancel_persisted(tmp_path):
    with (
        patch("securityscanner.core.orchestrator.build_command", return_value=["nmap"]),
        patch("securityscanner.core.orchestrator.run_command", side_effect=KeyboardInterrupt),
    ):
        result = execute(**arguments(tmp_path))
    assert result.status == "cancelled"
    assert result.finished_at is not None
    assert Database(tmp_path).get(result.id).status == "cancelled"


def test_outside_result_rejected(tmp_path):
    with (
        patch("securityscanner.core.orchestrator.build_command", return_value=["nmap"]),
        patch(
            "securityscanner.core.orchestrator.run_command",
            return_value=[
                Service(address="192.0.2.10", port=443),
            ],
        ),
    ):
        result = execute(**arguments(tmp_path))
    assert result.status == "failed" and result.services == []


def test_database_lookup_and_schema(tmp_path):
    db = Database(tmp_path)
    with pytest.raises(ValueError, match="not found"):
        db.get("' OR 1=1 --")
    with db.connect() as connection:
        connection.execute("PRAGMA user_version=99")
    with pytest.raises(ValueError, match="Unsupported"):
        Database(tmp_path)


def test_analysis_does_not_invent_vulnerability():
    findings = analyze([Service(address="192.0.2.1", port=22, version="old")])
    assert findings[0].severity == Severity.INFORMATIONAL
    assert findings[0].kind == "information"
    assert not findings[0].references
    assert "CVE-" not in findings[0].model_dump_json()


def test_reports_escaping_roundtrip(tmp_path):
    attack = "<script>alert(1)</script>[link](javascript:alert(1))"
    scan = Scan(profile="passive", targets=[], allowed=[], status="completed")
    scan.services = [Service(address="192.0.2.1", port=80, product=attack)]
    scan.findings = analyze(scan.services)
    assert Scan.model_validate_json(render(scan, "json")) == scan
    html = render(scan, "html")
    assert "<script>" not in html and "&lt;script&gt;" in html
    assert "cdn" not in html
    markdown = render(scan, "markdown")
    assert "<script>" not in markdown and "[link]" not in markdown
    path = tmp_path / "report.html"
    write_report(scan, "html", path)
    with pytest.raises(FileExistsError):
        write_report(scan, "html", path)


def test_finding_validation():
    with pytest.raises(ValueError):
        Finding(
            identifier="x",
            title="x",
            description="x",
            evidence="x",
            asset="x",
            impact="x",
            recommendation="x",
            severity="fake",
        )


def test_comparison():
    a = Scan(
        profile="basic",
        targets=["127.0.0.1"],
        allowed=["127.0.0.1"],
        ports=[80, 443],
        pinned={"127.0.0.1": ["127.0.0.1"]},
        status="completed",
    )
    a.services = [Service(address="127.0.0.1", port=80)]
    a.findings = analyze(a.services)
    b = a.model_copy(deep=True)
    b.services = [Service(address="127.0.0.1", port=443)]
    b.findings = analyze(b.services)
    result = compare(a, b)
    assert result["new_services"] == ["127.0.0.1|tcp|443"]
    assert result["services_no_longer_observed"] == ["127.0.0.1|tcp|80"]
    assert len(result["new_findings"]) == 1
    assert len(compare(a, a)["persistent_findings"]) == 1
    b.ports = [443]
    with pytest.raises(ValueError, match="must match"):
        compare(a, b)
    b.status = "failed"
    with pytest.raises(ValueError, match="completed"):
        compare(a, b)


def test_cli_end_to_end(tmp_path, xml, monkeypatch):
    monkeypatch.setenv("SECURITYSCANNER_DATA_DIR", str(tmp_path / "data"))
    source = tmp_path / "scan.xml"
    source.write_bytes(xml)
    runner = CliRunner()
    result = runner.invoke(app, ["scan", "--profile", "passive", "--import-xml", str(source)])
    assert result.exit_code == 0, result.output
    scan = Database(tmp_path / "data").history()[0]
    assert runner.invoke(app, ["history"]).exit_code == 0
    for format in ["html", "json", "markdown"]:
        output = tmp_path / f"report.{format}"
        result = runner.invoke(
            app, ["report", "--scan-id", scan.id, "--format", format, "--output", str(output)]
        )
        assert result.exit_code == 0, result.output
        assert output.is_file()
    assert runner.invoke(app, ["compare", "--scan-a", scan.id, "--scan-b", scan.id]).exit_code == 0


@pytest.mark.parametrize(
    "args",
    [
        ["scan", "--target", "127.0.0.1"],
        ["scan", "--profile", "web"],
        ["scan", "--ports", "1-65535"],
        ["ui"],
        ["report", "--scan-id", "absent"],
        ["scan", "--profile", "passive"],
        ["scan", "--timeout", "999"],
    ],
)
def test_cli_errors(tmp_path, monkeypatch, args):
    monkeypatch.setenv("SECURITYSCANNER_DATA_DIR", str(tmp_path))
    result = CliRunner().invoke(app, args)
    assert result.exit_code == 2
    assert "Traceback" not in result.output


def test_version_and_help():
    runner = CliRunner()
    result = runner.invoke(app, ["--version"])
    assert result.exit_code == 0 and "0.2.0" in result.output
    assert runner.invoke(app, ["--help"]).exit_code == 0
    assert runner.invoke(app, ["profiles"]).exit_code == 0


def test_doctor(tmp_path, monkeypatch):
    monkeypatch.setenv("SECURITYSCANNER_DATA_DIR", str(tmp_path))
    with (
        patch("securityscanner.cli.shutil.which", return_value="/usr/bin/nmap"),
        patch(
            "securityscanner.cli.subprocess.run", return_value=Mock(stdout="Nmap version test\n")
        ),
    ):
        assert CliRunner().invoke(app, ["doctor"]).exit_code == 0
    with patch("securityscanner.cli.shutil.which", return_value=None):
        assert CliRunner().invoke(app, ["doctor"]).exit_code == 1


def test_doctor_unusable_nmap(tmp_path, monkeypatch):
    monkeypatch.setenv("SECURITYSCANNER_DATA_DIR", str(tmp_path))
    with (
        patch("securityscanner.cli.shutil.which", return_value="/usr/bin/nmap"),
        patch(
            "securityscanner.cli.subprocess.run", side_effect=subprocess.TimeoutExpired("nmap", 5)
        ),
    ):
        result = CliRunner().invoke(app, ["doctor"])
    assert result.exit_code == 1 and "FAILED" in result.output
