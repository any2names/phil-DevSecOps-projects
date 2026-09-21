import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from platformctl import scan
from platformctl.cli import app
from tests.conftest import RunRecorder

SARIF = {
    "version": "2.1.0",
    "runs": [
        {
            "tool": {
                "driver": {
                    "name": "checkov",
                    "rules": [
                        {"id": "CKV_AWS_1", "properties": {"security-severity": "8.0"}},
                        {"id": "CKV_AWS_2", "properties": {"security-severity": "3.0"}},
                    ],
                }
            },
            "results": [
                {
                    "ruleId": "CKV_AWS_1",
                    "level": "error",
                    "message": {"text": "bad"},
                    "locations": [
                        {
                            "physicalLocation": {
                                "artifactLocation": {"uri": "main.tf"},
                                "region": {"startLine": 7},
                            }
                        }
                    ],
                },
                {"ruleId": "CKV_AWS_2", "level": "warning", "message": {"text": "meh"}},
                {"ruleId": "UNKNOWN", "level": "note", "message": {"text": "fyi"}},
            ],
        }
    ],
}


def test_findings_from_sarif_maps_severity_and_location() -> None:
    findings = scan.findings_from_sarif(SARIF)
    assert [f.severity for f in findings] == [
        scan.Severity.high,
        scan.Severity.low,
        scan.Severity.low,
    ]
    assert findings[0].file == "main.tf" and findings[0].line == 7
    assert findings[0].tool == "checkov"
    assert findings[1].file is None


def test_exceeds_threshold() -> None:
    findings = scan.findings_from_sarif(SARIF)
    assert [f.rule_id for f in scan.exceeds(findings, scan.Severity.high)] == ["CKV_AWS_1"]
    assert len(scan.exceeds(findings, scan.Severity.low)) == 3
    assert scan.exceeds(findings, scan.Severity.critical) == []


def test_merge_sarif_concatenates_runs() -> None:
    merged = scan.merge_sarif([SARIF, SARIF])
    assert merged["version"] == "2.1.0" and len(merged["runs"]) == 2


def test_run_scanner_skips_missing_tool(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(scan.proc, "which", lambda _n: False)
    assert scan.run_scanner("checkov", tmp_path, tmp_path) is None


def test_run_scanner_reads_sarif_file(
    tmp_path: Path, fake_run: RunRecorder, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(scan.proc, "which", lambda _n: True)
    fake_run.add(("gitleaks",), returncode=1, stdout="")
    (tmp_path / "gitleaks.sarif").write_text(json.dumps(SARIF))
    result = scan.run_scanner("gitleaks", tmp_path, tmp_path)
    assert result is not None and result["runs"][0]["tool"]["driver"]["name"] == "checkov"
    assert "--report-path" in fake_run.calls[0]


def test_run_scanner_no_output_returns_none(
    tmp_path: Path, fake_run: RunRecorder, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(scan.proc, "which", lambda _n: True)
    assert scan.run_scanner("tfsec", tmp_path, tmp_path) is None


def test_unknown_scanner() -> None:
    with pytest.raises(KeyError):
        scan.run_scanner("nmap", Path("."), Path("."))


def test_scan_cli_gates(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    (tmp_path / "platformctl.toml").write_text('adapter = "fake"\n')
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(scan, "run_scanner", lambda name, root, out: SARIF)
    out = str(tmp_path / "r.sarif")
    r = CliRunner().invoke(app, ["scan", "--tool", "checkov", "--fail-on", "high", "--out", out])
    assert r.exit_code == 1, r.output
    r = CliRunner().invoke(
        app, ["scan", "--tool", "checkov", "--fail-on", "critical", "--out", out]
    )
    assert r.exit_code == 0, r.output
    assert json.loads((tmp_path / "r.sarif").read_text())["version"] == "2.1.0"
