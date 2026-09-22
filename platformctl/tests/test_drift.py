import json

import pytest
from typer.testing import CliRunner

from platformctl import config, drift, terraform
from platformctl.cli import app
from tests.conftest import RunRecorder


def _summary(*addresses: str) -> terraform.PlanSummary:
    return terraform.parse_plan(
        {
            "resource_changes": [
                {"address": a, "type": "t", "change": {"actions": ["update"]}} for a in addresses
            ]
        }
    )


def test_compare_no_previous_and_no_changes() -> None:
    r = drift.compare("aws", "dev", None, _summary())
    assert r.drifted is False and r.new_addresses == []


def test_compare_detects_new_and_resolved() -> None:
    r = drift.compare("aws", "dev", _summary("a", "b"), _summary("b", "c"))
    assert r.drifted is True
    assert r.new_addresses == ["c"] and r.resolved_addresses == ["a"]


def test_render_markdown_lists_addresses() -> None:
    md = drift.render_markdown(drift.compare("azure", "prod", None, _summary("x")))
    assert "# Drift report: azure/prod" in md and "- `x`" in md and "DRIFTED" in md


def test_render_markdown_in_sync() -> None:
    md = drift.render_markdown(drift.compare("azure", "prod", None, _summary()))
    assert "IN SYNC" in md and "- none" in md


def test_cli_drift_exit_codes(
    settings: config.Settings, fake_run: RunRecorder, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(settings.repo_root)
    fake_run.add(("terragrunt", "plan"), returncode=2)
    fake_run.add(
        ("terragrunt", "show"),
        stdout=json.dumps(
            {"resource_changes": [{"address": "a", "type": "t", "change": {"actions": ["update"]}}]}
        ),
    )
    report = settings.repo_root / "drift.md"
    r = CliRunner().invoke(app, ["drift", "aws", "dev", "--report", str(report)])
    assert r.exit_code == 2, r.output
    assert "DRIFTED" in report.read_text()

    r = CliRunner().invoke(app, ["drift", "aws", "dev", "--accept"])
    assert r.exit_code == 0, r.output
    assert drift.last_good_path(settings, config.CloudName.aws, config.EnvName.dev).exists()

    fake_run.add(("terragrunt", "plan"), returncode=0)
    fake_run.add(("terragrunt", "show"), stdout='{"resource_changes": []}')
    r = CliRunner().invoke(app, ["drift", "aws", "dev"])
    assert r.exit_code == 0
