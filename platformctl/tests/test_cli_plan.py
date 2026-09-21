import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from platformctl.cli import app
from tests.conftest import RunRecorder

runner = CliRunner()


@pytest.fixture
def repo(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    (tmp_path / "platformctl.toml").write_text('adapter = "fake"\n')
    (tmp_path / "infra/envs/dev/azure").mkdir(parents=True)
    (tmp_path / "policy/terraform").mkdir(parents=True)
    monkeypatch.chdir(tmp_path)
    return tmp_path


def test_plan_pass(repo: Path, fake_run: RunRecorder) -> None:
    fake_run.add(
        ("terragrunt", "show"),
        stdout=json.dumps(
            {"resource_changes": [{"address": "a", "type": "t", "change": {"actions": ["create"]}}]}
        ),
    )
    fake_run.add(("conftest",), returncode=0, stdout='[{"successes": 2}]')
    result = runner.invoke(app, ["plan", "azure", "dev"])
    assert result.exit_code == 0, result.output
    assert "create" in result.output and "Policy: PASS" in result.output


def test_plan_policy_failure_exits_1(repo: Path, fake_run: RunRecorder) -> None:
    fake_run.add(("terragrunt", "show"), stdout='{"resource_changes": []}')
    fake_run.add(
        ("conftest",), returncode=1, stdout='[{"namespace":"x","failures":[{"msg":"nope"}]}]'
    )
    result = runner.invoke(app, ["plan", "azure", "dev"])
    assert result.exit_code == 1
    assert "nope" in result.output


def test_plan_no_policy_skips_conftest(repo: Path, fake_run: RunRecorder) -> None:
    fake_run.add(("terragrunt", "show"), stdout='{"resource_changes": []}')
    result = runner.invoke(app, ["plan", "azure", "dev", "--no-policy"])
    assert result.exit_code == 0
    assert not any(c[0] == "conftest" for c in fake_run.calls)
