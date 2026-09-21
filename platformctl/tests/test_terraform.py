import json
from pathlib import Path

import pytest
from hypothesis import given
from hypothesis import strategies as st

from platformctl import config, terraform
from tests.conftest import RunRecorder

FIXTURES = Path(__file__).parent / "fixtures"


def test_parse_plan_counts_actions() -> None:
    plan = json.loads((FIXTURES / "plan_small.json").read_text())
    summary = terraform.parse_plan(plan)
    counts = (summary.create, summary.update, summary.delete, summary.replace, summary.no_op)
    assert counts == (1, 1, 1, 1, 1)
    assert summary.has_changes()
    assert summary.changes[1].actions == ["delete", "create"]


def test_parse_plan_empty() -> None:
    summary = terraform.parse_plan({"resource_changes": []})
    assert not summary.has_changes()
    assert summary.changes == []


def test_parse_plan_missing_key() -> None:
    assert terraform.parse_plan({}).changes == []


ACTIONS = st.sampled_from(
    [["create"], ["update"], ["delete"], ["no-op"], ["delete", "create"], ["create", "delete"]]
)


@given(st.lists(st.tuples(st.text(min_size=1), ACTIONS), max_size=30))
def test_parse_plan_totals_match_changes(items: list[tuple[str, list[str]]]) -> None:
    plan = {
        "resource_changes": [
            {"address": a, "type": "t", "change": {"actions": acts}} for a, acts in items
        ]
    }
    s = terraform.parse_plan(plan)
    assert s.create + s.update + s.delete + s.replace + s.no_op == len(items)


def test_env_dir(settings: config.Settings) -> None:
    got = terraform.env_dir(settings, config.CloudName.aws, config.EnvName.dev)
    assert got == settings.infra_dir / "envs/dev/aws"


def test_env_dir_missing_raises(settings: config.Settings) -> None:
    with pytest.raises(FileNotFoundError):
        terraform.env_dir(settings, config.CloudName.aws, config.EnvName.prod)


def test_terragrunt_plan_writes_json(settings: config.Settings, fake_run: RunRecorder) -> None:
    fake_run.add(("terragrunt", "plan"), returncode=0)
    fake_run.add(("terragrunt", "show"), stdout='{"resource_changes": []}')
    path, code = terraform.terragrunt_plan(settings, config.CloudName.azure, config.EnvName.dev)
    assert code == 0
    assert json.loads(path.read_text()) == {"resource_changes": []}
    assert path == settings.state_dir / "plans" / "azure-dev.json"
    assert fake_run.calls[0][:3] == ("terragrunt", "plan", "-out=tfplan.binary")
    assert fake_run.calls[1] == ("terragrunt", "show", "-json", "tfplan.binary")


def test_terragrunt_plan_detailed_exitcode(
    settings: config.Settings, fake_run: RunRecorder
) -> None:
    fake_run.add(("terragrunt", "plan"), returncode=2)
    fake_run.add(("terragrunt", "show"), stdout="{}")
    _, code = terraform.terragrunt_plan(
        settings, config.CloudName.azure, config.EnvName.dev, detailed_exitcode=True
    )
    assert code == 2
    assert "-detailed-exitcode" in fake_run.calls[0]


def test_terragrunt_outputs_flatten(settings: config.Settings, fake_run: RunRecorder) -> None:
    fake_run.add(
        ("terragrunt", "output"),
        stdout=json.dumps({"vm_public_ip": {"value": "1.2.3.4", "sensitive": False}}),
    )
    got = terraform.terragrunt_outputs(settings, config.CloudName.aws, config.EnvName.dev)
    assert got == {"vm_public_ip": "1.2.3.4"}


def test_base_env_sets_automation_flags(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("TG_BACKEND", raising=False)
    env = terraform.base_env()
    assert env["TF_IN_AUTOMATION"] == "1"
    assert env["TG_BACKEND"] == "local"
