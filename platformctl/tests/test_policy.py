import json
from pathlib import Path

from platformctl import config, policy
from tests.conftest import RunRecorder

CONFTEST_FAIL = json.dumps(
    [
        {
            "filename": "plan.json",
            "namespace": "terraform.ingress",
            "successes": 3,
            "failures": [{"msg": "SSH open to the world on aws_security_group.vm"}],
            "warnings": [{"msg": "consider private endpoint"}],
        },
        {"filename": "plan.json", "namespace": "terraform.tags", "successes": 2},
    ]
)


def test_evaluate_parses_failures(
    settings: config.Settings, fake_run: RunRecorder, tmp_path: Path
) -> None:
    plan = tmp_path / "plan.json"
    plan.write_text("{}")
    fake_run.add(("conftest", "test"), returncode=1, stdout=CONFTEST_FAIL)
    result = policy.evaluate(settings, plan)
    assert result.passed is False
    assert result.failures == ["[terraform.ingress] SSH open to the world on aws_security_group.vm"]
    assert result.warnings == ["[terraform.ingress] consider private endpoint"]
    assert result.successes == 5
    assert fake_run.calls[0] == (
        "conftest",
        "test",
        str(plan),
        "-p",
        str(settings.policy_dir),
        "-o",
        "json",
        "--all-namespaces",
    )


def test_evaluate_pass(settings: config.Settings, fake_run: RunRecorder, tmp_path: Path) -> None:
    plan = tmp_path / "plan.json"
    plan.write_text("{}")
    fake_run.add(("conftest", "test"), returncode=0, stdout='[{"successes": 4}]')
    result = policy.evaluate(settings, plan)
    assert result.passed and result.successes == 4 and result.failures == []
