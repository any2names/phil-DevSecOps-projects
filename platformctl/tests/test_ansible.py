import json

import pytest
import yaml
from typer.testing import CliRunner

from platformctl import ansible, config
from platformctl.cli import app
from tests.conftest import RunRecorder

OUTPUTS = {
    "vm_public_ip": "203.0.113.10",
    "vm_private_ip": "10.0.1.4",
    "secret_store_id": "kv-123",
    "identity_id": "id-456",
}


def test_build_inventory_shape() -> None:
    inv = ansible.build_inventory(OUTPUTS, config.CloudName.azure, config.EnvName.dev)
    host = inv["all"]["hosts"]["api-azure-dev"]
    assert host["ansible_host"] == "203.0.113.10" and host["private_ip"] == "10.0.1.4"
    assert inv["all"]["vars"] == {
        "cloud": "azure",
        "environment": "dev",
        "secret_store_id": "kv-123",
        "identity_id": "id-456",
        "ansible_user": "platform",
        "ansible_python_interpreter": "/usr/bin/python3",
    }
    assert inv["all"]["children"] == {"api": {"hosts": {"api-azure-dev": None}}}


def test_build_inventory_missing_output() -> None:
    with pytest.raises(ansible.MissingOutputError):
        ansible.build_inventory({"vm_public_ip": "x"}, config.CloudName.aws, config.EnvName.prod)


def test_cli_inventory_writes_yaml(
    settings: config.Settings, fake_run: RunRecorder, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(settings.repo_root)
    fake_run.add(
        ("terragrunt", "output"), stdout=json.dumps({k: {"value": v} for k, v in OUTPUTS.items()})
    )
    r = CliRunner().invoke(app, ["ansible", "inventory", "aws", "dev"])
    assert r.exit_code == 0, r.output
    path = settings.repo_root / "ansible/inventory/aws-dev.yml"
    loaded = yaml.safe_load(path.read_text())
    assert loaded["all"]["hosts"]["api-aws-dev"]["ansible_host"] == "203.0.113.10"
