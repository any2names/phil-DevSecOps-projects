"""Generate an Ansible YAML inventory from Terraform stack outputs."""

from pathlib import Path
from typing import Any

import yaml

from platformctl.config import CloudName, EnvName, Settings

REQUIRED_OUTPUTS = ("vm_public_ip", "vm_private_ip", "secret_store_id", "identity_id")


class MissingOutputError(KeyError):
    pass


def build_inventory(outputs: dict[str, Any], cloud: CloudName, env: EnvName) -> dict[str, Any]:
    missing = [k for k in REQUIRED_OUTPUTS if k not in outputs]
    if missing:
        raise MissingOutputError(f"terraform outputs missing: {', '.join(missing)}")
    host = f"api-{cloud.value}-{env.value}"
    return {
        "all": {
            "hosts": {
                host: {
                    "ansible_host": outputs["vm_public_ip"],
                    "private_ip": outputs["vm_private_ip"],
                }
            },
            "vars": {
                "cloud": cloud.value,
                "environment": env.value,
                "secret_store_id": outputs["secret_store_id"],
                "identity_id": outputs["identity_id"],
                "ansible_user": "platform",
                "ansible_python_interpreter": "/usr/bin/python3",
            },
            "children": {"api": {"hosts": {host: None}}},
        }
    }


def write_inventory(
    settings: Settings, cloud: CloudName, env: EnvName, inventory: dict[str, Any]
) -> Path:
    path = settings.repo_root / "ansible" / "inventory" / f"{cloud.value}-{env.value}.yml"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(yaml.safe_dump(inventory, sort_keys=False))
    return path
