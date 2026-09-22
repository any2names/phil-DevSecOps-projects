"""Terragrunt/Terraform wrapper and plan-JSON parser."""

import json
import os
from pathlib import Path
from typing import Any

from pydantic import BaseModel

from platformctl import proc
from platformctl.config import CloudName, EnvName, Settings

PLAN_BINARY = "tfplan.binary"
ZERO_GUID = "00000000-0000-0000-0000-000000000000"


class ResourceChange(BaseModel):
    address: str
    type: str
    actions: list[str]


class PlanSummary(BaseModel):
    create: int = 0
    update: int = 0
    delete: int = 0
    replace: int = 0
    no_op: int = 0
    changes: list[ResourceChange] = []

    def has_changes(self) -> bool:
        return (self.create + self.update + self.delete + self.replace) > 0


def parse_plan(plan_json: dict[str, Any]) -> PlanSummary:
    summary = PlanSummary()
    for rc in plan_json.get("resource_changes", []):
        actions = list(rc.get("change", {}).get("actions", []))
        change = ResourceChange(
            address=rc.get("address", "?"), type=rc.get("type", "?"), actions=actions
        )
        summary.changes.append(change)
        if "create" in actions and "delete" in actions:
            summary.replace += 1
        elif actions == ["create"]:
            summary.create += 1
        elif actions == ["update"]:
            summary.update += 1
        elif actions == ["delete"]:
            summary.delete += 1
        else:
            summary.no_op += 1
    return summary


def _has_real_cloud_credentials(env: dict[str, str]) -> bool:
    azure = any(env.get(k) for k in ("ARM_CLIENT_ID", "ARM_USE_OIDC", "ARM_USE_MSI"))
    aws = bool(env.get("AWS_ACCESS_KEY_ID")) or bool(env.get("AWS_ROLE_ARN"))
    return azure or aws


def hermetic_env(repo_root: Path) -> dict[str, str]:
    """Environment that lets `terraform plan` run with no cloud account.

    AWS: the provider is configured to skip credential validation; dummy keys suffice.
    Azure: the provider decodes a token's claims locally and only calls the API for data
    sources or apply, so an `az` CLI shim minting an unsigned JWT satisfies authentication,
    and TC_TEST_VIA_VCR (the provider's own hermetic-test hook) skips resource-provider
    listing. See docs/adr/0007-hermetic-azure-plan.md.
    """
    shim = repo_root / "scripts" / "az-shim"
    return {
        "PATH": f"{shim}{os.pathsep}{os.environ.get('PATH', '')}",
        "ARM_USE_CLI": "true",
        "ARM_TENANT_ID": ZERO_GUID,
        "ARM_SUBSCRIPTION_ID": ZERO_GUID,
        "TC_TEST_VIA_VCR": "1",
        "AWS_ACCESS_KEY_ID": "hermetic-plan-only",
        "AWS_SECRET_ACCESS_KEY": "hermetic-plan-only",
        "AWS_REGION": os.environ.get("AWS_REGION", "us-east-1"),
    }


def base_env(repo_root: Path | None = None) -> dict[str, str]:
    env = dict(os.environ)
    env.setdefault("TF_IN_AUTOMATION", "1")
    env.setdefault("TF_INPUT", "0")
    env.setdefault("TG_BACKEND", "local")
    env.setdefault("TERRAGRUNT_NON_INTERACTIVE", "true")
    if (
        repo_root is not None
        and env["TG_BACKEND"] == "local"
        and not _has_real_cloud_credentials(env)
    ):
        env.update(hermetic_env(repo_root))
    return env


def env_dir(settings: Settings, cloud: CloudName, env: EnvName) -> Path:
    path = settings.infra_dir / "envs" / env.value / cloud.value
    if not path.is_dir():
        raise FileNotFoundError(f"no terragrunt unit at {path}")
    return path


def terragrunt_plan(
    settings: Settings, cloud: CloudName, env: EnvName, *, detailed_exitcode: bool = False
) -> tuple[Path, int]:
    unit = env_dir(settings, cloud, env)
    argv = ["terragrunt", "plan", f"-out={PLAN_BINARY}", "-input=false"]
    ok = frozenset({0})
    if detailed_exitcode:
        argv.append("-detailed-exitcode")
        ok = frozenset({0, 2})
    plan_result = proc.run(argv, cwd=unit, env=base_env(settings.repo_root), ok_codes=ok)
    show = proc.run(
        ["terragrunt", "show", "-json", PLAN_BINARY], cwd=unit, env=base_env(settings.repo_root)
    )
    out = settings.state_dir / "plans" / f"{cloud.value}-{env.value}.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(show.stdout)
    return out, plan_result.returncode


def terragrunt_outputs(settings: Settings, cloud: CloudName, env: EnvName) -> dict[str, Any]:
    unit = env_dir(settings, cloud, env)
    result = proc.run(["terragrunt", "output", "-json"], cwd=unit, env=base_env(settings.repo_root))
    raw: dict[str, dict[str, Any]] = json.loads(result.stdout or "{}")
    return {name: entry.get("value") for name, entry in raw.items()}
