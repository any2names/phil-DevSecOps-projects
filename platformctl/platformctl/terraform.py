"""Terragrunt/Terraform wrapper and plan-JSON parser."""

import json
import os
from pathlib import Path
from typing import Any

from pydantic import BaseModel

from platformctl import proc
from platformctl.config import CloudName, EnvName, Settings

PLAN_BINARY = "tfplan.binary"


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


def base_env() -> dict[str, str]:
    env = dict(os.environ)
    env.setdefault("TF_IN_AUTOMATION", "1")
    env.setdefault("TF_INPUT", "0")
    env.setdefault("TG_BACKEND", "local")
    env.setdefault("TERRAGRUNT_NON_INTERACTIVE", "true")
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
    plan_result = proc.run(argv, cwd=unit, env=base_env(), ok_codes=ok)
    show = proc.run(["terragrunt", "show", "-json", PLAN_BINARY], cwd=unit, env=base_env())
    out = settings.state_dir / "plans" / f"{cloud.value}-{env.value}.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(show.stdout)
    return out, plan_result.returncode


def terragrunt_outputs(settings: Settings, cloud: CloudName, env: EnvName) -> dict[str, Any]:
    unit = env_dir(settings, cloud, env)
    result = proc.run(["terragrunt", "output", "-json"], cwd=unit, env=base_env())
    raw: dict[str, dict[str, Any]] = json.loads(result.stdout or "{}")
    return {name: entry.get("value") for name, entry in raw.items()}
