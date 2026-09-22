"""OPA/Conftest gate over Terraform plan JSON."""

import json
from pathlib import Path

from pydantic import BaseModel

from platformctl import proc
from platformctl.config import Settings


class PolicyResult(BaseModel):
    passed: bool
    failures: list[str] = []
    warnings: list[str] = []
    successes: int = 0


def evaluate(settings: Settings, plan_json_path: Path) -> PolicyResult:
    argv = [
        "conftest",
        "test",
        str(plan_json_path),
        "-p",
        str(settings.policy_dir),
        "-o",
        "json",
        "--all-namespaces",
    ]
    # conftest exits 1 when any policy fails; that is data, not an error.
    result = proc.run(argv, ok_codes=frozenset({0, 1}))
    entries = json.loads(result.stdout or "[]")
    failures: list[str] = []
    warnings: list[str] = []
    successes = 0
    for entry in entries:
        ns = entry.get("namespace", "policy")
        successes += int(entry.get("successes", 0))
        failures.extend(f"[{ns}] {f['msg']}" for f in entry.get("failures", []) or [])
        warnings.extend(f"[{ns}] {w['msg']}" for w in entry.get("warnings", []) or [])
    return PolicyResult(
        passed=not failures, failures=failures, warnings=warnings, successes=successes
    )
