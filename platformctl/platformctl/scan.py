"""Run security scanners and normalise their SARIF into one report.

Each scanner writes SARIF to <out_dir>/<name>.sarif. Non-zero exit codes mean
"findings present" for every tool here, so they are treated as data.
"""

import json
from enum import StrEnum
from pathlib import Path
from typing import Any

from pydantic import BaseModel

from platformctl import proc
from platformctl.logging import get_logger

log = get_logger(__name__)


class Severity(StrEnum):
    low = "low"
    medium = "medium"
    high = "high"
    critical = "critical"


SEVERITY_ORDER: dict[Severity, int] = {
    Severity.low: 0,
    Severity.medium: 1,
    Severity.high: 2,
    Severity.critical: 3,
}


class Finding(BaseModel):
    tool: str
    rule_id: str
    severity: Severity
    message: str
    file: str | None = None
    line: int | None = None


# {out} is replaced with <out_dir>/<name>.sarif; {root} with the repo root.
SCANNERS: dict[str, list[str]] = {
    "checkov": [
        "checkov",
        "--config-file",
        "{root}/.checkov.yaml",
        "-d",
        "{root}",
        "-o",
        "sarif",
        "--output-file-path",
        "{out_dir}",
    ],
    "tfsec": [
        "tfsec",
        "{root}/infra/terraform",
        "--format",
        "sarif",
        "--out",
        "{out}",
        "--soft-fail",
    ],
    "gitleaks": [
        "gitleaks",
        "detect",
        "--source",
        "{root}",
        "--config",
        "{root}/.gitleaks.toml",
        "--report-format",
        "sarif",
        "--report-path",
        "{out}",
        "--no-banner",
    ],
    "trivy": [
        "trivy",
        "fs",
        "--scanners",
        "vuln,misconfig,secret",
        "--format",
        "sarif",
        "--output",
        "{out}",
        "{root}",
    ],
}

# Tools that always exit non-zero when they find something.
_OK_CODES: dict[str, frozenset[int]] = {
    "checkov": frozenset({0, 1}),
    "tfsec": frozenset({0, 1}),
    "gitleaks": frozenset({0, 1}),
    "trivy": frozenset({0, 1}),
}


def _severity_from_score(score: float) -> Severity:
    if score >= 9.0:
        return Severity.critical
    if score >= 7.0:
        return Severity.high
    if score >= 4.0:
        return Severity.medium
    return Severity.low


_LEVEL_FALLBACK: dict[str, Severity] = {
    "error": Severity.high,
    "warning": Severity.medium,
    "note": Severity.low,
    "none": Severity.low,
}


def findings_from_sarif(sarif: dict[str, Any]) -> list[Finding]:
    findings: list[Finding] = []
    for run in sarif.get("runs", []):
        driver = run.get("tool", {}).get("driver", {})
        tool = driver.get("name", "unknown")
        scores: dict[str, float] = {}
        for rule in driver.get("rules", []) or []:
            raw = (rule.get("properties") or {}).get("security-severity")
            if raw is not None:
                scores[rule["id"]] = float(raw)
        for res in run.get("results", []) or []:
            rule_id = res.get("ruleId", "unknown")
            if rule_id in scores:
                severity = _severity_from_score(scores[rule_id])
            else:
                severity = _LEVEL_FALLBACK.get(res.get("level", "warning"), Severity.medium)
            file: str | None = None
            line: int | None = None
            locs = res.get("locations") or []
            if locs:
                phys = locs[0].get("physicalLocation", {})
                file = phys.get("artifactLocation", {}).get("uri")
                line = phys.get("region", {}).get("startLine")
            findings.append(
                Finding(
                    tool=tool,
                    rule_id=rule_id,
                    severity=severity,
                    message=res.get("message", {}).get("text", ""),
                    file=file,
                    line=line,
                )
            )
    return findings


def merge_sarif(reports: list[dict[str, Any]]) -> dict[str, Any]:
    runs: list[dict[str, Any]] = []
    for report in reports:
        runs.extend(report.get("runs", []))
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": runs,
    }


def exceeds(findings: list[Finding], fail_on: Severity) -> list[Finding]:
    threshold = SEVERITY_ORDER[fail_on]
    return [f for f in findings if SEVERITY_ORDER[f.severity] >= threshold]


def run_scanner(name: str, repo_root: Path, out_dir: Path) -> dict[str, Any] | None:
    template = SCANNERS[name]  # KeyError for unknown tools is intentional
    if not proc.which(template[0]):
        log.warning("scanner.missing", tool=name)
        return None
    out = out_dir / f"{name}.sarif"
    argv = [a.format(root=repo_root, out=out, out_dir=out_dir) for a in template]
    proc.run(argv, cwd=repo_root, ok_codes=_OK_CODES[name])
    # checkov names its file results_sarif.sarif inside out_dir
    candidate = out if out.exists() else out_dir / "results_sarif.sarif"
    if not candidate.exists():
        log.warning("scanner.no_output", tool=name)
        return None
    data: dict[str, Any] = json.loads(candidate.read_text())
    if candidate != out:
        candidate.rename(out)
    return data
