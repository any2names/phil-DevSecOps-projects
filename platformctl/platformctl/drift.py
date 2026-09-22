"""Drift detection: compare the current plan with the last accepted plan."""

from datetime import UTC, datetime
from pathlib import Path

from pydantic import BaseModel

from platformctl.config import CloudName, EnvName, Settings
from platformctl.terraform import PlanSummary


class DriftReport(BaseModel):
    cloud: str
    env: str
    drifted: bool
    current: PlanSummary
    new_addresses: list[str] = []
    resolved_addresses: list[str] = []
    generated_at: datetime


def _changed(summary: PlanSummary) -> set[str]:
    return {c.address for c in summary.changes if c.actions and c.actions != ["no-op"]}


def compare(
    cloud: str, env: str, previous: PlanSummary | None, current: PlanSummary
) -> DriftReport:
    before = _changed(previous) if previous else set()
    now = _changed(current)
    return DriftReport(
        cloud=cloud,
        env=env,
        drifted=current.has_changes(),
        current=current,
        new_addresses=sorted(now - before),
        resolved_addresses=sorted(before - now),
        generated_at=datetime.now(UTC),
    )


def last_good_path(settings: Settings, cloud: CloudName, env: EnvName) -> Path:
    return settings.state_dir / "last-good" / f"{cloud.value}-{env.value}.json"


def render_markdown(report: DriftReport) -> str:
    status = "DRIFTED" if report.drifted else "IN SYNC"
    c = report.current
    lines = [
        f"# Drift report: {report.cloud}/{report.env}",
        "",
        f"**Status:** {status}  ",
        f"**Generated:** {report.generated_at.isoformat(timespec='seconds')}  ",
        f"**Changes:** +{c.create} ~{c.update} -{c.delete} ±{c.replace}",
        "",
        "## Resources that would change",
    ]
    changing = [ch for ch in c.changes if ch.actions != ["no-op"]]
    lines += [f"- `{ch.address}` ({', '.join(ch.actions)})" for ch in changing] or ["- none"]
    lines += ["", "## New since last accepted plan"]
    lines += [f"- `{a}`" for a in report.new_addresses] or ["- none"]
    lines += ["", "## Resolved since last accepted plan"]
    lines += [f"- `{a}`" for a in report.resolved_addresses] or ["- none"]
    return "\n".join(lines) + "\n"
