"""Rich renderers. Pure functions from models to renderables so the CLI stays thin."""

from rich.panel import Panel
from rich.table import Table

from platformctl.policy import PolicyResult
from platformctl.terraform import PlanSummary

_ACTION_STYLE = {
    "create": "green",
    "update": "yellow",
    "delete": "red",
    "replace": "magenta",
    "no-op": "dim",
}


def _label(actions: list[str]) -> str:
    if "create" in actions and "delete" in actions:
        return "replace"
    return actions[0] if actions else "no-op"


def plan_table(summary: PlanSummary) -> Table:
    title = f"Plan: +{summary.create} ~{summary.update} -{summary.delete} ±{summary.replace}"
    table = Table(title=title)
    table.add_column("Action")
    table.add_column("Type")
    table.add_column("Address")
    for change in summary.changes:
        label = _label(change.actions)
        if label == "no-op":
            continue
        table.add_row(f"[{_ACTION_STYLE[label]}]{label}[/]", change.type, change.address)
    return table


def policy_panel(result: PolicyResult) -> Panel:
    lines = [f"[green]{result.successes} checks passed[/]"]
    lines += [f"[yellow]WARN[/] {w}" for w in result.warnings]
    lines += [f"[red]FAIL[/] {f}" for f in result.failures]
    title = "[green]Policy: PASS" if result.passed else "[red]Policy: FAIL"
    return Panel("\n".join(lines), title=title)
