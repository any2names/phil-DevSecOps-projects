"""Typer entrypoint. Wiring only — no business logic lives here."""

import json
from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console
from rich.table import Table

from platformctl import __version__, render, terraform
from platformctl import policy as policy_mod
from platformctl import scan as scan_mod
from platformctl.config import CloudName, EnvName, Settings, load_settings
from platformctl.logging import configure

app = typer.Typer(no_args_is_help=True, help="secure-api-platform orchestration CLI")
console = Console()


def _version_cb(value: bool) -> None:
    if value:
        typer.echo(f"platformctl {__version__}")
        raise typer.Exit()


@app.callback()
def _root(
    ctx: typer.Context,
    config: Annotated[
        Path | None, typer.Option("--config", "-c", help="Path to platformctl.toml")
    ] = None,
    verbose: Annotated[bool, typer.Option("--verbose", "-v")] = False,
    version: Annotated[
        bool, typer.Option("--version", callback=_version_cb, is_eager=True)
    ] = False,
) -> None:
    """secure-api-platform orchestration CLI."""
    configure(verbose)
    if ctx.invoked_subcommand is not None:
        ctx.obj = load_settings(config)


def get_settings(ctx: typer.Context) -> Settings:
    settings: Settings = ctx.obj
    return settings


@app.command()
def plan(
    ctx: typer.Context,
    cloud: CloudName,
    env: EnvName,
    policy: Annotated[bool, typer.Option(help="Run the OPA/Conftest gate on the plan")] = True,
) -> None:
    """Run terragrunt plan for CLOUD/ENV, summarise changes and gate on policy."""
    settings = get_settings(ctx)
    plan_path, _ = terraform.terragrunt_plan(settings, cloud, env)
    summary = terraform.parse_plan(json.loads(plan_path.read_text()))
    console.print(render.plan_table(summary))
    if not policy:
        return
    result = policy_mod.evaluate(settings, plan_path)
    console.print(render.policy_panel(result))
    if not result.passed:
        raise typer.Exit(code=1)


@app.command()
def scan(
    ctx: typer.Context,
    fail_on: Annotated[
        scan_mod.Severity,
        typer.Option(help="Exit 1 if any finding is at or above this severity"),
    ] = scan_mod.Severity.high,
    tool: Annotated[
        list[str] | None, typer.Option(help="Subset of scanners to run (default: all)")
    ] = None,
    out: Annotated[Path, typer.Option(help="Merged SARIF output path")] = Path("results.sarif"),
) -> None:
    """Run checkov, tfsec, gitleaks and trivy; merge to SARIF; gate on severity."""
    settings = get_settings(ctx)
    out_dir = settings.state_dir / "scan"
    out_dir.mkdir(parents=True, exist_ok=True)
    names = tool or list(scan_mod.SCANNERS)
    reports = [
        r
        for name in names
        if (r := scan_mod.run_scanner(name, settings.repo_root, out_dir)) is not None
    ]
    merged = scan_mod.merge_sarif(reports)
    out.write_text(json.dumps(merged, indent=2))
    findings = scan_mod.findings_from_sarif(merged)
    table = Table(title=f"{len(findings)} findings (fail-on: {fail_on})")
    for col in ("Sev", "Tool", "Rule", "Location", "Message"):
        table.add_column(col)
    for f in sorted(findings, key=lambda f: -scan_mod.SEVERITY_ORDER[f.severity]):
        loc = f"{f.file}:{f.line}" if f.file else "-"
        table.add_row(f.severity, f.tool, f.rule_id, loc, f.message[:80])
    console.print(table)
    console.print(f"SARIF written to {out}")
    if scan_mod.exceeds(findings, fail_on):
        raise typer.Exit(code=1)
