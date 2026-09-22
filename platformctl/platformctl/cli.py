"""Typer entrypoint. Wiring only — no business logic lives here."""

import json
from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console
from rich.table import Table

from platformctl import __version__, adapters, render, terraform
from platformctl import certs as certs_mod
from platformctl import drift as drift_mod
from platformctl import policy as policy_mod
from platformctl import scan as scan_mod
from platformctl import secrets as secrets_mod
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


@app.command()
def drift(
    ctx: typer.Context,
    cloud: CloudName,
    env: EnvName,
    accept: Annotated[
        bool, typer.Option(help="Record the current plan as the new last-good baseline")
    ] = False,
    report: Annotated[Path | None, typer.Option(help="Write a markdown drift report here")] = None,
) -> None:
    """Detect drift: exit 2 if the plan would change anything, 0 if in sync."""
    settings = get_settings(ctx)
    plan_path, _ = terraform.terragrunt_plan(settings, cloud, env, detailed_exitcode=True)
    current = terraform.parse_plan(json.loads(plan_path.read_text()))
    baseline = drift_mod.last_good_path(settings, cloud, env)
    previous = (
        terraform.PlanSummary.model_validate_json(baseline.read_text())
        if baseline.exists()
        else None
    )
    result = drift_mod.compare(cloud.value, env.value, previous, current)
    md = drift_mod.render_markdown(result)
    if report:
        report.write_text(md)
    console.print(md)
    if accept:
        baseline.parent.mkdir(parents=True, exist_ok=True)
        baseline.write_text(current.model_dump_json(indent=2))
        console.print(f"Baseline saved to {baseline}")
        return
    if result.drifted:
        raise typer.Exit(code=2)


secrets_app = typer.Typer(help="Secret lifecycle (rotate, list)")
app.add_typer(secrets_app, name="secrets")


@secrets_app.command("rotate")
def secrets_rotate(
    ctx: typer.Context,
    name: str,
    execute: Annotated[
        bool,
        typer.Option("--execute", help="Actually write the new version (default: dry run)"),
    ] = False,
) -> None:
    """Generate a new secret version and deprecate previous ones."""
    settings = get_settings(ctx)
    adapter = adapters.get_adapter(settings)
    result = secrets_mod.rotate(adapter, name, settings.secret_policy, execute=execute)
    if not result.executed:
        console.print(f"[yellow]DRY RUN[/] would rotate '{name}' (pass --execute to apply)")
        return
    console.print(
        f"[green]rotated[/] '{name}' -> version {result.new_version}; "
        f"deprecated {len(result.deprecated)} version(s)"
    )


@secrets_app.command("list")
def secrets_list(ctx: typer.Context, name: str) -> None:
    """List versions of a secret (values are never shown)."""
    adapter = adapters.get_adapter(get_settings(ctx))
    table = Table(title=name)
    for col in ("Version", "Created", "Enabled", "Tags"):
        table.add_column(col)
    for v in adapter.list_secret_versions(name):
        tags = ", ".join(f"{k}={val}" for k, val in v.tags.items())
        table.add_row(v.version, v.created.isoformat(timespec="seconds"), str(v.enabled), tags)
    console.print(table)


certs_app = typer.Typer(help="Certificate lifecycle")
app.add_typer(certs_app, name="certs")


@certs_app.command("check")
def certs_check(
    ctx: typer.Context,
    warn_days: Annotated[
        int | None, typer.Option(help="Override warn threshold from config")
    ] = None,
    probe: Annotated[bool, typer.Option(help="Also TLS-probe cert_targets from config")] = True,
) -> None:
    """Report certificates expiring within the warning window. Exit 1 if any."""
    settings = get_settings(ctx)
    found: list[adapters.Certificate] = adapters.get_adapter(settings).list_certificates()
    if probe:
        for target in settings.cert_targets:
            try:
                found.append(certs_mod.probe_tls(target.host, target.port))
            except certs_mod.ProbeError as exc:
                console.print(f"[yellow]probe failed[/] {exc}")
    statuses = certs_mod.evaluate(found, warn_days or settings.warn_days)
    table = Table(title="Certificates")
    for col in ("Status", "Name", "Source", "Expires", "Days"):
        table.add_column(col)
    style = {"ok": "green", "warning": "yellow", "expired": "red"}
    for s in statuses:
        table.add_row(
            f"[{style[s.status]}]{s.status}[/]",
            s.name,
            s.source,
            s.not_after.date().isoformat(),
            str(s.days_remaining),
        )
    console.print(table)
    if any(s.status != "ok" for s in statuses):
        raise typer.Exit(code=1)
