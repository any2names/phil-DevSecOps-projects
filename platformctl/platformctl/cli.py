"""Typer entrypoint. Wiring only — no business logic lives here."""

from pathlib import Path
from typing import Annotated

import typer

from platformctl import __version__
from platformctl.config import Settings, load_settings
from platformctl.logging import configure

app = typer.Typer(no_args_is_help=True, help="secure-api-platform orchestration CLI")


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
