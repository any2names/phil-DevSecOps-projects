"""Typer entrypoint. Wiring only — no business logic lives here."""

import typer

app = typer.Typer(no_args_is_help=True, help="secure-api-platform orchestration CLI")


@app.callback()
def _root() -> None:
    """secure-api-platform orchestration CLI."""
