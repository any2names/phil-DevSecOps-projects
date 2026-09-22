"""structlog configuration. Call configure() once from the CLI callback."""

import logging
import sys
from typing import Any

import structlog


def _stderr_logger(*_args: Any) -> structlog.PrintLogger:
    # Resolve sys.stderr on every call so test runners that swap/close streams stay safe.
    return structlog.PrintLogger(file=sys.stderr)


def configure(verbose: bool = False) -> None:
    level = logging.DEBUG if verbose else logging.INFO
    structlog.configure(
        processors=[
            structlog.contextvars.merge_contextvars,
            structlog.processors.add_log_level,
            structlog.processors.TimeStamper(fmt="iso"),
            structlog.dev.ConsoleRenderer(colors=False),
        ],
        wrapper_class=structlog.make_filtering_bound_logger(level),
        logger_factory=_stderr_logger,
        cache_logger_on_first_use=False,
    )


def get_logger(name: str) -> structlog.stdlib.BoundLogger:
    return structlog.get_logger(name)  # type: ignore[no-any-return]
