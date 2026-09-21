"""Single choke point for running external tools.

Every subprocess in platformctl goes through run() so that command, duration and
exit code are logged uniformly and failures surface as a typed ToolError.
"""

import shutil
import subprocess
import time
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path

from platformctl.logging import get_logger

log = get_logger(__name__)


@dataclass(frozen=True)
class CommandResult:
    argv: tuple[str, ...]
    returncode: int
    stdout: str
    stderr: str
    duration_s: float


class ToolError(RuntimeError):
    def __init__(self, argv: Sequence[str], returncode: int, stderr: str) -> None:
        self.argv = tuple(argv)
        self.returncode = returncode
        self.stderr = stderr
        super().__init__(f"{' '.join(self.argv)} exited {returncode}: {stderr.strip()}")


def which(name: str) -> bool:
    return shutil.which(name) is not None


def run(
    argv: Sequence[str],
    *,
    cwd: Path | None = None,
    env: Mapping[str, str] | None = None,
    ok_codes: frozenset[int] = frozenset({0}),
) -> CommandResult:
    started = time.perf_counter()
    log.debug("exec", argv=list(argv), cwd=str(cwd) if cwd else None)
    try:
        completed = subprocess.run(  # noqa: S603 — argv is a list, never a shell string
            list(argv),
            cwd=cwd,
            env=dict(env) if env is not None else None,
            capture_output=True,
            text=True,
            check=False,
        )
    except FileNotFoundError as exc:
        raise ToolError(argv, 127, f"binary not found: {exc}") from exc
    duration = time.perf_counter() - started
    result = CommandResult(
        tuple(argv), completed.returncode, completed.stdout, completed.stderr, duration
    )
    log.info(
        "exec.done", argv0=argv[0], returncode=result.returncode, duration_s=round(duration, 3)
    )
    if result.returncode not in ok_codes:
        raise ToolError(argv, result.returncode, result.stderr)
    return result
