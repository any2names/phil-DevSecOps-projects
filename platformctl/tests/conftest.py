"""Shared fixtures. `settings` gives an isolated repo layout; `fake_run` stubs proc.run."""

import subprocess
from pathlib import Path

import pytest

from platformctl import config, proc


@pytest.fixture
def settings(tmp_path: Path) -> config.Settings:
    (tmp_path / "platformctl.toml").write_text('adapter = "fake"\n')
    for d in (
        "infra/envs/dev/azure",
        "infra/envs/dev/aws",
        "infra/envs/prod/azure",
        "policy/terraform",
    ):
        (tmp_path / d).mkdir(parents=True)
    return config.load_settings(tmp_path / "platformctl.toml")


class RunRecorder:
    """Records every argv passed to proc.run and replays canned responses keyed by prefix."""

    def __init__(self) -> None:
        self.calls: list[tuple[str, ...]] = []
        self.responses: dict[tuple[str, ...], tuple[int, str, str]] = {}

    def add(
        self, prefix: tuple[str, ...], returncode: int = 0, stdout: str = "", stderr: str = ""
    ) -> None:
        self.responses[prefix] = (returncode, stdout, stderr)

    def __call__(self, argv: list[str], **kw: object) -> subprocess.CompletedProcess[str]:
        self.calls.append(tuple(argv))
        for prefix, (code, out, err) in self.responses.items():
            if tuple(argv[: len(prefix)]) == prefix:
                return subprocess.CompletedProcess(argv, code, stdout=out, stderr=err)
        return subprocess.CompletedProcess(argv, 0, stdout="", stderr="")


@pytest.fixture
def fake_run(monkeypatch: pytest.MonkeyPatch) -> RunRecorder:
    rec = RunRecorder()
    monkeypatch.setattr(proc.subprocess, "run", rec)
    return rec
