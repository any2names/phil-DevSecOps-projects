import subprocess
from pathlib import Path

import pytest

from platformctl import proc


def test_run_returns_result_with_timing(monkeypatch: pytest.MonkeyPatch) -> None:
    def fake(argv, **kw):
        return subprocess.CompletedProcess(argv, 0, stdout="hi\n", stderr="")

    monkeypatch.setattr(subprocess, "run", fake)
    result = proc.run(["echo", "hi"])
    assert result.returncode == 0
    assert result.stdout == "hi\n"
    assert result.argv == ("echo", "hi")
    assert result.duration_s >= 0


def test_run_raises_tool_error_with_stderr(monkeypatch: pytest.MonkeyPatch) -> None:
    def fake(argv, **kw):
        return subprocess.CompletedProcess(argv, 3, stdout="", stderr="boom")

    monkeypatch.setattr(subprocess, "run", fake)
    with pytest.raises(proc.ToolError) as exc:
        proc.run(["terraform", "plan"])
    assert exc.value.returncode == 3
    assert "boom" in str(exc.value)
    assert exc.value.argv == ("terraform", "plan")


def test_run_accepts_extra_ok_codes(monkeypatch: pytest.MonkeyPatch) -> None:
    def fake(argv, **kw):
        return subprocess.CompletedProcess(argv, 2, stdout="", stderr="")

    monkeypatch.setattr(subprocess, "run", fake)
    result = proc.run(["terraform", "plan", "-detailed-exitcode"], ok_codes=frozenset({0, 2}))
    assert result.returncode == 2


def test_run_passes_cwd_and_env(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    captured: dict[str, object] = {}

    def fake(argv, **kw):
        captured.update(kw)
        return subprocess.CompletedProcess(argv, 0, stdout="", stderr="")

    monkeypatch.setattr(subprocess, "run", fake)
    proc.run(["true"], cwd=tmp_path, env={"A": "1"})
    assert captured["cwd"] == tmp_path
    assert captured["env"] == {"A": "1"}


def test_missing_binary_is_tool_error(monkeypatch: pytest.MonkeyPatch) -> None:
    def fake(argv, **kw):
        raise FileNotFoundError(argv[0])

    monkeypatch.setattr(subprocess, "run", fake)
    with pytest.raises(proc.ToolError) as exc:
        proc.run(["definitely-not-a-binary"])
    assert exc.value.returncode == 127


def test_which() -> None:
    assert proc.which("python3") is True
    assert proc.which("definitely-not-a-binary-xyz") is False
