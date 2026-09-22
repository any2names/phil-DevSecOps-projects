from pathlib import Path

import pytest
from typer.testing import CliRunner

from platformctl import config, supplychain
from platformctl.cli import app
from tests.conftest import RunRecorder


def test_sbom_invokes_syft(tmp_path: Path, fake_run: RunRecorder) -> None:
    out = supplychain.sbom("ghcr.io/x/app:1", tmp_path / "sbom.json")
    assert fake_run.calls[0] == ("syft", "ghcr.io/x/app:1", "-o", f"spdx-json={out}")


def test_sign_and_attest(tmp_path: Path, fake_run: RunRecorder) -> None:
    supplychain.sign("img:1")
    supplychain.attest_sbom("img:1", tmp_path / "sbom.json")
    assert fake_run.calls[0] == ("cosign", "sign", "--yes", "img:1")
    assert fake_run.calls[1][:4] == ("cosign", "attest", "--yes", "--type")


def test_verify_true_false(fake_run: RunRecorder) -> None:
    assert supplychain.verify("img:1", "^https://github.com/o/r/") is True
    fake_run.add(("cosign", "verify"), returncode=1, stderr="no matching signatures")
    assert supplychain.verify("img:1", "^https://github.com/o/r/") is False
    assert "--certificate-oidc-issuer" in fake_run.calls[0]


def test_cli_supplychain_commands(
    settings: config.Settings, fake_run: RunRecorder, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(settings.repo_root)
    runner = CliRunner()
    assert runner.invoke(app, ["sbom", "img:1", "--out", "s.json"]).exit_code == 0
    assert runner.invoke(app, ["sign", "img:1", "--sbom", "s.json"]).exit_code == 0
    assert fake_run.calls[-1][:2] == ("cosign", "attest")
    r = runner.invoke(app, ["verify", "img:1", "--identity-regexp", "^https://github.com/o/r/"])
    assert r.exit_code == 0 and "verified" in r.output
    fake_run.add(("cosign", "verify"), returncode=1)
    r = runner.invoke(app, ["verify", "img:1", "--identity-regexp", "^https://github.com/o/r/"])
    assert r.exit_code == 1 and "NOT verified" in r.output
