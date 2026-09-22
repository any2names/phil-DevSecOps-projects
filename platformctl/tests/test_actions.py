from pathlib import Path

import pytest
from typer.testing import CliRunner

from platformctl import actions, config
from platformctl.cli import app
from tests.conftest import RunRecorder

SHA_T = "t" * 40
SHA_C = "c" * 40
WORKFLOW = """
jobs:
  a:
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5.2.0
        with: {python-version: "3.12"}
      - uses: docker/build-push-action@0123456789abcdef0123456789abcdef01234567 # v6.0.0
      - uses: ./.github/actions/local
      - uses: slsa-framework/slsa-github-generator/.github/workflows/gen.yml@v2.0.0
      - uses: aquasecurity/trivy-action/sub/path@0.24.0
"""


def test_find_unpinned() -> None:
    found = actions.find_unpinned(WORKFLOW)
    assert [(u.repo, u.path, u.ref) for u in found] == [
        ("actions/checkout", "", "v4"),
        ("actions/setup-python", "", "v5.2.0"),
        ("aquasecurity/trivy-action", "/sub/path", "0.24.0"),
    ]


def test_pin_text_rewrites_with_comment() -> None:
    out = actions.pin_text(WORKFLOW, resolver=lambda repo, ref: "a" * 40)
    assert "uses: actions/checkout@" + "a" * 40 + " # v4" in out
    assert "uses: aquasecurity/trivy-action/sub/path@" + "a" * 40 + " # 0.24.0" in out
    assert "docker/build-push-action@0123456789abcdef0123456789abcdef01234567 # v6.0.0" in out
    assert "slsa-github-generator/.github/workflows/gen.yml@v2.0.0" in out


def test_resolve_sha_dereferences_annotated_tag(fake_run: RunRecorder) -> None:
    fake_run.add(
        ("gh", "api", "repos/actions/checkout/git/ref/tags/v4"),
        stdout='{"object": {"type": "tag", "sha": "' + SHA_T + '"}}',
    )
    fake_run.add(
        ("gh", "api", "repos/actions/checkout/git/tags/" + SHA_T),
        stdout='{"object": {"sha": "' + SHA_C + '"}}',
    )
    assert actions.resolve_sha("actions/checkout", "v4") == SHA_C


def test_resolve_sha_lightweight_tag(fake_run: RunRecorder) -> None:
    fake_run.add(
        ("gh", "api", "repos/o/r/git/ref/tags/v1"),
        stdout='{"object": {"type": "commit", "sha": "' + "d" * 40 + '"}}',
    )
    assert actions.resolve_sha("o/r", "v1") == "d" * 40


def test_resolve_sha_falls_back_to_branch(fake_run: RunRecorder) -> None:
    fake_run.add(("gh", "api", "repos/o/r/git/ref/tags/main"), returncode=1, stderr="Not Found")
    fake_run.add(
        ("gh", "api", "repos/o/r/git/ref/heads/main"),
        stdout='{"object": {"type": "commit", "sha": "' + "e" * 40 + '"}}',
    )
    assert actions.resolve_sha("o/r", "main") == "e" * 40


def test_resolve_sha_unknown_ref(fake_run: RunRecorder) -> None:
    fake_run.add(("gh", "api"), returncode=1, stderr="Not Found")
    with pytest.raises(LookupError):
        actions.resolve_sha("o/r", "nope")


def test_cli_check_mode(
    settings: config.Settings, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.chdir(settings.repo_root)
    wf = settings.repo_root / ".github/workflows"
    wf.mkdir(parents=True)
    (wf / "ci.yml").write_text(WORKFLOW)
    r = CliRunner().invoke(app, ["actions", "pin", "--check"])
    assert r.exit_code == 1 and "actions/checkout@v4" in r.output
    monkeypatch.setattr(actions, "resolve_sha", lambda repo, ref: "f" * 40)
    r = CliRunner().invoke(app, ["actions", "pin"])
    assert r.exit_code == 0 and "pinned" in r.output
    assert CliRunner().invoke(app, ["actions", "pin", "--check"]).exit_code == 0
