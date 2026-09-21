import random

import pytest
from hypothesis import given
from hypothesis import strategies as st
from typer.testing import CliRunner

from platformctl import config, secrets
from platformctl.adapters.fake import FakeAdapter
from platformctl.cli import app


@given(
    st.integers(min_value=16, max_value=128),
    st.text(alphabet="abcXYZ019-_", min_size=10, max_size=30),
)
def test_generate_secret_respects_policy(length: int, alphabet: str) -> None:
    value = secrets.generate_secret(config.SecretPolicy(length=length, alphabet=alphabet))
    assert len(value) == length and set(value) <= set(alphabet)


def test_generate_secret_uses_system_random_by_default() -> None:
    a = secrets.generate_secret(config.SecretPolicy())
    b = secrets.generate_secret(config.SecretPolicy())
    assert a != b


def test_generate_secret_deterministic_with_seeded_rng() -> None:
    policy = config.SecretPolicy(length=20)
    first = secrets.generate_secret(policy, rng=random.Random(1))  # noqa: S311
    second = secrets.generate_secret(policy, rng=random.Random(1))  # noqa: S311
    assert first == second


def test_rotate_dry_run_changes_nothing() -> None:
    adapter = FakeAdapter()
    adapter.put_secret_version("api-key", "old")
    result = secrets.rotate(adapter, "api-key", config.SecretPolicy(), execute=False)
    assert result.executed is False and result.new_version is None
    assert adapter.get_secret("api-key") == "old"


def test_rotate_execute_adds_version_and_deprecates_previous() -> None:
    adapter = FakeAdapter()
    v0 = adapter.put_secret_version("api-key", "old")
    result = secrets.rotate(adapter, "api-key", config.SecretPolicy(length=24), execute=True)
    assert result.executed and result.new_version and result.deprecated == [v0.version]
    assert adapter.get_secret("api-key") != "old" and len(adapter.get_secret("api-key")) == 24
    assert adapter.list_secret_versions("api-key")[0].enabled is False


def test_rotate_new_secret_has_nothing_to_deprecate() -> None:
    result = secrets.rotate(FakeAdapter(), "fresh", config.SecretPolicy(), execute=True)
    assert result.deprecated == [] and result.new_version


def test_cli_secrets_rotate_and_list(
    settings: config.Settings, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(settings.repo_root)
    r = CliRunner().invoke(app, ["secrets", "rotate", "db-password"])
    assert r.exit_code == 0, r.output
    assert "DRY RUN" in r.output
    r = CliRunner().invoke(app, ["secrets", "rotate", "db-password", "--execute"])
    assert r.exit_code == 0 and "rotated" in r.output
    r = CliRunner().invoke(app, ["secrets", "list", "db-password"])
    assert r.exit_code == 0 and "db-password" in r.output
