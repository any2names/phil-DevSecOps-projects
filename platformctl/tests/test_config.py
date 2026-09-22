from pathlib import Path

import pytest

from platformctl import config

TOML = """
adapter = "fake"
infra_dir = "infra"
policy_dir = "policy/terraform"
state_dir = ".platformctl"
warn_days = 14

[secret_policy]
length = 20
alphabet = "abcdefghij"

[[cert_targets]]
host = "example.org"
"""


def test_load_settings_from_explicit_path(tmp_path: Path) -> None:
    (tmp_path / "platformctl.toml").write_text(TOML)
    s = config.load_settings(tmp_path / "platformctl.toml")
    assert s.repo_root == tmp_path
    assert s.infra_dir == tmp_path / "infra"
    assert s.policy_dir == tmp_path / "policy" / "terraform"
    assert s.warn_days == 14
    assert s.secret_policy.length == 20
    assert s.cert_targets[0].host == "example.org"
    assert s.cert_targets[0].port == 443


def test_load_settings_walks_up_from_cwd(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    (tmp_path / "platformctl.toml").write_text(TOML)
    nested = tmp_path / "a" / "b"
    nested.mkdir(parents=True)
    monkeypatch.chdir(nested)
    assert config.load_settings().repo_root == tmp_path


def test_missing_config_raises(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.chdir(tmp_path)
    with pytest.raises(config.ConfigError):
        config.load_settings()


def test_invalid_adapter_rejected(tmp_path: Path) -> None:
    (tmp_path / "platformctl.toml").write_text('adapter = "gcp"\n')
    with pytest.raises(config.ConfigError):
        config.load_settings(tmp_path / "platformctl.toml")


def test_enums() -> None:
    assert config.CloudName("azure") is config.CloudName.azure
    assert config.EnvName("prod").value == "prod"
