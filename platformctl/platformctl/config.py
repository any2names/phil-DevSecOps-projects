"""Typed runtime configuration loaded from platformctl.toml."""

import tomllib
from enum import StrEnum
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, Field, ValidationError

CONFIG_FILENAME = "platformctl.toml"


class ConfigError(RuntimeError):
    pass


class CloudName(StrEnum):
    azure = "azure"
    aws = "aws"


class EnvName(StrEnum):
    dev = "dev"
    prod = "prod"


class SecretPolicy(BaseModel):
    length: int = Field(default=40, ge=16, le=256)
    alphabet: str = Field(
        default="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_",
        min_length=10,
    )


class CertTarget(BaseModel):
    host: str
    port: int = Field(default=443, ge=1, le=65535)


class Settings(BaseModel):
    repo_root: Path
    adapter: Literal["fake", "azure", "aws"] = "fake"
    infra_dir: Path = Path("infra")
    policy_dir: Path = Path("policy/terraform")
    state_dir: Path = Path(".platformctl")
    warn_days: int = Field(default=30, ge=1)
    secret_policy: SecretPolicy = SecretPolicy()
    cert_targets: list[CertTarget] = []

    def model_post_init(self, _ctx: object) -> None:
        for name in ("infra_dir", "policy_dir", "state_dir"):
            value: Path = getattr(self, name)
            if not value.is_absolute():
                setattr(self, name, self.repo_root / value)


def find_config(start: Path | None = None) -> Path:
    current = (start or Path.cwd()).resolve()
    for candidate in (current, *current.parents):
        path = candidate / CONFIG_FILENAME
        if path.is_file():
            return path
    raise ConfigError(f"{CONFIG_FILENAME} not found in {current} or any parent")


def load_settings(path: Path | None = None) -> Settings:
    config_path = path.resolve() if path else find_config()
    try:
        raw = tomllib.loads(config_path.read_text())
        return Settings(repo_root=config_path.parent, **raw)
    except (tomllib.TOMLDecodeError, ValidationError) as exc:
        raise ConfigError(f"invalid {config_path}: {exc}") from exc
