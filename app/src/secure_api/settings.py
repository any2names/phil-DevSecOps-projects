"""Runtime settings. APP_SECRET is injected by fetch-secret.sh (VM) or the container runtime."""

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="APP_")

    secret: str = Field(
        min_length=16, description="Runtime secret from Key Vault / Secrets Manager"
    )
    env: str = "dev"
