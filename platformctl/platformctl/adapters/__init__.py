"""Adapter factory."""

from platformctl.adapters.base import Certificate, CloudAdapter, SecretNotFoundError, SecretVersion
from platformctl.adapters.fake import FakeAdapter
from platformctl.config import Settings


class AdapterConfigError(RuntimeError):
    pass


def get_adapter(settings: Settings) -> CloudAdapter:
    if settings.adapter == "fake":
        return FakeAdapter()
    if settings.adapter == "azure":
        from platformctl.adapters.azure import AzureKeyVaultAdapter

        try:
            return AzureKeyVaultAdapter.from_env()
        except ValueError as exc:
            raise AdapterConfigError(str(exc)) from exc
    if settings.adapter == "aws":
        from platformctl.adapters.aws import AwsAdapter

        return AwsAdapter()
    raise AdapterConfigError(f"unknown adapter {settings.adapter}")


__all__ = [
    "AdapterConfigError",
    "Certificate",
    "CloudAdapter",
    "FakeAdapter",
    "SecretNotFoundError",
    "SecretVersion",
    "get_adapter",
]
