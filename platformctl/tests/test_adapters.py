from datetime import UTC, datetime

import pytest

from platformctl import adapters, config
from platformctl.adapters.base import Certificate, SecretNotFoundError
from platformctl.adapters.fake import FakeAdapter


def test_fake_adapter_versions_and_deprecation() -> None:
    a = FakeAdapter()
    v1 = a.put_secret_version("db-password", "one")
    v2 = a.put_secret_version("db-password", "two")
    assert a.get_secret("db-password") == "two"
    assert [v.version for v in a.list_secret_versions("db-password")] == [v1.version, v2.version]
    a.deprecate_version("db-password", v1.version)
    versions = a.list_secret_versions("db-password")
    assert versions[0].enabled is False and versions[0].tags == {"status": "deprecated"}
    assert versions[1].enabled is True


def test_fake_adapter_missing_secret() -> None:
    with pytest.raises(SecretNotFoundError):
        FakeAdapter().get_secret("nope")
    assert FakeAdapter().list_secret_versions("nope") == []
    with pytest.raises(SecretNotFoundError):
        FakeAdapter().deprecate_version("nope", "v0")


def test_fake_adapter_certificates() -> None:
    cert = Certificate(
        name="api",
        subject="CN=api.example.com",
        not_after=datetime(2030, 1, 1, tzinfo=UTC),
        source="fake",
    )
    assert FakeAdapter(certificates=[cert]).list_certificates() == [cert]


def test_get_adapter_fake(settings: config.Settings) -> None:
    assert isinstance(adapters.get_adapter(settings), FakeAdapter)


def test_get_adapter_azure_requires_sdk(
    settings: config.Settings, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(settings, "adapter", "azure")
    monkeypatch.delenv("AZURE_KEY_VAULT_URL", raising=False)
    with pytest.raises((ImportError, adapters.AdapterConfigError)):
        adapters.get_adapter(settings)


def test_get_adapter_aws_requires_sdk(
    settings: config.Settings, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(settings, "adapter", "aws")
    with pytest.raises((ImportError, adapters.AdapterConfigError)):
        adapters.get_adapter(settings)
