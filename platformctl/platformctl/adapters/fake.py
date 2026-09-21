"""In-memory adapter for tests and demos."""

import uuid
from datetime import UTC, datetime

from platformctl.adapters.base import Certificate, CloudAdapter, SecretNotFoundError, SecretVersion


class FakeAdapter(CloudAdapter):
    def __init__(self, certificates: list[Certificate] | None = None) -> None:
        self._secrets: dict[str, list[tuple[SecretVersion, str]]] = {}
        self._certs = list(certificates or [])

    def get_secret(self, name: str) -> str:
        versions = self._secrets.get(name)
        if not versions:
            raise SecretNotFoundError(name)
        return versions[-1][1]

    def put_secret_version(self, name: str, value: str) -> SecretVersion:
        version = SecretVersion(name=name, version=uuid.uuid4().hex[:12], created=datetime.now(UTC))
        self._secrets.setdefault(name, []).append((version, value))
        return version

    def list_secret_versions(self, name: str) -> list[SecretVersion]:
        return [v for v, _ in self._secrets.get(name, [])]

    def deprecate_version(self, name: str, version: str) -> None:
        for i, (v, value) in enumerate(self._secrets.get(name, [])):
            if v.version == version:
                updated = v.model_copy(update={"enabled": False, "tags": {"status": "deprecated"}})
                self._secrets[name][i] = (updated, value)
                return
        raise SecretNotFoundError(f"{name}@{version}")

    def list_certificates(self) -> list[Certificate]:
        return list(self._certs)
