"""Azure Key Vault adapter.

SDK imports live inside methods so this module imports without azure-* installed.
"""

import os
from datetime import UTC, datetime
from typing import Any

from platformctl.adapters.base import Certificate, CloudAdapter, SecretNotFoundError, SecretVersion


class AzureKeyVaultAdapter(CloudAdapter):
    def __init__(self, vault_url: str) -> None:
        from azure.identity import DefaultAzureCredential
        from azure.keyvault.certificates import CertificateClient
        from azure.keyvault.secrets import SecretClient

        credential = DefaultAzureCredential()
        self._secrets: Any = SecretClient(vault_url=vault_url, credential=credential)
        self._certs: Any = CertificateClient(vault_url=vault_url, credential=credential)

    @classmethod
    def from_env(cls) -> "AzureKeyVaultAdapter":
        url = os.environ.get("AZURE_KEY_VAULT_URL")
        if not url:
            raise ValueError("AZURE_KEY_VAULT_URL is required for the azure adapter")
        return cls(url)

    def get_secret(self, name: str) -> str:
        from azure.core.exceptions import ResourceNotFoundError

        try:
            return str(self._secrets.get_secret(name).value)
        except ResourceNotFoundError as exc:
            raise SecretNotFoundError(name) from exc

    def put_secret_version(self, name: str, value: str) -> SecretVersion:
        s = self._secrets.set_secret(name, value)
        return SecretVersion(
            name=name,
            version=s.properties.version,
            created=s.properties.created_on or datetime.now(UTC),
        )

    def list_secret_versions(self, name: str) -> list[SecretVersion]:
        return [
            SecretVersion(
                name=name,
                version=p.version,
                created=p.created_on or datetime.now(UTC),
                enabled=bool(p.enabled),
                tags=dict(p.tags or {}),
            )
            for p in self._secrets.list_properties_of_secret_versions(name)
        ]

    def deprecate_version(self, name: str, version: str) -> None:
        self._secrets.update_secret_properties(
            name, version=version, enabled=False, tags={"status": "deprecated"}
        )

    def list_certificates(self) -> list[Certificate]:
        out: list[Certificate] = []
        for p in self._certs.list_properties_of_certificates():
            cert = self._certs.get_certificate(p.name)
            out.append(
                Certificate(
                    name=p.name,
                    subject=str(cert.policy.subject or ""),
                    not_after=p.expires_on,
                    source="azure-keyvault",
                )
            )
        return out
