"""Abstract cloud adapter.

Everything that touches a cloud API goes through this interface so the CLI is
testable with FakeAdapter and never needs credentials in CI.
"""

from abc import ABC, abstractmethod
from datetime import datetime

from pydantic import BaseModel


class SecretNotFoundError(KeyError):
    pass


class SecretVersion(BaseModel):
    name: str
    version: str
    created: datetime
    enabled: bool = True
    tags: dict[str, str] = {}


class Certificate(BaseModel):
    name: str
    subject: str
    not_after: datetime
    source: str


class CloudAdapter(ABC):
    @abstractmethod
    def get_secret(self, name: str) -> str: ...

    @abstractmethod
    def put_secret_version(self, name: str, value: str) -> SecretVersion: ...

    @abstractmethod
    def list_secret_versions(self, name: str) -> list[SecretVersion]: ...

    @abstractmethod
    def deprecate_version(self, name: str, version: str) -> None: ...

    @abstractmethod
    def list_certificates(self) -> list[Certificate]: ...
