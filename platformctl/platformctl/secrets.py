"""Secret generation and rotation. Dry-run by default; the value is never printed."""

import random
from collections.abc import Sequence

from pydantic import BaseModel

from platformctl.adapters.base import CloudAdapter
from platformctl.config import SecretPolicy
from platformctl.logging import get_logger

log = get_logger(__name__)


def generate_secret(policy: SecretPolicy, rng: random.Random | None = None) -> str:
    chooser: random.Random = rng or random.SystemRandom()
    alphabet: Sequence[str] = policy.alphabet
    return "".join(chooser.choice(alphabet) for _ in range(policy.length))


class RotationResult(BaseModel):
    name: str
    executed: bool
    new_version: str | None = None
    deprecated: list[str] = []


def rotate(
    adapter: CloudAdapter, name: str, policy: SecretPolicy, *, execute: bool
) -> RotationResult:
    previous = [v for v in adapter.list_secret_versions(name) if v.enabled]
    log.info("secrets.rotate", name=name, execute=execute, active_versions=len(previous))
    if not execute:
        return RotationResult(name=name, executed=False)
    new = adapter.put_secret_version(name, generate_secret(policy))
    deprecated: list[str] = []
    for old in previous:
        adapter.deprecate_version(name, old.version)
        deprecated.append(old.version)
    return RotationResult(name=name, executed=True, new_version=new.version, deprecated=deprecated)
