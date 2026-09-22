"""Pin GitHub Actions `uses:` references to commit SHAs (supply-chain hygiene)."""

import json
import re
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

from platformctl import proc

_USES = re.compile(
    r"^(?P<indent>\s*-?\s*uses:\s*)(?P<repo>[\w.-]+/[\w.-]+)(?P<path>(?:/[\w.-]+)*)"
    r"@(?P<ref>[^\s#]+)(?P<rest>.*)$"
)
_SHA = re.compile(r"^[0-9a-f]{40}$")
# SLSA verifies the generator workflow by tag; SHA pins are rejected by design.
SKIP_REPOS = {"slsa-framework/slsa-github-generator"}


@dataclass(frozen=True)
class Use:
    repo: str
    path: str
    ref: str
    line: int


def find_unpinned(text: str) -> list[Use]:
    out: list[Use] = []
    for i, line in enumerate(text.splitlines(), start=1):
        m = _USES.match(line)
        if not m or m["repo"] in SKIP_REPOS or _SHA.match(m["ref"]):
            continue
        out.append(Use(repo=m["repo"], path=m["path"], ref=m["ref"], line=i))
    return out


def _gh(path: str) -> dict[str, object] | None:
    result = proc.run(["gh", "api", path], ok_codes=frozenset({0, 1}))
    if result.returncode != 0:
        return None
    data: dict[str, object] = json.loads(result.stdout)
    return data


def resolve_sha(repo: str, ref: str) -> str:
    data = _gh(f"repos/{repo}/git/ref/tags/{ref}") or _gh(f"repos/{repo}/git/ref/heads/{ref}")
    if data is None:
        raise LookupError(f"{repo}@{ref}: not a tag or branch")
    obj = data["object"]
    if not isinstance(obj, dict):
        raise LookupError(f"{repo}@{ref}: unexpected API response")
    if obj["type"] == "tag":  # annotated tag → dereference to the commit
        tag = _gh(f"repos/{repo}/git/tags/{obj['sha']}")
        if tag is None or not isinstance(tag.get("object"), dict):
            raise LookupError(f"{repo}@{ref}: cannot dereference annotated tag")
        inner: dict[str, object] = tag["object"]  # type: ignore[assignment]
        return str(inner["sha"])
    return str(obj["sha"])


def pin_text(text: str, resolver: Callable[[str, str], str]) -> str:
    lines = text.splitlines(keepends=True)
    for use in find_unpinned(text):
        idx = use.line - 1
        m = _USES.match(lines[idx].rstrip("\n"))
        if m is None:
            continue
        sha = resolver(use.repo, use.ref)
        newline = f"{m['indent']}{use.repo}{use.path}@{sha} # {use.ref}"
        lines[idx] = newline + ("\n" if lines[idx].endswith("\n") else "")
    return "".join(lines)


def pin_directory(directory: Path, resolver: Callable[[str, str], str]) -> list[Path]:
    changed: list[Path] = []
    for path in sorted(directory.glob("*.yml")):
        original = path.read_text()
        updated = pin_text(original, resolver)
        if updated != original:
            path.write_text(updated)
            changed.append(path)
    return changed
