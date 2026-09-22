"""Wrappers around syft and cosign. Keyless signing needs an OIDC identity (GitHub Actions)."""

from pathlib import Path

from platformctl import proc

GITHUB_ISSUER = "https://token.actions.githubusercontent.com"


def sbom(image: str, out: Path) -> Path:
    proc.run(["syft", image, "-o", f"spdx-json={out}"])
    return out


def sign(image: str) -> None:
    proc.run(["cosign", "sign", "--yes", image])


def attest_sbom(image: str, sbom_path: Path) -> None:
    proc.run(
        ["cosign", "attest", "--yes", "--type", "spdxjson", "--predicate", str(sbom_path), image]
    )


def verify(image: str, identity_regexp: str, issuer: str = GITHUB_ISSUER) -> bool:
    result = proc.run(
        [
            "cosign",
            "verify",
            "--certificate-identity-regexp",
            identity_regexp,
            "--certificate-oidc-issuer",
            issuer,
            image,
        ],
        ok_codes=frozenset({0, 1}),
    )
    return result.returncode == 0
