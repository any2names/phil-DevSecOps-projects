# Runbook: compromised signing identity

Signing is keyless; the "identity" is the `release.yml` workflow in this repository. A compromise means someone could run that workflow (stolen maintainer account, malicious merge).

1. Freeze: disable the `release` workflow in Actions and set branch protection to require reviews from a second maintainer.
2. Identify the window: Rekor holds an immutable log. Search `rekor-cli search --email <identity>` or the Sigstore search UI for entries in the suspicious period.
3. Revoke trust: consumers must add the compromised time window to their verification, e.g. `cosign verify ... ` plus an explicit denylist of digests published in this repo's `SECURITY.md`.
4. Rebuild: fix the cause, rotate the maintainer credentials, re-tag and re-release. New signatures come from the same identity but a later timestamp; the SLSA provenance records the exact commit.
5. Publish an advisory listing affected digests.
