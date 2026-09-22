# platformctl

Typed Python CLI that orchestrates the platform. Every external tool call goes through `proc.run()` (logged, timed, typed errors); every cloud call goes through a `CloudAdapter` (`fake` for tests/CI, `azure`, `aws`).

| Command | Does |
|---|---|
| `plan <cloud> <env> [--no-policy]` | terragrunt plan → JSON → change table → OPA/Conftest gate (exit 1 on deny). Hermetic when no credentials are set (ADR-0007) |
| `scan [--fail-on high] [--tool …] [--out results.sarif]` | checkov, tfsec, gitleaks, trivy → one SARIF; exit 1 above threshold |
| `drift <cloud> <env> [--accept] [--report f.md]` | plan vs accepted baseline; exit 2 on drift |
| `ansible inventory <cloud> <env>` | Terraform outputs → `ansible/inventory/<cloud>-<env>.yml` |
| `secrets rotate <name> [--execute]` · `secrets list <name>` | new version + deprecate old; dry-run default; values never printed |
| `certs check [--warn-days N] [--no-probe]` | store certificates + live TLS probes; exit 1 if expiring |
| `sbom` · `sign` · `verify` | syft SBOM, cosign keyless sign/attest, verify by OIDC identity |
| `actions pin [--check]` | SHA-pin GitHub Actions `uses:` references (annotated tags dereferenced) |

Config: `platformctl.toml` at the repo root (found by walking up from cwd).

    make test        # pytest + hypothesis, coverage ≥ 85%
    make lint        # ruff + mypy --strict
