# Security Policy

## Reporting a vulnerability

Open a private security advisory on this repository (Security → Advisories → "Report a vulnerability").
Do not open a public issue for security problems. You will get an acknowledgement within 72 hours.

## Scope

- `platformctl/` — Python CLI
- `app/` — FastAPI service and container image
- `infra/`, `ansible/`, `policy/` — infrastructure and policy definitions
- `.github/workflows/` — CI/CD

## What is enforced automatically

- gitleaks (pre-commit + CI) blocks committed secrets.
- Checkov, tfsec and OPA/Conftest gate every Terraform change.
- Trivy scans the filesystem on every PR and the container image on release.
- Release images are signed with cosign (keyless, GitHub OIDC) and ship an SPDX SBOM and SLSA provenance. Verify with `platformctl verify <image>`.
- All GitHub Actions are pinned by commit SHA and updated by Dependabot.
