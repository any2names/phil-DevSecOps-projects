# Secure API Platform — Design Spec

**Date:** 2026-09-21
**Status:** Approved
**Purpose:** Portfolio repository demonstrating IaC, workflow orchestration, cloud-native automation, advanced Python, and DevSecOps practice for a job application. Every artifact must map to a job-description skill and be verifiable in CI without cloud credentials.

## 1. Goals and constraints

### Goals
- Demonstrate, with real working code: Terraform, Terragrunt, Ansible, ARM templates, GitHub Actions, advanced Python, policy-as-code, security-integrated CI/CD, secrets and certificate management, and software supply-chain security.
- One coherent system, not a grab-bag: a FastAPI service deployed onto a CIS-hardened VM in Azure and AWS, orchestrated by a Python CLI.
- Documentation good enough that a hiring manager can follow the story top-to-bottom in ten minutes.

### Constraints
- **Validate-only CI.** No cloud credentials in GitHub. CI proves correctness, policy compliance, scanning and signing. Apply is a manually-triggered, environment-gated workflow documented as "requires account setup".
- **Multi-cloud.** Azure and AWS, behind an identical Terraform module contract.
- **Local dev without Docker.** Docker-dependent steps (Molecule, Trivy image scan) run in CI only; `make ci` skips them locally with a clear message.
- **Zero secrets in repo**, enforced by gitleaks in pre-commit and CI.

### Skill → artifact map (must appear in README)
| JD skill | Artifact |
|---|---|
| Infrastructure-as-code | `infra/terraform/modules/*`, `infra/arm/keyvault.json` |
| Workflow orchestration | `platformctl/` CLI, `.github/workflows/*` |
| Cloud-native automation | Dynamic Ansible inventory from Terraform outputs, managed-identity secret access |
| Terraform | `infra/terraform/`, `terraform test` |
| Ansible | `ansible/roles/{harden,app_deploy}`, Molecule tests |
| ARM templates | `infra/arm/keyvault.json` wrapped by `azurerm_resource_group_template_deployment` |
| GitHub / GitHub Actions | Reusable workflows, SHA-pinned actions, OIDC, environments, SARIF upload |
| Advanced Python | `platformctl/` — typer, pydantic, structlog, hypothesis, mypy strict |
| Secure-by-design | Threat model, hardened systemd units, least-privilege IAM in modules |
| Policy-as-code | `policy/terraform/*.rego` + Conftest, Checkov |
| CI/CD with integrated security | `ci.yml` gates: fmt → validate → plan → OPA → Checkov/tfsec → gitleaks → Trivy |
| Secrets / certificate management | Key Vault + Secrets Manager modules, `platformctl secrets rotate`, `platformctl certs check`, ACME in `app_deploy` |
| Supply chain (bonus) | syft SBOM, cosign keyless signing, SLSA provenance |

## 2. Repository layout

```
phil-DevSecOps-projects/
├── README.md
├── CONTRIBUTING.md
├── SECURITY.md
├── LICENSE                      # MIT
├── Makefile
├── pyproject.toml
├── .pre-commit-config.yaml
├── .github/
│   ├── dependabot.yml
│   └── workflows/
│       ├── ci.yml               # every PR / push to main
│       ├── release.yml          # on tag: build, sign, SBOM, provenance
│       ├── apply.yml            # workflow_dispatch, environment-gated, OIDC
│       ├── _reusable-terraform.yml
│       ├── _reusable-python.yml
│       └── _reusable-security.yml
├── docs/
│   ├── architecture.md          # Mermaid: infra, pipeline, secret flow
│   ├── threat-model.md          # STRIDE table
│   ├── adr/0001..0006-*.md
│   └── runbooks/{deploy,rotate-secrets,respond-to-drift,revoke-signing}.md
├── app/
│   ├── README.md
│   ├── src/secure_api/          # FastAPI service
│   ├── tests/
│   └── Dockerfile               # distroless, non-root
├── infra/
│   ├── README.md
│   ├── terragrunt.hcl           # root: backend + provider generation
│   ├── terraform/
│   │   └── modules/
│   │       ├── network/{azure,aws}/
│   │       ├── compute/{azure,aws}/
│   │       └── secrets/{azure,aws}/
│   ├── envs/{dev,prod}/{azure,aws}/terragrunt.hcl
│   └── arm/
│       ├── keyvault.json
│       └── keyvault.parameters.json
├── ansible/
│   ├── README.md
│   ├── ansible.cfg
│   ├── playbooks/site.yml
│   ├── roles/harden/
│   ├── roles/app_deploy/
│   └── molecule/default/
├── policy/
│   ├── README.md
│   ├── terraform/*.rego
│   └── terraform/*_test.rego
└── platformctl/
    ├── README.md
    ├── platformctl/
    │   ├── cli.py
    │   ├── config.py
    │   ├── terraform.py
    │   ├── ansible.py
    │   ├── policy.py
    │   ├── scan.py
    │   ├── drift.py
    │   ├── secrets.py
    │   ├── certs.py
    │   ├── supplychain.py
    │   └── adapters/{base,azure,aws,fake}.py
    └── tests/
```

## 3. Components

### 3.1 Terraform + Terragrunt
- Three modules — `network`, `compute`, `secrets` — each with `azure/` and `aws/` implementations that share one `variables.tf` contract: `project`, `environment`, `region`, `cidr`, `allowed_ssh_cidrs`, `instance_size`, `tags`. Outputs are likewise identical: `vm_public_ip`, `vm_private_ip`, `secret_store_id`, `identity_id`.
- Security defaults inside modules: disks encrypted, no public ingress except 443 (and 22 only from `allowed_ssh_cidrs`), IMDSv2 required (AWS), managed identity / instance profile with read-only secret access, boot diagnostics / flow logs on.
- Terragrunt root `terragrunt.hcl` generates provider and backend blocks. Backend config uses placeholder bucket / storage-account names; CI and local runs use `terragrunt plan --terragrunt-no-auto-init` with `-backend=false` equivalent via `TERRAGRUNT_DISABLE_BACKEND`-style override documented in `infra/README.md`.
- `envs/prod` inputs enforce stricter values (no `0.0.0.0/0`, larger instance allow-list, `deletion_protection = true`).
- Each module has a `tests/*.tftest.hcl` using `terraform test` with `command = plan` and mock providers.

### 3.2 ARM template
- `infra/arm/keyvault.json`: Key Vault with RBAC authorization, purge protection, soft delete, public network access disabled, diagnostic settings. Parameters file with placeholder values.
- Consumed by `modules/secrets/azure` via `azurerm_resource_group_template_deployment`, so the ARM template is part of the real deployment path.
- Validated in CI with `arm-ttk` (PowerShell) and JSON schema check.

### 3.3 Ansible
- `roles/harden`: CIS-inspired — SSH (no root, no password auth, allowed ciphers), auditd rules, unattended-upgrades, fail2ban, sysctl hardening, remove unneeded packages, umask, login banners.
- `roles/app_deploy`: service user, Python venv, app install, systemd unit with `ProtectSystem=strict`, `NoNewPrivileges=yes`, `PrivateTmp=yes`, `CapabilityBoundingSet=`; secrets fetched at start via `az keyvault` / `aws secretsmanager` using the instance identity; TLS via certbot (ACME) with renewal timer; nginx reverse proxy with TLS 1.2+ only.
- Inventory is generated by `platformctl ansible inventory <cloud> <env>` from Terraform outputs into `ansible/inventory/<cloud>-<env>.yml`.
- Molecule scenario (Docker driver, Ubuntu 22.04 image) converges both roles and runs `verify.yml` assertions. Runs in CI only.
- `ansible-lint` in pre-commit and CI.

### 3.4 Python — `platformctl`
- Stack: Python 3.12+, `typer`, `pydantic` v2 (typed config from `platformctl.toml` + env), `structlog`, `rich` tables, `httpx`. `mypy --strict`, `ruff`, `pytest`, `hypothesis` for plan-JSON parsing property tests.
- Cloud access goes through `adapters.base.CloudAdapter` (abstract: `get_secret`, `put_secret_version`, `list_secret_versions`, `deprecate_version`, `list_certificates`). `azure` and `aws` adapters wrap the respective SDKs; `fake` adapter is in-memory for tests. Adapter selected by config; SDK imports are lazy so tests never need cloud packages configured.
- Commands:
  - `plan <cloud> <env>` — runs terragrunt plan, converts to JSON, runs policy gate, prints resource-change summary table. Non-zero exit if policy fails.
  - `scan [--fail-on high]` — runs Checkov, tfsec, gitleaks, Trivy (fs mode); normalises findings into a single SARIF 2.1.0 file; applies severity threshold.
  - `drift <cloud> <env>` — `plan -detailed-exitcode`; compares to `.platformctl/last-good/<cloud>-<env>.json`; writes markdown drift report.
  - `ansible inventory <cloud> <env>` — Terraform outputs → YAML inventory.
  - `secrets rotate <name> [--execute]` — generates a new value (length/charset from config), writes a new version via adapter, tags previous version `deprecated`. Dry-run unless `--execute`.
  - `certs check [--warn-days 30]` — lists certificates via adapter plus optional TLS probe of configured endpoints; table + non-zero exit if any under threshold.
  - `sbom`, `sign`, `verify` — wrap syft and cosign for the app image.
- Every external process call goes through `platformctl.proc.run()` which logs command, duration and exit code and raises a typed `ToolError` with stderr.
- Tests: unit tests per module with fake adapter and stubbed `proc.run`; property tests for plan-JSON parser; CLI smoke tests via `typer.testing.CliRunner`. Target ≥ 85% coverage.

### 3.5 Policy-as-code
- Rego policies under `policy/terraform/`, evaluated with Conftest against `terraform show -json` output:
  - `deny_public_ingress` — only 443 from `0.0.0.0/0`; 22 only from listed CIDRs
  - `require_encryption` — disks, storage, secret stores encrypted
  - `require_tags` — `project`, `environment`, `owner`, `cost-center`
  - `deny_inline_secrets` — no values matching secret patterns in plan
  - `instance_allowlist` — sizes per environment
  - `prod_deletion_protection`
- Each policy has a `_test.rego`; `conftest verify` runs in CI.
- Checkov runs alongside with a `.checkov.yaml` config; suppressions must carry a justification comment.

### 3.6 GitHub Actions
- All actions pinned by commit SHA; `permissions:` minimal per job; Dependabot updates actions weekly.
- `ci.yml` (PR + push to main), fan-out jobs:
  1. `python` — ruff, mypy, pytest with coverage (reusable)
  2. `terraform` — fmt, validate, terragrunt plan (no backend, fake vars), `terraform test`, Conftest, upload plan JSON artifact (reusable)
  3. `arm` — arm-ttk + schema
  4. `ansible` — ansible-lint, Molecule
  5. `security` — Checkov, tfsec, gitleaks, Trivy fs → SARIF → `github/codeql-action/upload-sarif` (reusable)
  6. `app` — pytest, build image, Trivy image scan
- `release.yml` (on `v*` tag): build + push image to GHCR, `cosign sign` keyless via GitHub OIDC, syft SBOM attached as attestation, SLSA provenance via `slsa-framework/slsa-github-generator`.
- `apply.yml`: `workflow_dispatch` with `cloud` + `env` inputs; `environment: prod` requires reviewer; OIDC federation steps present but documented as requiring account setup. Never runs green in this repo.

### 3.7 Secrets and certificate management
- IaC provisions Key Vault (Azure, via ARM) and Secrets Manager (AWS) with least-privilege access from the VM identity only.
- App reads secrets at startup through the identity; nothing in env files or repo.
- Rotation: `platformctl secrets rotate` + `docs/runbooks/rotate-secrets.md`.
- Certificates: ACME via certbot on the VM, `platformctl certs check` for expiry monitoring, runbook for manual renewal.
- gitleaks in pre-commit and CI; `.gitleaks.toml` with allow-list only for documented placeholders.

### 3.8 Supply chain
- App image: multi-stage build to distroless, non-root, pinned base digest.
- SBOM (SPDX JSON) via syft; cosign keyless signing and attestation; SLSA L3 provenance on release.
- `platformctl verify <image>` checks signature and provenance and exits non-zero on failure.
- Runbook `revoke-signing.md` covers compromised-identity response.

## 4. Documentation
- `README.md`: pitch, Mermaid architecture diagram, skill → artifact table, CI badges, quickstart, "what does not run without cloud accounts", future work.
- `docs/architecture.md`: infra topology (both clouds), pipeline with gates, identity and secret flow.
- `docs/threat-model.md`: STRIDE table with mitigations linked to specific files.
- ADRs: 0001 multi-cloud module contract; 0002 Terragrunt over workspaces; 0003 OPA/Conftest over Sentinel; 0004 validate-only CI; 0005 keyless cosign; 0006 ARM wrapped in Terraform.
- Runbooks: deploy, rotate-secrets, respond-to-drift, revoke-signing.
- README in `app/`, `infra/`, `ansible/`, `policy/`, `platformctl/`.
- `CONTRIBUTING.md`, `SECURITY.md`, `LICENSE`.

## 5. Testing

| Layer | Tool | Local (no Docker) | CI |
|---|---|---|---|
| Python | pytest, hypothesis, mypy strict, ruff | yes | yes |
| Terraform | fmt, validate, plan (no backend), terraform test | yes | yes |
| Policy | conftest verify + conftest test | yes | yes |
| Ansible | ansible-lint | yes | yes |
| Ansible | Molecule | skipped with message | yes |
| App | pytest | yes | yes |
| App image | Trivy image scan | skipped with message | yes |
| ARM | JSON schema, arm-ttk | schema only | both |
| Supply chain | cosign, syft, SLSA | no | on tag |

`make ci` runs the full local set and prints which steps were skipped and why.

## 6. Definition of done
- `make ci` passes locally with no cloud credentials and no Docker.
- `ci.yml` green on `main` in GitHub.
- Every JD skill has at least one row in the README table pointing at a real file.
- Every top-level directory has a README.
- All six ADRs and four runbooks written in full.
- No `TODO`, `TBD` or placeholder text outside of explicitly documented backend / account placeholders.

## 7. Out of scope
Actual cloud apply, Kubernetes, HashiCorp Vault server, multi-region, cost tooling, Windows targets. Listed under "future work" in the README.
