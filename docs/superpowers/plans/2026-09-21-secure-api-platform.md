# Secure API Platform Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a portfolio-grade DevSecOps repository: a FastAPI service deployed to CIS-hardened VMs on Azure and AWS via Terraform/Terragrunt + ARM + Ansible, orchestrated by a typed Python CLI (`platformctl`), gated by OPA policy and security scanners in GitHub Actions, with keyless signing and SBOM on release — all verifiable in CI with no cloud credentials.

**Architecture:** `platformctl` shells out to terragrunt → captures plan JSON → Conftest/OPA gate → Checkov/tfsec/gitleaks/Trivy normalised to SARIF → Ansible inventory generated from Terraform outputs → Ansible hardens and deploys. Azure and AWS live behind an identical module contract; the Azure secrets module wraps an ARM template. CI proves correctness, policy compliance, scanning and signing; `apply.yml` is manual, environment-gated, and documented as requiring account setup.

**Tech Stack:** Python 3.12+ (typer, pydantic v2, structlog, rich, httpx, PyYAML; pytest, hypothesis, mypy --strict, ruff), Terraform ≥1.7 + Terragrunt, ARM (JSON), Ansible + Molecule, OPA/Rego + Conftest, Checkov, tfsec, gitleaks, Trivy, syft, cosign, slsa-github-generator, GitHub Actions.

**Spec:** `docs/superpowers/specs/2026-09-21-secure-api-platform-design.md`

## Global Constraints

- **Validate-only CI.** No cloud credentials in GitHub. CI never applies. `apply.yml` is `workflow_dispatch` + `environment: prod` and is documented as requiring account setup.
- **Zero secrets in repo.** gitleaks runs in pre-commit and CI. Only documented placeholders (`REPLACE_ME_*`, `ami-0123456789abcdef0`, `tfstate-placeholder`, the all-zero GUID, and the three literal dev/test secret strings `local-dev-only-not-a-real-secret`, `ci-only-secret`, `test-secret-value`) are allow-listed.
- **Local dev has no Docker.** Molecule and Trivy *image* scans run in CI only; `make ci` prints `SKIP: <step> (docker not available)` and continues.
- **Python ≥ 3.12**, `mypy --strict` clean, `ruff` clean, `pytest` coverage ≥ 85% for `platformctl`.
- **Terraform ≥ 1.7** (needed for `terraform test` mock providers). Terragrunt ≥ 0.55.
- **Module contract** (both clouds): inputs `project`, `environment`, `region`, `cidr`, `allowed_ssh_cidrs`, `instance_size`, `tags`; stack outputs `vm_public_ip`, `vm_private_ip`, `secret_store_id`, `identity_id`.
- **Backend selection** via `TG_BACKEND` env: `local` (default) or `remote`.
- **Required tags** on every taggable resource: `project`, `environment`, `owner`, `cost-center`.
- **GitHub Actions**: every `uses:` pinned to a full commit SHA with a `# vX.Y.Z` trailing comment; every job declares minimal `permissions:`.
- **Commit convention:** Conventional Commits (`feat:`, `fix:`, `docs:`, `ci:`, `test:`, `chore:`). Every commit message ends with `Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>`.
- **No `TODO`/`TBD`** in committed files except the explicitly documented placeholders above.

## File structure (what each file is responsible for)

```
pyproject.toml                  # tool config only: ruff, mypy, pytest (no [project])
platformctl.toml                # runtime config for platformctl (adapter=fake by default)
Makefile                        # local entrypoints; `make ci` = everything runnable without Docker
.pre-commit-config.yaml         # ruff, mypy, terraform fmt, ansible-lint, gitleaks
.gitleaks.toml                  # allow-list for documented placeholders only
.checkov.yaml                   # framework + skip list with justifications
platformctl/pyproject.toml      # installable package `platformctl` + console script
platformctl/platformctl/
  proc.py        # run() wrapper: logging, timing, ToolError
  config.py      # pydantic Settings + load_settings()
  terraform.py   # terragrunt plan/show/outputs, PlanSummary parser
  policy.py      # conftest wrapper -> PolicyResult
  scan.py        # scanner runners, SARIF merge, Finding, thresholds
  drift.py       # compare PlanSummary, DriftReport, markdown render
  adapters/      # CloudAdapter ABC, fake, azure, aws, get_adapter()
  secrets.py     # generate_secret(), rotate()
  certs.py       # probe_tls(), evaluate() -> CertStatus
  ansible.py     # build_inventory(), write_inventory()
  supplychain.py # syft/cosign wrappers
  cli.py         # typer app wiring only — no logic
platformctl/tests/              # one test file per module + conftest.py with fixtures
app/pyproject.toml, app/src/secure_api/{__init__,main,settings}.py, app/tests/, app/Dockerfile
infra/terraform/modules/{network,compute,secrets}/{azure,aws}/{main,variables,outputs}.tf + tests/plan.tftest.hcl
infra/terraform/stacks/{azure,aws}/{main,variables,outputs}.tf   # composition root per cloud
infra/terragrunt.hcl, infra/envs/{dev,prod}/{azure,aws}/terragrunt.hcl
infra/arm/keyvault.json, infra/arm/keyvault.parameters.json
policy/terraform/{ingress,encryption,tags,secrets,instances,protection}.rego + *_test.rego
ansible/{ansible.cfg,playbooks/site.yml,roles/harden,roles/app_deploy,molecule/default}
scripts/pin_actions.py          # resolves `uses: x/y@vN` -> SHA, keeps `# vN` comment
.github/workflows/{ci,release,apply,_reusable-python,_reusable-terraform,_reusable-security}.yml
docs/{architecture,threat-model}.md, docs/adr/000{1..6}-*.md, docs/runbooks/*.md
README.md + README.md in app/ infra/ ansible/ policy/ platformctl/
```

---

## Phase 0 — Scaffold

### Task 1: Repository scaffold and local toolchain

**Files:**
- Create: `.gitignore`, `.editorconfig`, `LICENSE`, `CONTRIBUTING.md`, `SECURITY.md`, `pyproject.toml`, `platformctl.toml`, `Makefile`, `.pre-commit-config.yaml`, `.gitleaks.toml`, `.checkov.yaml`

**Interfaces:**
- Produces: `make bootstrap`, `make lint`, `make test`, `make ci` targets used by every later task; `.venv/` with dev tooling.

- [ ] **Step 1: Install / upgrade local tools (macOS, brew)**

Run:
```bash
brew install hashicorp/tap/terraform terragrunt conftest checkov gitleaks trivy tfsec opa cosign syft 2>&1 | tail -5
brew upgrade hashicorp/tap/terraform 2>&1 | tail -1
terraform version | head -1   # must print v1.7 or newer
terragrunt --version && conftest --version && checkov --version && gitleaks version
```
Expected: terraform ≥ 1.7; every tool prints a version. If `hashicorp/tap/terraform` conflicts with the existing `/usr/local/bin/terraform`, run `brew unlink terraform && brew link hashicorp/tap/terraform`.

- [ ] **Step 2: Write `.gitignore` and `.editorconfig`**

`.gitignore`:
```gitignore
# Python
.venv/
__pycache__/
*.pyc
.pytest_cache/
.mypy_cache/
.ruff_cache/
.coverage
htmlcov/
dist/
*.egg-info/

# Terraform / Terragrunt
**/.terraform/
**/.terragrunt-cache/
*.tfstate
*.tfstate.*
*.tfplan
crash.log
.terraform.lock.hcl

# platformctl outputs
.platformctl/
ansible/inventory/*.yml
!ansible/inventory/.gitkeep

# Scanner outputs
*.sarif
sbom.*.json

# OS / editor
.DS_Store
.idea/
.vscode/
```

`.editorconfig`:
```ini
root = true

[*]
charset = utf-8
end_of_line = lf
insert_final_newline = true
trim_trailing_whitespace = true
indent_style = space
indent_size = 2

[*.py]
indent_size = 4

[Makefile]
indent_style = tab
```

- [ ] **Step 3: Write `LICENSE` (MIT), `CONTRIBUTING.md`, `SECURITY.md`**

`LICENSE`:
```text
MIT License

Copyright (c) 2026 Phillip James

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

`CONTRIBUTING.md`:
```markdown
# Contributing

## Local setup

    make bootstrap        # creates .venv, installs platformctl + app in editable mode, installs pre-commit hooks
    make ci               # runs everything CI runs that does not need Docker

## Workflow

1. Branch from `main` (`feat/<topic>`, `fix/<topic>`, `docs/<topic>`).
2. Write the failing test first, then the implementation.
3. `make ci` must pass before opening a PR.
4. Commits follow Conventional Commits (`feat:`, `fix:`, `docs:`, `ci:`, `test:`, `chore:`).
5. PRs require the `ci` workflow green and one review.

## Where things live

| Area | Directory | Test command |
|---|---|---|
| Python CLI | `platformctl/` | `make test` |
| App | `app/` | `make test` |
| Terraform modules | `infra/terraform/modules` | `make tf-test` |
| Policies | `policy/` | `make policy-test` |
| Ansible | `ansible/` | `make ansible-lint`, `make molecule` (CI only) |

## Security findings

Scanner suppressions (`# checkov:skip`, `#tfsec:ignore`, `.gitleaks.toml` allow-list) must carry a one-line justification on the same line or in the config file. See `SECURITY.md` for reporting vulnerabilities.
```

`SECURITY.md`:
```markdown
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
```

- [ ] **Step 4: Write root `pyproject.toml` (tool config only)**

```toml
[tool.ruff]
line-length = 100
target-version = "py312"
src = ["platformctl", "app/src"]

[tool.ruff.lint]
select = ["E", "F", "I", "B", "UP", "S", "N", "ANN", "RUF"]
ignore = ["ANN401"]  # Any is acceptable for **kwargs passthrough

[tool.ruff.lint.per-file-ignores]
"**/tests/**" = ["S101", "S106", "ANN"]  # asserts and test passwords are fine in tests

[tool.mypy]
python_version = "3.12"
strict = true
warn_unreachable = true
files = ["platformctl/platformctl", "app/src", "scripts"]
mypy_path = "platformctl:app/src"

[[tool.mypy.overrides]]
module = ["azure.*", "boto3", "botocore.*", "yaml"]
ignore_missing_imports = true

[tool.pytest.ini_options]
testpaths = ["platformctl/tests", "app/tests"]
addopts = "-ra --strict-markers"
markers = ["integration: needs external tools on PATH"]

[tool.coverage.run]
source = ["platformctl/platformctl"]
branch = true

[tool.coverage.report]
fail_under = 85
show_missing = true
```

- [ ] **Step 5: Write `platformctl.toml`**

```toml
# Runtime configuration for platformctl. Paths are relative to the repo root.
adapter = "fake"            # fake | azure | aws  (fake needs no credentials)
infra_dir = "infra"
policy_dir = "policy/terraform"
state_dir = ".platformctl"
warn_days = 30

[secret_policy]
length = 40
alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"

[[cert_targets]]
host = "example.com"
port = 443
```

- [ ] **Step 6: Write `Makefile`**

```makefile
SHELL := /bin/bash
VENV  := .venv
PY    := $(VENV)/bin/python
PIP   := $(VENV)/bin/pip
HAS_DOCKER := $(shell command -v docker >/dev/null 2>&1 && docker info >/dev/null 2>&1 && echo yes || echo no)

.PHONY: bootstrap lint test tf-fmt tf-validate tf-test policy-test ansible-lint molecule scan arm-check ci clean

bootstrap: $(VENV)/bin/activate
$(VENV)/bin/activate:
	python3 -m venv $(VENV)
	$(PIP) install --upgrade pip
	$(PIP) install -e "./platformctl[dev]" -e "./app[dev]" pre-commit ansible ansible-lint "molecule>=6" "molecule-plugins[docker]"
	$(VENV)/bin/pre-commit install

lint: bootstrap
	$(VENV)/bin/ruff check .
	$(VENV)/bin/ruff format --check .
	$(VENV)/bin/mypy

test: bootstrap
	$(VENV)/bin/pytest --cov --cov-report=term-missing

tf-fmt:
	terraform fmt -check -recursive infra/terraform

tf-validate:
	@for d in infra/terraform/modules/*/* infra/terraform/stacks/*; do \
	  echo "== $$d"; (cd $$d && terraform init -backend=false -input=false >/dev/null && terraform validate) || exit 1; \
	done

tf-test:
	@for d in infra/terraform/modules/*/*; do \
	  echo "== $$d"; (cd $$d && terraform init -backend=false -input=false >/dev/null && terraform test) || exit 1; \
	done

policy-test:
	conftest verify -p policy/terraform --data policy/terraform

ansible-lint: bootstrap
	cd ansible && ../$(VENV)/bin/ansible-lint

molecule: bootstrap
ifeq ($(HAS_DOCKER),yes)
	cd ansible && ../$(VENV)/bin/molecule test
else
	@echo "SKIP: molecule (docker not available)"
endif

scan: bootstrap
	$(VENV)/bin/platformctl scan --fail-on high

arm-check:
	$(PY) -c "import json,sys; json.load(open('infra/arm/keyvault.json')); json.load(open('infra/arm/keyvault.parameters.json')); print('ARM JSON ok')"

ci: lint test tf-fmt tf-validate tf-test policy-test ansible-lint molecule arm-check scan
	@echo "CI (local subset) passed"

clean:
	rm -rf $(VENV) .platformctl .pytest_cache .mypy_cache .ruff_cache htmlcov .coverage
	find . -name '.terraform' -type d -prune -exec rm -rf {} + 2>/dev/null || true
	find . -name '.terragrunt-cache' -type d -prune -exec rm -rf {} + 2>/dev/null || true
```

- [ ] **Step 7: Write `.pre-commit-config.yaml`, `.gitleaks.toml`, `.checkov.yaml`**

`.pre-commit-config.yaml`:
```yaml
repos:
  - repo: https://github.com/pre-commit/pre-commit-hooks
    rev: v4.6.0
    hooks:
      - id: end-of-file-fixer
      - id: trailing-whitespace
      - id: check-yaml
        args: [--allow-multiple-documents]
      - id: check-json
      - id: check-added-large-files
  - repo: https://github.com/astral-sh/ruff-pre-commit
    rev: v0.6.9
    hooks:
      - id: ruff
        args: [--fix]
      - id: ruff-format
  - repo: https://github.com/antonbabenko/pre-commit-terraform
    rev: v1.96.1
    hooks:
      - id: terraform_fmt
      - id: terraform_validate
        args: [--hook-config=--retry-once-with-cleanup=true]
  - repo: https://github.com/ansible/ansible-lint
    rev: v24.9.2
    hooks:
      - id: ansible-lint
        files: ^ansible/
  - repo: https://github.com/gitleaks/gitleaks
    rev: v8.20.1
    hooks:
      - id: gitleaks
```

`.gitleaks.toml`:
```toml
title = "secure-api-platform gitleaks config"

[extend]
useDefault = true

[allowlist]
description = "Documented placeholders only. Anything else that looks like a secret is a finding."
regexes = [
  '''REPLACE_ME_[A-Z_]+''',
  '''ami-0123456789abcdef0''',
  '''tfstate-placeholder''',
  '''00000000-0000-0000-0000-000000000000''',
  '''local-dev-only-not-a-real-secret''',
  '''ci-only-secret''',
  '''test-secret-value''',
]
paths = [
  '''docs/superpowers/.*''',
]
```

`.checkov.yaml`:
```yaml
directory:
  - infra/terraform
  - infra/arm
  - app
framework:
  - terraform
  - arm
  - dockerfile
  - github_actions
compact: true
quiet: true
# Every skip needs a justification. Keep this list short.
skip-check:
  - CKV_AZURE_50   # VM extensions are intentionally allowed for the Azure Monitor agent installed by Ansible
  - CKV_AWS_79     # false positive: IMDSv2 is enforced via metadata_options http_tokens=required
```

- [ ] **Step 8: Create minimal package stubs so `make bootstrap` can install**

`platformctl/pyproject.toml`:
```toml
[build-system]
requires = ["setuptools>=69", "wheel"]
build-backend = "setuptools.build_meta"

[project]
name = "platformctl"
version = "0.1.0"
description = "Orchestration CLI for the secure-api-platform: plan, policy, scan, drift, secrets, certs, supply chain."
requires-python = ">=3.12"
dependencies = [
  "typer>=0.12",
  "pydantic>=2.7",
  "structlog>=24.1",
  "rich>=13.7",
  "httpx>=0.27",
  "PyYAML>=6.0",
]

[project.optional-dependencies]
dev = ["pytest>=8", "pytest-cov>=5", "hypothesis>=6.100", "mypy>=1.11", "ruff>=0.6", "types-PyYAML"]
azure = ["azure-identity>=1.17", "azure-keyvault-secrets>=4.8", "azure-keyvault-certificates>=4.8"]
aws = ["boto3>=1.34"]

[project.scripts]
platformctl = "platformctl.cli:app"

[tool.setuptools.packages.find]
where = ["."]
include = ["platformctl*"]
```

`platformctl/platformctl/__init__.py`:
```python
"""platformctl — orchestration CLI for the secure-api-platform."""

__version__ = "0.1.0"
```

`platformctl/platformctl/cli.py` (temporary skeleton; Task 2 replaces it):
```python
"""Typer entrypoint. Wiring only — no business logic lives here."""

import typer

app = typer.Typer(no_args_is_help=True, help="secure-api-platform orchestration CLI")


@app.callback()
def _root() -> None:
    """secure-api-platform orchestration CLI."""
```

`platformctl/tests/__init__.py`: empty file.

`app/pyproject.toml`:
```toml
[build-system]
requires = ["setuptools>=69", "wheel"]
build-backend = "setuptools.build_meta"

[project]
name = "secure-api"
version = "0.1.0"
description = "Minimal FastAPI service deployed by the secure-api-platform."
requires-python = ">=3.11"  # distroless python3-debian12 ships 3.11
dependencies = ["fastapi>=0.115", "uvicorn[standard]>=0.30", "pydantic-settings>=2.4"]

[project.optional-dependencies]
dev = ["pytest>=8", "httpx>=0.27"]

[tool.setuptools.packages.find]
where = ["src"]
```

`app/src/secure_api/__init__.py`:
```python
"""secure-api service package."""

__version__ = "0.1.0"
```

`app/tests/` — create the directory with no `__init__.py` (a second `tests` package would collide with `platformctl/tests`; pytest imports these by basename). Add an empty `app/tests/.gitkeep` so the directory is committed.

- [ ] **Step 9: Bootstrap and verify lint passes on the empty skeleton**

Run: `make bootstrap && make lint`
Expected: venv created, packages installed, `ruff` and `mypy` report no errors (`Success: no issues found`).

- [ ] **Step 10: Run pre-commit once and commit**

Run: `.venv/bin/pre-commit run --all-files` — expected: all hooks pass or skip (terraform/ansible hooks have no files yet).

```bash
git add -A
git commit -m "chore: scaffold repository tooling, packaging and security config

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>"
```

---

## Phase 1 — `platformctl` (Python CLI, TDD)

### Task 2: `proc.run()`, typed settings, CLI skeleton

**Files:**
- Create: `platformctl/platformctl/proc.py`, `platformctl/platformctl/config.py`, `platformctl/platformctl/logging.py`
- Modify: `platformctl/platformctl/cli.py`
- Test: `platformctl/tests/conftest.py`, `platformctl/tests/test_proc.py`, `platformctl/tests/test_config.py`, `platformctl/tests/test_cli.py`

**Interfaces:**
- Produces:
  - `proc.run(argv: Sequence[str], *, cwd: Path | None = None, env: Mapping[str, str] | None = None, ok_codes: frozenset[int] = frozenset({0})) -> CommandResult`
  - `proc.CommandResult(argv: tuple[str, ...], returncode: int, stdout: str, stderr: str, duration_s: float)` (frozen dataclass)
  - `proc.ToolError(RuntimeError)` with attributes `argv`, `returncode`, `stderr`
  - `proc.which(name: str) -> bool`
  - `config.CloudName` (`StrEnum`: `azure`, `aws`), `config.EnvName` (`StrEnum`: `dev`, `prod`)
  - `config.SecretPolicy(length: int, alphabet: str)`, `config.CertTarget(host: str, port: int = 443)`
  - `config.Settings(repo_root: Path, adapter: Literal["fake","azure","aws"], infra_dir: Path, policy_dir: Path, state_dir: Path, warn_days: int, secret_policy: SecretPolicy, cert_targets: list[CertTarget])`
  - `config.load_settings(path: Path | None = None) -> Settings` — finds `platformctl.toml` walking up from cwd when `path` is None; `repo_root` = the toml's parent; relative dirs are resolved against it.
  - `cli.app` (typer) with `--version`; later tasks add commands.
  - Test fixture `settings(tmp_path)` and `fake_run(monkeypatch)` in `conftest.py`.

- [ ] **Step 1: Write failing tests for `proc`**

`platformctl/tests/test_proc.py`:
```python
import subprocess
from pathlib import Path

import pytest

from platformctl import proc


def test_run_returns_result_with_timing(monkeypatch: pytest.MonkeyPatch) -> None:
    def fake(argv, **kw):  # noqa: ANN001, ANN003
        return subprocess.CompletedProcess(argv, 0, stdout="hi\n", stderr="")

    monkeypatch.setattr(subprocess, "run", fake)
    result = proc.run(["echo", "hi"])
    assert result.returncode == 0
    assert result.stdout == "hi\n"
    assert result.argv == ("echo", "hi")
    assert result.duration_s >= 0


def test_run_raises_tool_error_with_stderr(monkeypatch: pytest.MonkeyPatch) -> None:
    def fake(argv, **kw):  # noqa: ANN001, ANN003
        return subprocess.CompletedProcess(argv, 3, stdout="", stderr="boom")

    monkeypatch.setattr(subprocess, "run", fake)
    with pytest.raises(proc.ToolError) as exc:
        proc.run(["terraform", "plan"])
    assert exc.value.returncode == 3
    assert "boom" in str(exc.value)
    assert exc.value.argv == ("terraform", "plan")


def test_run_accepts_extra_ok_codes(monkeypatch: pytest.MonkeyPatch) -> None:
    def fake(argv, **kw):  # noqa: ANN001, ANN003
        return subprocess.CompletedProcess(argv, 2, stdout="", stderr="")

    monkeypatch.setattr(subprocess, "run", fake)
    assert proc.run(["terraform", "plan", "-detailed-exitcode"], ok_codes=frozenset({0, 2})).returncode == 2


def test_run_passes_cwd_and_env(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    captured: dict[str, object] = {}

    def fake(argv, **kw):  # noqa: ANN001, ANN003
        captured.update(kw)
        return subprocess.CompletedProcess(argv, 0, stdout="", stderr="")

    monkeypatch.setattr(subprocess, "run", fake)
    proc.run(["true"], cwd=tmp_path, env={"A": "1"})
    assert captured["cwd"] == tmp_path
    assert captured["env"] == {"A": "1"}


def test_missing_binary_is_tool_error(monkeypatch: pytest.MonkeyPatch) -> None:
    def fake(argv, **kw):  # noqa: ANN001, ANN003
        raise FileNotFoundError(argv[0])

    monkeypatch.setattr(subprocess, "run", fake)
    with pytest.raises(proc.ToolError) as exc:
        proc.run(["definitely-not-a-binary"])
    assert exc.value.returncode == 127


def test_which() -> None:
    assert proc.which("python3") is True
    assert proc.which("definitely-not-a-binary-xyz") is False
```

- [ ] **Step 2: Run to verify failure**

Run: `.venv/bin/pytest platformctl/tests/test_proc.py -q`
Expected: `ImportError: cannot import name 'proc'` (or ModuleNotFoundError).

- [ ] **Step 3: Implement `logging.py` and `proc.py`**

`platformctl/platformctl/logging.py`:
```python
"""structlog configuration. Call configure() once from the CLI callback."""

import logging
import sys

import structlog


def configure(verbose: bool = False) -> None:
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(level=level, stream=sys.stderr, format="%(message)s")
    structlog.configure(
        processors=[
            structlog.contextvars.merge_contextvars,
            structlog.processors.add_log_level,
            structlog.processors.TimeStamper(fmt="iso"),
            structlog.dev.ConsoleRenderer(colors=sys.stderr.isatty()),
        ],
        wrapper_class=structlog.make_filtering_bound_logger(level),
        logger_factory=structlog.PrintLoggerFactory(file=sys.stderr),
        cache_logger_on_first_use=False,
    )


def get_logger(name: str) -> structlog.stdlib.BoundLogger:
    return structlog.get_logger(name)  # type: ignore[no-any-return]
```

`platformctl/platformctl/proc.py`:
```python
"""Single choke point for running external tools.

Every subprocess in platformctl goes through run() so that command, duration and
exit code are logged uniformly and failures surface as a typed ToolError.
"""

import shutil
import subprocess
import time
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path

from platformctl.logging import get_logger

log = get_logger(__name__)


@dataclass(frozen=True)
class CommandResult:
    argv: tuple[str, ...]
    returncode: int
    stdout: str
    stderr: str
    duration_s: float


class ToolError(RuntimeError):
    def __init__(self, argv: Sequence[str], returncode: int, stderr: str) -> None:
        self.argv = tuple(argv)
        self.returncode = returncode
        self.stderr = stderr
        super().__init__(f"{' '.join(self.argv)} exited {returncode}: {stderr.strip()}")


def which(name: str) -> bool:
    return shutil.which(name) is not None


def run(
    argv: Sequence[str],
    *,
    cwd: Path | None = None,
    env: Mapping[str, str] | None = None,
    ok_codes: frozenset[int] = frozenset({0}),
) -> CommandResult:
    started = time.perf_counter()
    log.debug("exec", argv=list(argv), cwd=str(cwd) if cwd else None)
    try:
        completed = subprocess.run(  # noqa: S603 — argv is a list, never a shell string
            list(argv),
            cwd=cwd,
            env=dict(env) if env is not None else None,
            capture_output=True,
            text=True,
            check=False,
        )
    except FileNotFoundError as exc:
        raise ToolError(argv, 127, f"binary not found: {exc}") from exc
    duration = time.perf_counter() - started
    result = CommandResult(tuple(argv), completed.returncode, completed.stdout, completed.stderr, duration)
    log.info("exec.done", argv0=argv[0], returncode=result.returncode, duration_s=round(duration, 3))
    if result.returncode not in ok_codes:
        raise ToolError(argv, result.returncode, result.stderr)
    return result
```

- [ ] **Step 4: Run proc tests**

Run: `.venv/bin/pytest platformctl/tests/test_proc.py -q`
Expected: 6 passed.

- [ ] **Step 5: Write failing tests for `config`**

`platformctl/tests/test_config.py`:
```python
from pathlib import Path

import pytest

from platformctl import config

TOML = """
adapter = "fake"
infra_dir = "infra"
policy_dir = "policy/terraform"
state_dir = ".platformctl"
warn_days = 14

[secret_policy]
length = 12
alphabet = "abc"

[[cert_targets]]
host = "example.org"
"""


def test_load_settings_from_explicit_path(tmp_path: Path) -> None:
    (tmp_path / "platformctl.toml").write_text(TOML)
    s = config.load_settings(tmp_path / "platformctl.toml")
    assert s.repo_root == tmp_path
    assert s.infra_dir == tmp_path / "infra"
    assert s.policy_dir == tmp_path / "policy" / "terraform"
    assert s.warn_days == 14
    assert s.secret_policy.length == 12
    assert s.cert_targets[0].host == "example.org"
    assert s.cert_targets[0].port == 443


def test_load_settings_walks_up_from_cwd(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    (tmp_path / "platformctl.toml").write_text(TOML)
    nested = tmp_path / "a" / "b"
    nested.mkdir(parents=True)
    monkeypatch.chdir(nested)
    assert config.load_settings().repo_root == tmp_path


def test_missing_config_raises(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.chdir(tmp_path)
    with pytest.raises(config.ConfigError):
        config.load_settings()


def test_invalid_adapter_rejected(tmp_path: Path) -> None:
    (tmp_path / "platformctl.toml").write_text('adapter = "gcp"\n')
    with pytest.raises(config.ConfigError):
        config.load_settings(tmp_path / "platformctl.toml")


def test_enums() -> None:
    assert config.CloudName("azure") is config.CloudName.azure
    assert config.EnvName("prod").value == "prod"
```

- [ ] **Step 6: Run to verify failure**

Run: `.venv/bin/pytest platformctl/tests/test_config.py -q`
Expected: ImportError.

- [ ] **Step 7: Implement `config.py`**

```python
"""Typed runtime configuration loaded from platformctl.toml."""

import tomllib
from enum import StrEnum
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, Field, ValidationError

CONFIG_FILENAME = "platformctl.toml"


class ConfigError(RuntimeError):
    pass


class CloudName(StrEnum):
    azure = "azure"
    aws = "aws"


class EnvName(StrEnum):
    dev = "dev"
    prod = "prod"


class SecretPolicy(BaseModel):
    length: int = Field(default=40, ge=16, le=256)
    alphabet: str = Field(default="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_", min_length=10)


class CertTarget(BaseModel):
    host: str
    port: int = Field(default=443, ge=1, le=65535)


class Settings(BaseModel):
    repo_root: Path
    adapter: Literal["fake", "azure", "aws"] = "fake"
    infra_dir: Path = Path("infra")
    policy_dir: Path = Path("policy/terraform")
    state_dir: Path = Path(".platformctl")
    warn_days: int = Field(default=30, ge=1)
    secret_policy: SecretPolicy = SecretPolicy()
    cert_targets: list[CertTarget] = []

    def model_post_init(self, _ctx: object) -> None:
        for name in ("infra_dir", "policy_dir", "state_dir"):
            value: Path = getattr(self, name)
            if not value.is_absolute():
                object.__setattr__(self, name, self.repo_root / value)


def find_config(start: Path | None = None) -> Path:
    current = (start or Path.cwd()).resolve()
    for candidate in (current, *current.parents):
        path = candidate / CONFIG_FILENAME
        if path.is_file():
            return path
    raise ConfigError(f"{CONFIG_FILENAME} not found in {current} or any parent")


def load_settings(path: Path | None = None) -> Settings:
    config_path = path.resolve() if path else find_config()
    try:
        raw = tomllib.loads(config_path.read_text())
        return Settings(repo_root=config_path.parent, **raw)
    except (tomllib.TOMLDecodeError, ValidationError) as exc:
        raise ConfigError(f"invalid {config_path}: {exc}") from exc
```

- [ ] **Step 8: Run config tests**

Run: `.venv/bin/pytest platformctl/tests/test_config.py -q`
Expected: 5 passed.

- [ ] **Step 9: Write shared fixtures and CLI test**

`platformctl/tests/conftest.py`:
```python
"""Shared fixtures. `settings` gives an isolated repo layout; `fake_run` stubs proc.run."""

import subprocess
from collections.abc import Callable
from pathlib import Path

import pytest

from platformctl import config, proc

FakeRun = Callable[[list[str]], subprocess.CompletedProcess[str]]


@pytest.fixture
def settings(tmp_path: Path) -> config.Settings:
    (tmp_path / "platformctl.toml").write_text('adapter = "fake"\n')
    for d in ("infra/envs/dev/azure", "infra/envs/dev/aws", "infra/envs/prod/azure", "policy/terraform"):
        (tmp_path / d).mkdir(parents=True)
    return config.load_settings(tmp_path / "platformctl.toml")


class RunRecorder:
    """Records every argv passed to proc.run and replays canned responses keyed by argv[0:2]."""

    def __init__(self) -> None:
        self.calls: list[tuple[str, ...]] = []
        self.responses: dict[tuple[str, ...], tuple[int, str, str]] = {}

    def add(self, prefix: tuple[str, ...], returncode: int = 0, stdout: str = "", stderr: str = "") -> None:
        self.responses[prefix] = (returncode, stdout, stderr)

    def __call__(self, argv: list[str], **kw: object) -> subprocess.CompletedProcess[str]:
        self.calls.append(tuple(argv))
        for prefix, (code, out, err) in self.responses.items():
            if tuple(argv[: len(prefix)]) == prefix:
                return subprocess.CompletedProcess(argv, code, stdout=out, stderr=err)
        return subprocess.CompletedProcess(argv, 0, stdout="", stderr="")


@pytest.fixture
def fake_run(monkeypatch: pytest.MonkeyPatch) -> RunRecorder:
    rec = RunRecorder()
    monkeypatch.setattr(proc.subprocess, "run", rec)
    return rec
```

`platformctl/tests/test_cli.py`:
```python
from typer.testing import CliRunner

from platformctl import __version__
from platformctl.cli import app

runner = CliRunner()


def test_version() -> None:
    result = runner.invoke(app, ["--version"])
    assert result.exit_code == 0
    assert __version__ in result.output


def test_help_lists_command_groups() -> None:
    result = runner.invoke(app, ["--help"])
    assert result.exit_code == 0
    assert "secure-api-platform" in result.output
```

- [ ] **Step 10: Replace `cli.py` skeleton**

```python
"""Typer entrypoint. Wiring only — no business logic lives here."""

from pathlib import Path
from typing import Annotated

import typer

from platformctl import __version__
from platformctl.config import Settings, load_settings
from platformctl.logging import configure

app = typer.Typer(no_args_is_help=True, help="secure-api-platform orchestration CLI")


def _version_cb(value: bool) -> None:
    if value:
        typer.echo(f"platformctl {__version__}")
        raise typer.Exit()


@app.callback()
def _root(
    ctx: typer.Context,
    config: Annotated[Path | None, typer.Option("--config", "-c", help="Path to platformctl.toml")] = None,
    verbose: Annotated[bool, typer.Option("--verbose", "-v")] = False,
    version: Annotated[bool, typer.Option("--version", callback=_version_cb, is_eager=True)] = False,
) -> None:
    """secure-api-platform orchestration CLI."""
    configure(verbose)
    if ctx.invoked_subcommand is not None:
        ctx.obj = load_settings(config)


def get_settings(ctx: typer.Context) -> Settings:
    settings: Settings = ctx.obj
    return settings
```

- [ ] **Step 11: Run all tests + lint**

Run: `.venv/bin/pytest -q && make lint`
Expected: all pass; mypy clean.

- [ ] **Step 12: Commit**

```bash
git add platformctl
git commit -m "feat(platformctl): process wrapper, typed settings and CLI skeleton

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>"
```

### Task 3: Terraform/Terragrunt wrapper and plan parser

**Files:**
- Create: `platformctl/platformctl/terraform.py`
- Test: `platformctl/tests/test_terraform.py`, `platformctl/tests/fixtures/plan_small.json`

**Interfaces:**
- Consumes: `proc.run`, `config.Settings`, `config.CloudName`, `config.EnvName`
- Produces:
  - `terraform.ResourceChange(address: str, type: str, actions: list[str])`
  - `terraform.PlanSummary(create: int, update: int, delete: int, replace: int, no_op: int, changes: list[ResourceChange])` with method `has_changes() -> bool`
  - `terraform.parse_plan(plan_json: dict[str, Any]) -> PlanSummary`
  - `terraform.env_dir(settings, cloud, env) -> Path` → `<infra_dir>/envs/<env>/<cloud>`
  - `terraform.terragrunt_plan(settings, cloud, env, *, detailed_exitcode: bool = False) -> tuple[Path, int]` — writes `<state_dir>/plans/<cloud>-<env>.json`, returns `(json_path, exit_code)` where exit code is 0 or 2
  - `terraform.terragrunt_outputs(settings, cloud, env) -> dict[str, Any]` — flattened `{name: value}`
  - `terraform.base_env() -> dict[str, str]` — os.environ + `TF_IN_AUTOMATION=1`, `TG_BACKEND` default `local`

- [ ] **Step 1: Create fixture plan JSON**

`platformctl/tests/fixtures/plan_small.json`:
```json
{
  "format_version": "1.2",
  "terraform_version": "1.9.0",
  "resource_changes": [
    {"address": "module.network.azurerm_virtual_network.this", "type": "azurerm_virtual_network", "change": {"actions": ["create"], "after": {"name": "vnet"}}},
    {"address": "module.compute.azurerm_linux_virtual_machine.this", "type": "azurerm_linux_virtual_machine", "change": {"actions": ["delete", "create"], "after": {"size": "Standard_B2s"}}},
    {"address": "module.secrets.azurerm_role_assignment.kv", "type": "azurerm_role_assignment", "change": {"actions": ["update"], "after": {}}},
    {"address": "module.network.azurerm_subnet.this", "type": "azurerm_subnet", "change": {"actions": ["no-op"], "after": {}}},
    {"address": "module.network.azurerm_network_security_rule.old", "type": "azurerm_network_security_rule", "change": {"actions": ["delete"], "before": {}}}
  ]
}
```

- [ ] **Step 2: Write failing tests**

`platformctl/tests/test_terraform.py`:
```python
import json
from pathlib import Path

import pytest
from hypothesis import given
from hypothesis import strategies as st

from platformctl import config, terraform
from tests.conftest import RunRecorder

FIXTURES = Path(__file__).parent / "fixtures"


def test_parse_plan_counts_actions() -> None:
    plan = json.loads((FIXTURES / "plan_small.json").read_text())
    summary = terraform.parse_plan(plan)
    assert (summary.create, summary.update, summary.delete, summary.replace, summary.no_op) == (1, 1, 1, 1, 1)
    assert summary.has_changes()
    assert summary.changes[1].actions == ["delete", "create"]


def test_parse_plan_empty() -> None:
    summary = terraform.parse_plan({"resource_changes": []})
    assert not summary.has_changes()
    assert summary.changes == []


def test_parse_plan_missing_key() -> None:
    assert terraform.parse_plan({}).changes == []


ACTIONS = st.sampled_from([["create"], ["update"], ["delete"], ["no-op"], ["delete", "create"], ["create", "delete"]])


@given(st.lists(st.tuples(st.text(min_size=1), ACTIONS), max_size=30))
def test_parse_plan_totals_match_changes(items: list[tuple[str, list[str]]]) -> None:
    plan = {"resource_changes": [{"address": a, "type": "t", "change": {"actions": acts}} for a, acts in items]}
    s = terraform.parse_plan(plan)
    assert s.create + s.update + s.delete + s.replace + s.no_op == len(items)


def test_env_dir(settings: config.Settings) -> None:
    assert terraform.env_dir(settings, config.CloudName.aws, config.EnvName.dev) == settings.infra_dir / "envs/dev/aws"


def test_env_dir_missing_raises(settings: config.Settings) -> None:
    with pytest.raises(FileNotFoundError):
        terraform.env_dir(settings, config.CloudName.aws, config.EnvName.prod)


def test_terragrunt_plan_writes_json(settings: config.Settings, fake_run: RunRecorder) -> None:
    fake_run.add(("terragrunt", "plan"), returncode=0)
    fake_run.add(("terragrunt", "show"), stdout='{"resource_changes": []}')
    path, code = terraform.terragrunt_plan(settings, config.CloudName.azure, config.EnvName.dev)
    assert code == 0
    assert json.loads(path.read_text()) == {"resource_changes": []}
    assert path == settings.state_dir / "plans" / "azure-dev.json"
    assert fake_run.calls[0][:3] == ("terragrunt", "plan", "-out=tfplan.binary")
    assert fake_run.calls[1] == ("terragrunt", "show", "-json", "tfplan.binary")


def test_terragrunt_plan_detailed_exitcode(settings: config.Settings, fake_run: RunRecorder) -> None:
    fake_run.add(("terragrunt", "plan"), returncode=2)
    fake_run.add(("terragrunt", "show"), stdout="{}")
    _, code = terraform.terragrunt_plan(settings, config.CloudName.azure, config.EnvName.dev, detailed_exitcode=True)
    assert code == 2
    assert "-detailed-exitcode" in fake_run.calls[0]


def test_terragrunt_outputs_flatten(settings: config.Settings, fake_run: RunRecorder) -> None:
    fake_run.add(("terragrunt", "output"), stdout=json.dumps({"vm_public_ip": {"value": "1.2.3.4", "sensitive": False}}))
    assert terraform.terragrunt_outputs(settings, config.CloudName.aws, config.EnvName.dev) == {"vm_public_ip": "1.2.3.4"}


def test_base_env_sets_automation_flags(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("TG_BACKEND", raising=False)
    env = terraform.base_env()
    assert env["TF_IN_AUTOMATION"] == "1"
    assert env["TG_BACKEND"] == "local"
```

- [ ] **Step 3: Run to verify failure**

Run: `.venv/bin/pytest platformctl/tests/test_terraform.py -q`
Expected: ImportError.

- [ ] **Step 4: Implement `terraform.py`**

```python
"""Terragrunt/Terraform wrapper and plan-JSON parser."""

import json
import os
from pathlib import Path
from typing import Any

from pydantic import BaseModel

from platformctl import proc
from platformctl.config import CloudName, EnvName, Settings

PLAN_BINARY = "tfplan.binary"


class ResourceChange(BaseModel):
    address: str
    type: str
    actions: list[str]


class PlanSummary(BaseModel):
    create: int = 0
    update: int = 0
    delete: int = 0
    replace: int = 0
    no_op: int = 0
    changes: list[ResourceChange] = []

    def has_changes(self) -> bool:
        return (self.create + self.update + self.delete + self.replace) > 0


def parse_plan(plan_json: dict[str, Any]) -> PlanSummary:
    summary = PlanSummary()
    for rc in plan_json.get("resource_changes", []):
        actions = list(rc.get("change", {}).get("actions", []))
        change = ResourceChange(address=rc.get("address", "?"), type=rc.get("type", "?"), actions=actions)
        summary.changes.append(change)
        if "create" in actions and "delete" in actions:
            summary.replace += 1
        elif actions == ["create"]:
            summary.create += 1
        elif actions == ["update"]:
            summary.update += 1
        elif actions == ["delete"]:
            summary.delete += 1
        else:
            summary.no_op += 1
    return summary


def base_env() -> dict[str, str]:
    env = dict(os.environ)
    env.setdefault("TF_IN_AUTOMATION", "1")
    env.setdefault("TF_INPUT", "0")
    env.setdefault("TG_BACKEND", "local")
    env.setdefault("TERRAGRUNT_NON_INTERACTIVE", "true")
    return env


def env_dir(settings: Settings, cloud: CloudName, env: EnvName) -> Path:
    path = settings.infra_dir / "envs" / env.value / cloud.value
    if not path.is_dir():
        raise FileNotFoundError(f"no terragrunt unit at {path}")
    return path


def terragrunt_plan(
    settings: Settings, cloud: CloudName, env: EnvName, *, detailed_exitcode: bool = False
) -> tuple[Path, int]:
    unit = env_dir(settings, cloud, env)
    argv = ["terragrunt", "plan", f"-out={PLAN_BINARY}", "-input=false"]
    ok = frozenset({0})
    if detailed_exitcode:
        argv.append("-detailed-exitcode")
        ok = frozenset({0, 2})
    plan_result = proc.run(argv, cwd=unit, env=base_env(), ok_codes=ok)
    show = proc.run(["terragrunt", "show", "-json", PLAN_BINARY], cwd=unit, env=base_env())
    out = settings.state_dir / "plans" / f"{cloud.value}-{env.value}.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(show.stdout)
    return out, plan_result.returncode


def terragrunt_outputs(settings: Settings, cloud: CloudName, env: EnvName) -> dict[str, Any]:
    unit = env_dir(settings, cloud, env)
    result = proc.run(["terragrunt", "output", "-json"], cwd=unit, env=base_env())
    raw: dict[str, dict[str, Any]] = json.loads(result.stdout or "{}")
    return {name: entry.get("value") for name, entry in raw.items()}
```

- [ ] **Step 5: Run tests**

Run: `.venv/bin/pytest platformctl/tests/test_terraform.py -q`
Expected: 10 passed.

- [ ] **Step 6: Commit**

```bash
git add platformctl
git commit -m "feat(platformctl): terragrunt plan/output wrapper and plan parser

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>"
```

### Task 4: Policy gate (Conftest) and the `plan` command

**Files:**
- Create: `platformctl/platformctl/policy.py`, `platformctl/platformctl/render.py`
- Modify: `platformctl/platformctl/cli.py`
- Test: `platformctl/tests/test_policy.py`, `platformctl/tests/test_cli_plan.py`

**Interfaces:**
- Consumes: `proc.run`, `terraform.terragrunt_plan`, `terraform.parse_plan`
- Produces:
  - `policy.PolicyResult(passed: bool, failures: list[str], warnings: list[str], successes: int)`
  - `policy.evaluate(settings, plan_json_path: Path) -> PolicyResult` — runs `conftest test <path> -p <policy_dir> -o json --all-namespaces`
  - `render.plan_table(summary: PlanSummary) -> rich.table.Table`, `render.policy_panel(result: PolicyResult) -> rich.panel.Panel`
  - CLI: `platformctl plan <cloud> <env> [--no-policy]` exits 0 on pass, 1 on policy failure.

- [ ] **Step 1: Write failing tests for `policy`**

`platformctl/tests/test_policy.py`:
```python
import json
from pathlib import Path

from platformctl import config, policy
from tests.conftest import RunRecorder

CONFTEST_FAIL = json.dumps(
    [
        {
            "filename": "plan.json",
            "namespace": "terraform.ingress",
            "successes": 3,
            "failures": [{"msg": "SSH open to the world on aws_security_group.vm"}],
            "warnings": [{"msg": "consider private endpoint"}],
        },
        {"filename": "plan.json", "namespace": "terraform.tags", "successes": 2},
    ]
)


def test_evaluate_parses_failures(settings: config.Settings, fake_run: RunRecorder, tmp_path: Path) -> None:
    plan = tmp_path / "plan.json"
    plan.write_text("{}")
    fake_run.add(("conftest", "test"), returncode=1, stdout=CONFTEST_FAIL)
    result = policy.evaluate(settings, plan)
    assert result.passed is False
    assert result.failures == ["[terraform.ingress] SSH open to the world on aws_security_group.vm"]
    assert result.warnings == ["[terraform.ingress] consider private endpoint"]
    assert result.successes == 5
    assert fake_run.calls[0] == (
        "conftest", "test", str(plan), "-p", str(settings.policy_dir), "-o", "json", "--all-namespaces",
    )


def test_evaluate_pass(settings: config.Settings, fake_run: RunRecorder, tmp_path: Path) -> None:
    plan = tmp_path / "plan.json"
    plan.write_text("{}")
    fake_run.add(("conftest", "test"), returncode=0, stdout='[{"successes": 4}]')
    result = policy.evaluate(settings, plan)
    assert result.passed and result.successes == 4 and result.failures == []
```

- [ ] **Step 2: Run to verify failure**

Run: `.venv/bin/pytest platformctl/tests/test_policy.py -q` — Expected: ImportError.

- [ ] **Step 3: Implement `policy.py` and `render.py`**

`platformctl/platformctl/policy.py`:
```python
"""OPA/Conftest gate over Terraform plan JSON."""

import json
from pathlib import Path

from pydantic import BaseModel

from platformctl import proc
from platformctl.config import Settings


class PolicyResult(BaseModel):
    passed: bool
    failures: list[str] = []
    warnings: list[str] = []
    successes: int = 0


def evaluate(settings: Settings, plan_json_path: Path) -> PolicyResult:
    argv = [
        "conftest", "test", str(plan_json_path),
        "-p", str(settings.policy_dir),
        "-o", "json", "--all-namespaces",
    ]
    # conftest exits 1 when any policy fails; that is data, not an error.
    result = proc.run(argv, ok_codes=frozenset({0, 1}))
    entries = json.loads(result.stdout or "[]")
    failures: list[str] = []
    warnings: list[str] = []
    successes = 0
    for entry in entries:
        ns = entry.get("namespace", "policy")
        successes += int(entry.get("successes", 0))
        failures.extend(f"[{ns}] {f['msg']}" for f in entry.get("failures", []) or [])
        warnings.extend(f"[{ns}] {w['msg']}" for w in entry.get("warnings", []) or [])
    return PolicyResult(passed=not failures, failures=failures, warnings=warnings, successes=successes)
```

`platformctl/platformctl/render.py`:
```python
"""Rich renderers. Pure functions from models to renderables so the CLI stays thin."""

from rich.panel import Panel
from rich.table import Table

from platformctl.policy import PolicyResult
from platformctl.terraform import PlanSummary

_ACTION_STYLE = {"create": "green", "update": "yellow", "delete": "red", "replace": "magenta", "no-op": "dim"}


def _label(actions: list[str]) -> str:
    if "create" in actions and "delete" in actions:
        return "replace"
    return actions[0] if actions else "no-op"


def plan_table(summary: PlanSummary) -> Table:
    table = Table(title=f"Plan: +{summary.create} ~{summary.update} -{summary.delete} ±{summary.replace}")
    table.add_column("Action")
    table.add_column("Type")
    table.add_column("Address")
    for change in summary.changes:
        label = _label(change.actions)
        if label == "no-op":
            continue
        table.add_row(f"[{_ACTION_STYLE[label]}]{label}[/]", change.type, change.address)
    return table


def policy_panel(result: PolicyResult) -> Panel:
    lines = [f"[green]{result.successes} checks passed[/]"]
    lines += [f"[yellow]WARN[/] {w}" for w in result.warnings]
    lines += [f"[red]FAIL[/] {f}" for f in result.failures]
    title = "[green]Policy: PASS" if result.passed else "[red]Policy: FAIL"
    return Panel("\n".join(lines), title=title)
```

- [ ] **Step 4: Run policy tests** — `.venv/bin/pytest platformctl/tests/test_policy.py -q` — Expected: 2 passed.

- [ ] **Step 5: Write failing CLI test for `plan`**

`platformctl/tests/test_cli_plan.py`:
```python
import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from platformctl.cli import app
from tests.conftest import RunRecorder

runner = CliRunner()


@pytest.fixture
def repo(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    (tmp_path / "platformctl.toml").write_text('adapter = "fake"\n')
    (tmp_path / "infra/envs/dev/azure").mkdir(parents=True)
    (tmp_path / "policy/terraform").mkdir(parents=True)
    monkeypatch.chdir(tmp_path)
    return tmp_path


def test_plan_pass(repo: Path, fake_run: RunRecorder) -> None:
    fake_run.add(("terragrunt", "show"), stdout=json.dumps({"resource_changes": [
        {"address": "a", "type": "t", "change": {"actions": ["create"]}}]}))
    fake_run.add(("conftest",), returncode=0, stdout='[{"successes": 2}]')
    result = runner.invoke(app, ["plan", "azure", "dev"])
    assert result.exit_code == 0, result.output
    assert "create" in result.output and "Policy: PASS" in result.output


def test_plan_policy_failure_exits_1(repo: Path, fake_run: RunRecorder) -> None:
    fake_run.add(("terragrunt", "show"), stdout='{"resource_changes": []}')
    fake_run.add(("conftest",), returncode=1, stdout='[{"namespace":"x","failures":[{"msg":"nope"}]}]')
    result = runner.invoke(app, ["plan", "azure", "dev"])
    assert result.exit_code == 1
    assert "nope" in result.output


def test_plan_no_policy_skips_conftest(repo: Path, fake_run: RunRecorder) -> None:
    fake_run.add(("terragrunt", "show"), stdout='{"resource_changes": []}')
    result = runner.invoke(app, ["plan", "azure", "dev", "--no-policy"])
    assert result.exit_code == 0
    assert not any(c[0] == "conftest" for c in fake_run.calls)
```

- [ ] **Step 6: Add `plan` command to `cli.py`**

Append to `cli.py`:
```python
from rich.console import Console  # noqa: E402  (place with the other imports at top of file)
from platformctl import policy as policy_mod, render, terraform  # noqa: E402
from platformctl.config import CloudName, EnvName  # noqa: E402

console = Console()


@app.command()
def plan(
    ctx: typer.Context,
    cloud: CloudName,
    env: EnvName,
    policy: Annotated[bool, typer.Option(help="Run the OPA/Conftest gate on the plan")] = True,
) -> None:
    """Run terragrunt plan for CLOUD/ENV, summarise changes and gate on policy."""
    settings = get_settings(ctx)
    plan_path, _ = terraform.terragrunt_plan(settings, cloud, env)
    summary = terraform.parse_plan(json.loads(plan_path.read_text()))
    console.print(render.plan_table(summary))
    if not policy:
        return
    result = policy_mod.evaluate(settings, plan_path)
    console.print(render.policy_panel(result))
    if not result.passed:
        raise typer.Exit(code=1)
```
(Move the imports to the top of the file with the others and add `import json`; the `# noqa` markers are only to show placement here.)

- [ ] **Step 7: Run all tests + lint** — `.venv/bin/pytest -q && make lint` — Expected: pass.

- [ ] **Step 8: Commit**

```bash
git add platformctl
git commit -m "feat(platformctl): conftest policy gate and plan command

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>"
```

### Task 5: Security scanners normalised to SARIF and the `scan` command

**Files:**
- Create: `platformctl/platformctl/scan.py`
- Modify: `platformctl/platformctl/cli.py`
- Test: `platformctl/tests/test_scan.py`

**Interfaces:**
- Consumes: `proc.run`, `proc.which`
- Produces:
  - `scan.Severity` (`StrEnum`: `low`, `medium`, `high`, `critical`) with ordering helper `scan.SEVERITY_ORDER: dict[Severity, int]`
  - `scan.Finding(tool: str, rule_id: str, severity: Severity, message: str, file: str | None, line: int | None)`
  - `scan.SCANNERS: dict[str, list[str]]` — name → argv template producing SARIF on stdout or file
  - `scan.run_scanner(name: str, repo_root: Path, out_dir: Path) -> dict[str, Any] | None` — returns parsed SARIF or None if tool not installed
  - `scan.merge_sarif(reports: list[dict[str, Any]]) -> dict[str, Any]`
  - `scan.findings_from_sarif(sarif: dict[str, Any]) -> list[Finding]`
  - `scan.exceeds(findings, fail_on: Severity) -> list[Finding]`
  - CLI: `platformctl scan [--fail-on high] [--tool checkov --tool gitleaks ...] [--out results.sarif]`

- [ ] **Step 1: Write failing tests**

`platformctl/tests/test_scan.py`:
```python
import json
from pathlib import Path

import pytest

from platformctl import scan
from tests.conftest import RunRecorder

SARIF = {
    "version": "2.1.0",
    "runs": [
        {
            "tool": {"driver": {"name": "checkov", "rules": [
                {"id": "CKV_AWS_1", "properties": {"security-severity": "8.0"}},
                {"id": "CKV_AWS_2", "properties": {"security-severity": "3.0"}},
            ]}},
            "results": [
                {"ruleId": "CKV_AWS_1", "level": "error", "message": {"text": "bad"},
                 "locations": [{"physicalLocation": {"artifactLocation": {"uri": "main.tf"}, "region": {"startLine": 7}}}]},
                {"ruleId": "CKV_AWS_2", "level": "warning", "message": {"text": "meh"}},
                {"ruleId": "UNKNOWN", "level": "note", "message": {"text": "fyi"}},
            ],
        }
    ],
}


def test_findings_from_sarif_maps_severity_and_location() -> None:
    findings = scan.findings_from_sarif(SARIF)
    assert [f.severity for f in findings] == [scan.Severity.high, scan.Severity.low, scan.Severity.low]
    assert findings[0].file == "main.tf" and findings[0].line == 7 and findings[0].tool == "checkov"
    assert findings[1].file is None


def test_exceeds_threshold() -> None:
    findings = scan.findings_from_sarif(SARIF)
    assert [f.rule_id for f in scan.exceeds(findings, scan.Severity.high)] == ["CKV_AWS_1"]
    assert len(scan.exceeds(findings, scan.Severity.low)) == 3
    assert scan.exceeds(findings, scan.Severity.critical) == []


def test_merge_sarif_concatenates_runs() -> None:
    merged = scan.merge_sarif([SARIF, SARIF])
    assert merged["version"] == "2.1.0" and len(merged["runs"]) == 2


def test_run_scanner_skips_missing_tool(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(scan.proc, "which", lambda _n: False)
    assert scan.run_scanner("checkov", tmp_path, tmp_path) is None


def test_run_scanner_reads_stdout_sarif(tmp_path: Path, fake_run: RunRecorder, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(scan.proc, "which", lambda _n: True)
    fake_run.add(("gitleaks",), returncode=1, stdout="")
    (tmp_path / "gitleaks.sarif").write_text(json.dumps(SARIF))
    result = scan.run_scanner("gitleaks", tmp_path, tmp_path)
    assert result is not None and result["runs"][0]["tool"]["driver"]["name"] == "checkov"
    assert "--report-path" in fake_run.calls[0]


def test_unknown_scanner() -> None:
    with pytest.raises(KeyError):
        scan.run_scanner("nmap", Path("."), Path("."))
```

- [ ] **Step 2: Run to verify failure** — `.venv/bin/pytest platformctl/tests/test_scan.py -q` — Expected: ImportError.

- [ ] **Step 3: Implement `scan.py`**

```python
"""Run security scanners and normalise their SARIF into one report.

Each scanner writes SARIF to <out_dir>/<name>.sarif. Non-zero exit codes mean
"findings present" for every tool here, so they are treated as data.
"""

import json
from enum import StrEnum
from pathlib import Path
from typing import Any

from pydantic import BaseModel

from platformctl import proc
from platformctl.logging import get_logger

log = get_logger(__name__)


class Severity(StrEnum):
    low = "low"
    medium = "medium"
    high = "high"
    critical = "critical"


SEVERITY_ORDER: dict[Severity, int] = {Severity.low: 0, Severity.medium: 1, Severity.high: 2, Severity.critical: 3}


class Finding(BaseModel):
    tool: str
    rule_id: str
    severity: Severity
    message: str
    file: str | None = None
    line: int | None = None


# {out} is replaced with <out_dir>/<name>.sarif; {root} with the repo root.
SCANNERS: dict[str, list[str]] = {
    "checkov": ["checkov", "--config-file", "{root}/.checkov.yaml", "-d", "{root}", "-o", "sarif", "--output-file-path", "{out_dir}"],
    "tfsec": ["tfsec", "{root}/infra/terraform", "--format", "sarif", "--out", "{out}", "--soft-fail"],
    "gitleaks": ["gitleaks", "detect", "--source", "{root}", "--config", "{root}/.gitleaks.toml", "--report-format", "sarif", "--report-path", "{out}", "--no-banner"],
    "trivy": ["trivy", "fs", "--scanners", "vuln,misconfig,secret", "--format", "sarif", "--output", "{out}", "{root}"],
}

# Tools that always exit non-zero when they find something.
_OK_CODES: dict[str, frozenset[int]] = {
    "checkov": frozenset({0, 1}),
    "tfsec": frozenset({0, 1}),
    "gitleaks": frozenset({0, 1}),
    "trivy": frozenset({0, 1}),
}


def _severity_from_score(score: float) -> Severity:
    if score >= 9.0:
        return Severity.critical
    if score >= 7.0:
        return Severity.high
    if score >= 4.0:
        return Severity.medium
    return Severity.low


_LEVEL_FALLBACK: dict[str, Severity] = {"error": Severity.high, "warning": Severity.medium, "note": Severity.low, "none": Severity.low}


def findings_from_sarif(sarif: dict[str, Any]) -> list[Finding]:
    findings: list[Finding] = []
    for run in sarif.get("runs", []):
        driver = run.get("tool", {}).get("driver", {})
        tool = driver.get("name", "unknown")
        scores: dict[str, float] = {}
        for rule in driver.get("rules", []) or []:
            raw = (rule.get("properties") or {}).get("security-severity")
            if raw is not None:
                scores[rule["id"]] = float(raw)
        for res in run.get("results", []) or []:
            rule_id = res.get("ruleId", "unknown")
            if rule_id in scores:
                severity = _severity_from_score(scores[rule_id])
            else:
                severity = _LEVEL_FALLBACK.get(res.get("level", "warning"), Severity.medium)
            file: str | None = None
            line: int | None = None
            locs = res.get("locations") or []
            if locs:
                phys = locs[0].get("physicalLocation", {})
                file = phys.get("artifactLocation", {}).get("uri")
                line = phys.get("region", {}).get("startLine")
            findings.append(Finding(tool=tool, rule_id=rule_id, severity=severity,
                                    message=res.get("message", {}).get("text", ""), file=file, line=line))
    return findings


def merge_sarif(reports: list[dict[str, Any]]) -> dict[str, Any]:
    runs: list[dict[str, Any]] = []
    for report in reports:
        runs.extend(report.get("runs", []))
    return {"$schema": "https://json.schemastore.org/sarif-2.1.0.json", "version": "2.1.0", "runs": runs}


def exceeds(findings: list[Finding], fail_on: Severity) -> list[Finding]:
    threshold = SEVERITY_ORDER[fail_on]
    return [f for f in findings if SEVERITY_ORDER[f.severity] >= threshold]


def run_scanner(name: str, repo_root: Path, out_dir: Path) -> dict[str, Any] | None:
    template = SCANNERS[name]  # KeyError for unknown tools is intentional
    if not proc.which(template[0]):
        log.warning("scanner.missing", tool=name)
        return None
    out = out_dir / f"{name}.sarif"
    argv = [a.format(root=repo_root, out=out, out_dir=out_dir) for a in template]
    proc.run(argv, cwd=repo_root, ok_codes=_OK_CODES[name])
    # checkov names its file results_sarif.sarif inside out_dir
    candidate = out if out.exists() else out_dir / "results_sarif.sarif"
    if not candidate.exists():
        log.warning("scanner.no_output", tool=name)
        return None
    data: dict[str, Any] = json.loads(candidate.read_text())
    if candidate != out:
        candidate.rename(out)
    return data
```

- [ ] **Step 4: Run scan tests** — `.venv/bin/pytest platformctl/tests/test_scan.py -q` — Expected: 6 passed.

- [ ] **Step 5: Add `scan` command to `cli.py`**

```python
@app.command()
def scan(
    ctx: typer.Context,
    fail_on: Annotated[scan_mod.Severity, typer.Option(help="Exit 1 if any finding is at or above this severity")] = scan_mod.Severity.high,
    tool: Annotated[list[str] | None, typer.Option(help="Subset of scanners to run (default: all)")] = None,
    out: Annotated[Path, typer.Option(help="Merged SARIF output path")] = Path("results.sarif"),
) -> None:
    """Run checkov, tfsec, gitleaks and trivy; merge to SARIF; gate on severity."""
    settings = get_settings(ctx)
    out_dir = settings.state_dir / "scan"
    out_dir.mkdir(parents=True, exist_ok=True)
    names = tool or list(scan_mod.SCANNERS)
    reports = [r for name in names if (r := scan_mod.run_scanner(name, settings.repo_root, out_dir)) is not None]
    merged = scan_mod.merge_sarif(reports)
    out.write_text(json.dumps(merged, indent=2))
    findings = scan_mod.findings_from_sarif(merged)
    table = Table(title=f"{len(findings)} findings (fail-on: {fail_on})")
    for col in ("Sev", "Tool", "Rule", "Location", "Message"):
        table.add_column(col)
    for f in sorted(findings, key=lambda f: -scan_mod.SEVERITY_ORDER[f.severity]):
        loc = f"{f.file}:{f.line}" if f.file else "-"
        table.add_row(f.severity, f.tool, f.rule_id, loc, f.message[:80])
    console.print(table)
    console.print(f"SARIF written to {out}")
    if scan_mod.exceeds(findings, fail_on):
        raise typer.Exit(code=1)
```
Add `from platformctl import scan as scan_mod` and `from rich.table import Table` to the imports.

- [ ] **Step 6: Add a CLI test to `test_scan.py`**

```python
from typer.testing import CliRunner

from platformctl.cli import app


def test_scan_cli_gates(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    (tmp_path / "platformctl.toml").write_text('adapter = "fake"\n')
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(scan, "run_scanner", lambda name, root, out: SARIF)
    r = CliRunner().invoke(app, ["scan", "--tool", "checkov", "--fail-on", "high", "--out", str(tmp_path / "r.sarif")])
    assert r.exit_code == 1, r.output
    r = CliRunner().invoke(app, ["scan", "--tool", "checkov", "--fail-on", "critical", "--out", str(tmp_path / "r.sarif")])
    assert r.exit_code == 0, r.output
    assert json.loads((tmp_path / "r.sarif").read_text())["version"] == "2.1.0"
```

- [ ] **Step 7: Run all + lint** — `.venv/bin/pytest -q && make lint` — Expected: pass.

- [ ] **Step 8: Commit**

```bash
git add platformctl
git commit -m "feat(platformctl): scanner runner with SARIF merge and severity gate

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>"
```

### Task 6: Drift detection and the `drift` command

**Files:**
- Create: `platformctl/platformctl/drift.py`
- Modify: `platformctl/platformctl/cli.py`
- Test: `platformctl/tests/test_drift.py`

**Interfaces:**
- Consumes: `terraform.terragrunt_plan`, `terraform.parse_plan`, `terraform.PlanSummary`
- Produces:
  - `drift.DriftReport(cloud: str, env: str, drifted: bool, current: PlanSummary, new_addresses: list[str], resolved_addresses: list[str])`
  - `drift.compare(cloud, env, previous: PlanSummary | None, current: PlanSummary) -> DriftReport`
  - `drift.render_markdown(report: DriftReport) -> str`
  - `drift.last_good_path(settings, cloud, env) -> Path` → `<state_dir>/last-good/<cloud>-<env>.json`
  - CLI: `platformctl drift <cloud> <env> [--accept] [--report drift.md]` — exit 2 when drifted, 0 otherwise; `--accept` saves current plan as last-good.

- [ ] **Step 1: Write failing tests**

`platformctl/tests/test_drift.py`:
```python
import json
from pathlib import Path

from typer.testing import CliRunner

from platformctl import config, drift, terraform
from platformctl.cli import app
from tests.conftest import RunRecorder


def _summary(*addresses: str) -> terraform.PlanSummary:
    return terraform.parse_plan({"resource_changes": [
        {"address": a, "type": "t", "change": {"actions": ["update"]}} for a in addresses]})


def test_compare_no_previous_and_no_changes() -> None:
    r = drift.compare("aws", "dev", None, _summary())
    assert r.drifted is False and r.new_addresses == []


def test_compare_detects_new_and_resolved() -> None:
    r = drift.compare("aws", "dev", _summary("a", "b"), _summary("b", "c"))
    assert r.drifted is True
    assert r.new_addresses == ["c"] and r.resolved_addresses == ["a"]


def test_render_markdown_lists_addresses() -> None:
    md = drift.render_markdown(drift.compare("azure", "prod", None, _summary("x")))
    assert "# Drift report: azure/prod" in md and "- `x`" in md and "DRIFTED" in md


def test_cli_drift_exit_codes(settings: config.Settings, fake_run: RunRecorder, monkeypatch) -> None:  # noqa: ANN001
    monkeypatch.chdir(settings.repo_root)
    fake_run.add(("terragrunt", "plan"), returncode=2)
    fake_run.add(("terragrunt", "show"), stdout=json.dumps({"resource_changes": [
        {"address": "a", "type": "t", "change": {"actions": ["update"]}}]}))
    report = settings.repo_root / "drift.md"
    r = CliRunner().invoke(app, ["drift", "aws", "dev", "--report", str(report)])
    assert r.exit_code == 2, r.output
    assert "DRIFTED" in report.read_text()

    r = CliRunner().invoke(app, ["drift", "aws", "dev", "--accept"])
    assert r.exit_code == 0, r.output
    assert drift.last_good_path(settings, config.CloudName.aws, config.EnvName.dev).exists()

    fake_run.add(("terragrunt", "plan"), returncode=0)
    fake_run.add(("terragrunt", "show"), stdout='{"resource_changes": []}')
    r = CliRunner().invoke(app, ["drift", "aws", "dev"])
    assert r.exit_code == 0
```

- [ ] **Step 2: Run to verify failure** — Expected: ImportError.

- [ ] **Step 3: Implement `drift.py`**

```python
"""Drift detection: compare the current plan with the last accepted plan."""

from datetime import UTC, datetime
from pathlib import Path

from pydantic import BaseModel

from platformctl.config import CloudName, EnvName, Settings
from platformctl.terraform import PlanSummary


class DriftReport(BaseModel):
    cloud: str
    env: str
    drifted: bool
    current: PlanSummary
    new_addresses: list[str] = []
    resolved_addresses: list[str] = []
    generated_at: datetime


def _changed(summary: PlanSummary) -> set[str]:
    return {c.address for c in summary.changes if c.actions and c.actions != ["no-op"]}


def compare(cloud: str, env: str, previous: PlanSummary | None, current: PlanSummary) -> DriftReport:
    before = _changed(previous) if previous else set()
    now = _changed(current)
    return DriftReport(
        cloud=cloud, env=env,
        drifted=current.has_changes(),
        current=current,
        new_addresses=sorted(now - before),
        resolved_addresses=sorted(before - now),
        generated_at=datetime.now(UTC),
    )


def last_good_path(settings: Settings, cloud: CloudName, env: EnvName) -> Path:
    return settings.state_dir / "last-good" / f"{cloud.value}-{env.value}.json"


def render_markdown(report: DriftReport) -> str:
    status = "DRIFTED" if report.drifted else "IN SYNC"
    lines = [
        f"# Drift report: {report.cloud}/{report.env}",
        "",
        f"**Status:** {status}  ",
        f"**Generated:** {report.generated_at.isoformat(timespec='seconds')}  ",
        f"**Changes:** +{report.current.create} ~{report.current.update} -{report.current.delete} ±{report.current.replace}",
        "",
        "## Resources that would change",
    ]
    lines += [f"- `{c.address}` ({', '.join(c.actions)})" for c in report.current.changes if c.actions != ["no-op"]] or ["- none"]
    lines += ["", "## New since last accepted plan"]
    lines += [f"- `{a}`" for a in report.new_addresses] or ["- none"]
    lines += ["", "## Resolved since last accepted plan"]
    lines += [f"- `{a}`" for a in report.resolved_addresses] or ["- none"]
    return "\n".join(lines) + "\n"
```

- [ ] **Step 4: Add `drift` command to `cli.py`**

```python
@app.command()
def drift(
    ctx: typer.Context,
    cloud: CloudName,
    env: EnvName,
    accept: Annotated[bool, typer.Option(help="Record the current plan as the new last-good baseline")] = False,
    report: Annotated[Path | None, typer.Option(help="Write a markdown drift report here")] = None,
) -> None:
    """Detect drift: exit 2 if the plan would change anything, 0 if in sync."""
    settings = get_settings(ctx)
    plan_path, _ = terraform.terragrunt_plan(settings, cloud, env, detailed_exitcode=True)
    current = terraform.parse_plan(json.loads(plan_path.read_text()))
    baseline = drift_mod.last_good_path(settings, cloud, env)
    previous = terraform.PlanSummary.model_validate_json(baseline.read_text()) if baseline.exists() else None
    result = drift_mod.compare(cloud.value, env.value, previous, current)
    md = drift_mod.render_markdown(result)
    if report:
        report.write_text(md)
    console.print(md)
    if accept:
        baseline.parent.mkdir(parents=True, exist_ok=True)
        baseline.write_text(current.model_dump_json(indent=2))
        console.print(f"Baseline saved to {baseline}")
        return
    if result.drifted:
        raise typer.Exit(code=2)
```
Add `from platformctl import drift as drift_mod` to imports.

- [ ] **Step 5: Run all + lint** — Expected: pass.

- [ ] **Step 6: Commit**

```bash
git add platformctl
git commit -m "feat(platformctl): drift detection with markdown report and baseline

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>"
```

### Task 7: Cloud adapters and secret rotation

**Files:**
- Create: `platformctl/platformctl/adapters/__init__.py`, `platformctl/platformctl/adapters/base.py`, `platformctl/platformctl/adapters/fake.py`, `platformctl/platformctl/adapters/azure.py`, `platformctl/platformctl/adapters/aws.py`, `platformctl/platformctl/secrets.py`
- Modify: `platformctl/platformctl/cli.py`
- Test: `platformctl/tests/test_adapters.py`, `platformctl/tests/test_secrets.py`

**Interfaces:**
- Produces:
  - `adapters.base.SecretVersion(name: str, version: str, created: datetime, enabled: bool, tags: dict[str, str])`
  - `adapters.base.Certificate(name: str, subject: str, not_after: datetime, source: str)`
  - `adapters.base.CloudAdapter` (ABC): `get_secret(name) -> str`, `put_secret_version(name, value) -> SecretVersion`, `list_secret_versions(name) -> list[SecretVersion]`, `deprecate_version(name, version) -> None`, `list_certificates() -> list[Certificate]`
  - `adapters.base.SecretNotFound(KeyError)`
  - `adapters.fake.FakeAdapter(CloudAdapter)` — in-memory; constructor accepts `certificates: list[Certificate] | None`
  - `adapters.get_adapter(settings: Settings) -> CloudAdapter` — lazy-imports the azure/aws SDK modules
  - `secrets.generate_secret(policy: SecretPolicy, rng: random.Random | None = None) -> str` (defaults to `random.SystemRandom()`)
  - `secrets.RotationResult(name: str, executed: bool, new_version: str | None, deprecated: list[str])`
  - `secrets.rotate(adapter, name, policy, *, execute: bool) -> RotationResult`
  - CLI: `platformctl secrets rotate <name> [--execute]`, `platformctl secrets list <name>`

- [ ] **Step 1: Write failing adapter tests**

`platformctl/tests/test_adapters.py`:
```python
from datetime import UTC, datetime

import pytest

from platformctl import adapters, config
from platformctl.adapters.base import Certificate, SecretNotFound
from platformctl.adapters.fake import FakeAdapter


def test_fake_adapter_versions_and_deprecation() -> None:
    a = FakeAdapter()
    v1 = a.put_secret_version("db-password", "one")
    v2 = a.put_secret_version("db-password", "two")
    assert a.get_secret("db-password") == "two"
    assert [v.version for v in a.list_secret_versions("db-password")] == [v1.version, v2.version]
    a.deprecate_version("db-password", v1.version)
    versions = a.list_secret_versions("db-password")
    assert versions[0].enabled is False and versions[0].tags == {"status": "deprecated"}
    assert versions[1].enabled is True


def test_fake_adapter_missing_secret() -> None:
    with pytest.raises(SecretNotFound):
        FakeAdapter().get_secret("nope")
    assert FakeAdapter().list_secret_versions("nope") == []


def test_fake_adapter_certificates() -> None:
    cert = Certificate(name="api", subject="CN=api.example.com", not_after=datetime(2030, 1, 1, tzinfo=UTC), source="fake")
    assert FakeAdapter(certificates=[cert]).list_certificates() == [cert]


def test_get_adapter_fake(settings: config.Settings) -> None:
    assert isinstance(adapters.get_adapter(settings), FakeAdapter)


def test_get_adapter_azure_requires_sdk(settings: config.Settings, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(settings, "adapter", "azure")
    monkeypatch.delenv("AZURE_KEY_VAULT_URL", raising=False)
    with pytest.raises((ImportError, adapters.AdapterConfigError)):
        adapters.get_adapter(settings)


def test_get_adapter_aws_requires_sdk(settings: config.Settings, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(settings, "adapter", "aws")
    with pytest.raises((ImportError, adapters.AdapterConfigError)):
        adapters.get_adapter(settings)
```

- [ ] **Step 2: Run to verify failure** — Expected: ImportError.

- [ ] **Step 3: Implement adapters**

`platformctl/platformctl/adapters/base.py`:
```python
"""Abstract cloud adapter. Everything that touches a cloud API goes through this interface
so the CLI is testable with FakeAdapter and never needs credentials in CI."""

from abc import ABC, abstractmethod
from datetime import datetime

from pydantic import BaseModel


class SecretNotFound(KeyError):
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
```

`platformctl/platformctl/adapters/fake.py`:
```python
"""In-memory adapter for tests and demos."""

import uuid
from datetime import UTC, datetime

from platformctl.adapters.base import Certificate, CloudAdapter, SecretNotFound, SecretVersion


class FakeAdapter(CloudAdapter):
    def __init__(self, certificates: list[Certificate] | None = None) -> None:
        self._secrets: dict[str, list[tuple[SecretVersion, str]]] = {}
        self._certs = list(certificates or [])

    def get_secret(self, name: str) -> str:
        versions = self._secrets.get(name)
        if not versions:
            raise SecretNotFound(name)
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
                self._secrets[name][i] = (v.model_copy(update={"enabled": False, "tags": {"status": "deprecated"}}), value)
                return
        raise SecretNotFound(f"{name}@{version}")

    def list_certificates(self) -> list[Certificate]:
        return list(self._certs)
```

`platformctl/platformctl/adapters/azure.py`:
```python
"""Azure Key Vault adapter. SDK imports are inside __init__ so the module imports without azure-* installed."""

import os
from datetime import UTC, datetime
from typing import Any

from platformctl.adapters.base import Certificate, CloudAdapter, SecretNotFound, SecretVersion


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
            raise SecretNotFound(name) from exc

    def put_secret_version(self, name: str, value: str) -> SecretVersion:
        s = self._secrets.set_secret(name, value)
        return SecretVersion(name=name, version=s.properties.version, created=s.properties.created_on or datetime.now(UTC))

    def list_secret_versions(self, name: str) -> list[SecretVersion]:
        return [
            SecretVersion(name=name, version=p.version, created=p.created_on or datetime.now(UTC),
                          enabled=bool(p.enabled), tags=dict(p.tags or {}))
            for p in self._secrets.list_properties_of_secret_versions(name)
        ]

    def deprecate_version(self, name: str, version: str) -> None:
        self._secrets.update_secret_properties(name, version=version, enabled=False, tags={"status": "deprecated"})

    def list_certificates(self) -> list[Certificate]:
        out: list[Certificate] = []
        for p in self._certs.list_properties_of_certificates():
            cert = self._certs.get_certificate(p.name)
            out.append(Certificate(name=p.name, subject=str(cert.policy.subject or ""), not_after=p.expires_on, source="azure-keyvault"))
        return out
```

`platformctl/platformctl/adapters/aws.py`:
```python
"""AWS Secrets Manager + ACM adapter. boto3 is imported lazily."""

from datetime import UTC, datetime
from typing import Any

from platformctl.adapters.base import Certificate, CloudAdapter, SecretNotFound, SecretVersion


class AwsAdapter(CloudAdapter):
    def __init__(self, region: str | None = None) -> None:
        import boto3

        self._sm: Any = boto3.client("secretsmanager", region_name=region)
        self._acm: Any = boto3.client("acm", region_name=region)

    def get_secret(self, name: str) -> str:
        try:
            return str(self._sm.get_secret_value(SecretId=name)["SecretString"])
        except self._sm.exceptions.ResourceNotFoundException as exc:
            raise SecretNotFound(name) from exc

    def put_secret_version(self, name: str, value: str) -> SecretVersion:
        r = self._sm.put_secret_value(SecretId=name, SecretString=value, VersionStages=["AWSCURRENT"])
        return SecretVersion(name=name, version=r["VersionId"], created=datetime.now(UTC))

    def list_secret_versions(self, name: str) -> list[SecretVersion]:
        r = self._sm.list_secret_version_ids(SecretId=name, IncludeDeprecated=True)
        return [
            SecretVersion(name=name, version=v["VersionId"], created=v.get("CreatedDate", datetime.now(UTC)),
                          enabled="AWSCURRENT" in v.get("VersionStages", []),
                          tags={"stages": ",".join(v.get("VersionStages", []))})
            for v in sorted(r.get("Versions", []), key=lambda v: v.get("CreatedDate", datetime.now(UTC)))
        ]

    def deprecate_version(self, name: str, version: str) -> None:
        # Secrets Manager deprecates by removing all staging labels; it is then purged after 24h.
        self._sm.update_secret_version_stage(SecretId=name, VersionStage="AWSPREVIOUS", RemoveFromVersionId=version)

    def list_certificates(self) -> list[Certificate]:
        out: list[Certificate] = []
        for c in self._acm.list_certificates().get("CertificateSummaryList", []):
            detail = self._acm.describe_certificate(CertificateArn=c["CertificateArn"])["Certificate"]
            out.append(Certificate(name=c["CertificateArn"].rsplit("/", 1)[-1], subject=detail.get("Subject", ""),
                                   not_after=detail.get("NotAfter", datetime.now(UTC)), source="aws-acm"))
        return out
```

`platformctl/platformctl/adapters/__init__.py`:
```python
"""Adapter factory."""

from platformctl.adapters.base import Certificate, CloudAdapter, SecretNotFound, SecretVersion
from platformctl.adapters.fake import FakeAdapter
from platformctl.config import Settings


class AdapterConfigError(RuntimeError):
    pass


def get_adapter(settings: Settings) -> CloudAdapter:
    if settings.adapter == "fake":
        return FakeAdapter()
    if settings.adapter == "azure":
        from platformctl.adapters.azure import AzureKeyVaultAdapter

        try:
            return AzureKeyVaultAdapter.from_env()
        except ValueError as exc:
            raise AdapterConfigError(str(exc)) from exc
    if settings.adapter == "aws":
        from platformctl.adapters.aws import AwsAdapter

        return AwsAdapter()
    raise AdapterConfigError(f"unknown adapter {settings.adapter}")


__all__ = ["AdapterConfigError", "Certificate", "CloudAdapter", "FakeAdapter", "SecretNotFound", "SecretVersion", "get_adapter"]
```

- [ ] **Step 4: Run adapter tests** — `.venv/bin/pytest platformctl/tests/test_adapters.py -q` — Expected: 6 passed. (If `azure`/`aws` tests fail because the SDKs happen to be installed, they will raise `AdapterConfigError`/botocore `NoRegionError` — the test tuple already accepts `AdapterConfigError`; for boto3, add `botocore.exceptions.NoRegionError` to the accepted tuple only if boto3 is installed in `.venv`. It is not part of `[dev]`, so this should not occur.)

- [ ] **Step 5: Write failing secrets tests**

`platformctl/tests/test_secrets.py`:
```python
import random

import pytest
from hypothesis import given
from hypothesis import strategies as st
from typer.testing import CliRunner

from platformctl import config, secrets
from platformctl.adapters.fake import FakeAdapter
from platformctl.cli import app


@given(st.integers(min_value=16, max_value=128), st.text(alphabet="abcXYZ019-_", min_size=10, max_size=30))
def test_generate_secret_respects_policy(length: int, alphabet: str) -> None:
    value = secrets.generate_secret(config.SecretPolicy(length=length, alphabet=alphabet))
    assert len(value) == length and set(value) <= set(alphabet)


def test_generate_secret_uses_system_random_by_default() -> None:
    a = secrets.generate_secret(config.SecretPolicy())
    b = secrets.generate_secret(config.SecretPolicy())
    assert a != b


def test_generate_secret_deterministic_with_seeded_rng() -> None:
    rng = random.Random(1)  # noqa: S311 — test determinism only
    assert secrets.generate_secret(config.SecretPolicy(length=20), rng=rng) == secrets.generate_secret(
        config.SecretPolicy(length=20), rng=random.Random(1))  # noqa: S311


def test_rotate_dry_run_changes_nothing() -> None:
    adapter = FakeAdapter()
    adapter.put_secret_version("api-key", "old")
    result = secrets.rotate(adapter, "api-key", config.SecretPolicy(), execute=False)
    assert result.executed is False and result.new_version is None
    assert adapter.get_secret("api-key") == "old"


def test_rotate_execute_adds_version_and_deprecates_previous() -> None:
    adapter = FakeAdapter()
    v0 = adapter.put_secret_version("api-key", "old")
    result = secrets.rotate(adapter, "api-key", config.SecretPolicy(length=24), execute=True)
    assert result.executed and result.new_version and result.deprecated == [v0.version]
    assert adapter.get_secret("api-key") != "old" and len(adapter.get_secret("api-key")) == 24
    assert adapter.list_secret_versions("api-key")[0].enabled is False


def test_rotate_new_secret_has_nothing_to_deprecate() -> None:
    result = secrets.rotate(FakeAdapter(), "fresh", config.SecretPolicy(), execute=True)
    assert result.deprecated == [] and result.new_version


def test_cli_secrets_rotate(settings: config.Settings, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.chdir(settings.repo_root)
    r = CliRunner().invoke(app, ["secrets", "rotate", "db-password"])
    assert r.exit_code == 0, r.output
    assert "DRY RUN" in r.output
    r = CliRunner().invoke(app, ["secrets", "rotate", "db-password", "--execute"])
    assert r.exit_code == 0 and "rotated" in r.output
```

- [ ] **Step 6: Implement `secrets.py`**

```python
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


def rotate(adapter: CloudAdapter, name: str, policy: SecretPolicy, *, execute: bool) -> RotationResult:
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
```

- [ ] **Step 7: Add `secrets` sub-app to `cli.py`**

```python
secrets_app = typer.Typer(help="Secret lifecycle (rotate, list)")
app.add_typer(secrets_app, name="secrets")


@secrets_app.command("rotate")
def secrets_rotate(
    ctx: typer.Context,
    name: str,
    execute: Annotated[bool, typer.Option("--execute", help="Actually write the new version (default: dry run)")] = False,
) -> None:
    """Generate a new secret version and deprecate previous ones."""
    settings = get_settings(ctx)
    adapter = adapters.get_adapter(settings)
    result = secrets_mod.rotate(adapter, name, settings.secret_policy, execute=execute)
    if not result.executed:
        console.print(f"[yellow]DRY RUN[/] would rotate '{name}' (pass --execute to apply)")
        return
    console.print(f"[green]rotated[/] '{name}' -> version {result.new_version}; deprecated {len(result.deprecated)} version(s)")


@secrets_app.command("list")
def secrets_list(ctx: typer.Context, name: str) -> None:
    """List versions of a secret (values are never shown)."""
    adapter = adapters.get_adapter(get_settings(ctx))
    table = Table(title=name)
    for col in ("Version", "Created", "Enabled", "Tags"):
        table.add_column(col)
    for v in adapter.list_secret_versions(name):
        table.add_row(v.version, v.created.isoformat(timespec="seconds"), str(v.enabled), ", ".join(f"{k}={val}" for k, val in v.tags.items()))
    console.print(table)
```
Add `from platformctl import adapters, secrets as secrets_mod` to imports.

- [ ] **Step 8: Run all + lint** — Expected: pass.

- [ ] **Step 9: Commit**

```bash
git add platformctl
git commit -m "feat(platformctl): cloud adapters (fake/azure/aws) and secret rotation

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>"
```

### Task 8: Certificate expiry checks

**Files:**
- Create: `platformctl/platformctl/certs.py`
- Modify: `platformctl/platformctl/cli.py`
- Test: `platformctl/tests/test_certs.py`

**Interfaces:**
- Consumes: `adapters.base.Certificate`, `config.CertTarget`
- Produces:
  - `certs.CertStatus(name: str, source: str, not_after: datetime, days_remaining: int, status: Literal["ok","warning","expired"])`
  - `certs.evaluate(certificates: list[Certificate], warn_days: int, now: datetime | None = None) -> list[CertStatus]`
  - `certs.probe_tls(host: str, port: int = 443, timeout: float = 5.0) -> Certificate` — uses `ssl` stdlib; raises `certs.ProbeError`
  - CLI: `platformctl certs check [--warn-days N] [--no-probe]` — exit 1 if any warning/expired.

- [ ] **Step 1: Write failing tests**

`platformctl/tests/test_certs.py`:
```python
from datetime import UTC, datetime, timedelta

import pytest
from typer.testing import CliRunner

from platformctl import certs, config
from platformctl.adapters.base import Certificate
from platformctl.cli import app

NOW = datetime(2026, 9, 21, tzinfo=UTC)


def _cert(name: str, days: int) -> Certificate:
    return Certificate(name=name, subject=f"CN={name}", not_after=NOW + timedelta(days=days), source="test")


def test_evaluate_statuses() -> None:
    out = certs.evaluate([_cert("ok", 90), _cert("soon", 10), _cert("dead", -1)], warn_days=30, now=NOW)
    assert [(c.name, c.status, c.days_remaining) for c in out] == [("dead", "expired", -1), ("soon", "warning", 10), ("ok", "ok", 90)]


def test_evaluate_boundary_is_warning() -> None:
    assert certs.evaluate([_cert("edge", 30)], warn_days=30, now=NOW)[0].status == "warning"


def test_parse_openssl_time() -> None:
    assert certs.parse_not_after("Sep 21 12:00:00 2030 GMT") == datetime(2030, 9, 21, 12, 0, tzinfo=UTC)


def test_probe_tls_failure_is_probe_error(monkeypatch: pytest.MonkeyPatch) -> None:
    import socket

    def boom(*a: object, **k: object) -> None:
        raise OSError("refused")

    monkeypatch.setattr(socket, "create_connection", boom)
    with pytest.raises(certs.ProbeError):
        certs.probe_tls("localhost", 1)


def test_cli_certs_check_uses_adapter_and_skips_probe(settings: config.Settings, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.chdir(settings.repo_root)
    from platformctl import adapters
    from platformctl.adapters.fake import FakeAdapter

    monkeypatch.setattr(adapters, "get_adapter", lambda s: FakeAdapter(certificates=[_cert("ok", 400)]))
    r = CliRunner().invoke(app, ["certs", "check", "--no-probe"])
    assert r.exit_code == 0, r.output
    monkeypatch.setattr(adapters, "get_adapter", lambda s: FakeAdapter(certificates=[_cert("soon", 3)]))
    r = CliRunner().invoke(app, ["certs", "check", "--no-probe"])
    assert r.exit_code == 1 and "warning" in r.output
```

- [ ] **Step 2: Run to verify failure** — Expected: ImportError.

- [ ] **Step 3: Implement `certs.py`**

```python
"""Certificate expiry evaluation from cloud stores and live TLS endpoints."""

import socket
import ssl
from datetime import UTC, datetime
from typing import Literal

from pydantic import BaseModel

from platformctl.adapters.base import Certificate

Status = Literal["ok", "warning", "expired"]


class ProbeError(RuntimeError):
    pass


class CertStatus(BaseModel):
    name: str
    source: str
    not_after: datetime
    days_remaining: int
    status: Status


def parse_not_after(value: str) -> datetime:
    """Parse the OpenSSL-style timestamp returned by ssl.getpeercert()."""
    return datetime.fromtimestamp(ssl.cert_time_to_seconds(value), tz=UTC)


def probe_tls(host: str, port: int = 443, timeout: float = 5.0) -> Certificate:
    context = ssl.create_default_context()
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock, context.wrap_socket(sock, server_hostname=host) as tls:
            peer = tls.getpeercert()
    except (OSError, ssl.SSLError) as exc:
        raise ProbeError(f"{host}:{port}: {exc}") from exc
    if not peer:
        raise ProbeError(f"{host}:{port}: no certificate returned")
    subject = ",".join("=".join(rdn[0]) for rdn in peer.get("subject", ()))
    return Certificate(name=f"{host}:{port}", subject=subject, not_after=parse_not_after(str(peer["notAfter"])), source="tls-probe")


def evaluate(certificates: list[Certificate], warn_days: int, now: datetime | None = None) -> list[CertStatus]:
    current = now or datetime.now(UTC)
    out: list[CertStatus] = []
    for cert in certificates:
        days = (cert.not_after - current).days
        status: Status = "expired" if days < 0 else "warning" if days <= warn_days else "ok"
        out.append(CertStatus(name=cert.name, source=cert.source, not_after=cert.not_after, days_remaining=days, status=status))
    return sorted(out, key=lambda c: c.days_remaining)
```

- [ ] **Step 4: Add `certs` sub-app to `cli.py`**

```python
certs_app = typer.Typer(help="Certificate lifecycle")
app.add_typer(certs_app, name="certs")


@certs_app.command("check")
def certs_check(
    ctx: typer.Context,
    warn_days: Annotated[int | None, typer.Option(help="Override warn threshold from config")] = None,
    probe: Annotated[bool, typer.Option(help="Also TLS-probe cert_targets from config")] = True,
) -> None:
    """Report certificates expiring within the warning window. Exit 1 if any."""
    settings = get_settings(ctx)
    found: list[adapters.Certificate] = adapters.get_adapter(settings).list_certificates()
    if probe:
        for target in settings.cert_targets:
            try:
                found.append(certs_mod.probe_tls(target.host, target.port))
            except certs_mod.ProbeError as exc:
                console.print(f"[yellow]probe failed[/] {exc}")
    statuses = certs_mod.evaluate(found, warn_days or settings.warn_days)
    table = Table(title="Certificates")
    for col in ("Status", "Name", "Source", "Expires", "Days"):
        table.add_column(col)
    style = {"ok": "green", "warning": "yellow", "expired": "red"}
    for s in statuses:
        table.add_row(f"[{style[s.status]}]{s.status}[/]", s.name, s.source, s.not_after.date().isoformat(), str(s.days_remaining))
    console.print(table)
    if any(s.status != "ok" for s in statuses):
        raise typer.Exit(code=1)
```
Add `from platformctl import certs as certs_mod` to imports.

- [ ] **Step 5: Run all + lint** — Expected: pass.

- [ ] **Step 6: Commit**

```bash
git add platformctl
git commit -m "feat(platformctl): certificate expiry checks via adapters and TLS probe

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>"
```

### Task 9: Ansible inventory from Terraform outputs

**Files:**
- Create: `platformctl/platformctl/ansible.py`, `ansible/inventory/.gitkeep`
- Modify: `platformctl/platformctl/cli.py`
- Test: `platformctl/tests/test_ansible.py`

**Interfaces:**
- Consumes: `terraform.terragrunt_outputs`
- Produces:
  - `ansible.build_inventory(outputs: dict[str, Any], cloud: CloudName, env: EnvName) -> dict[str, Any]` — requires `vm_public_ip`, `vm_private_ip`, `secret_store_id`, `identity_id`; raises `ansible.MissingOutput(KeyError)`
  - `ansible.write_inventory(settings, cloud, env, inventory) -> Path` → `<repo_root>/ansible/inventory/<cloud>-<env>.yml`
  - CLI: `platformctl ansible inventory <cloud> <env>`

- [ ] **Step 1: Write failing tests**

`platformctl/tests/test_ansible.py`:
```python
import json

import pytest
import yaml
from typer.testing import CliRunner

from platformctl import ansible, config
from platformctl.cli import app
from tests.conftest import RunRecorder

OUTPUTS = {"vm_public_ip": "203.0.113.10", "vm_private_ip": "10.0.1.4", "secret_store_id": "kv-123", "identity_id": "id-456"}


def test_build_inventory_shape() -> None:
    inv = ansible.build_inventory(OUTPUTS, config.CloudName.azure, config.EnvName.dev)
    host = inv["all"]["hosts"]["api-azure-dev"]
    assert host["ansible_host"] == "203.0.113.10" and host["private_ip"] == "10.0.1.4"
    assert inv["all"]["vars"] == {"cloud": "azure", "environment": "dev", "secret_store_id": "kv-123", "identity_id": "id-456",
                                  "ansible_user": "platform", "ansible_python_interpreter": "/usr/bin/python3"}
    assert inv["all"]["children"] == {"api": {"hosts": {"api-azure-dev": None}}}


def test_build_inventory_missing_output() -> None:
    with pytest.raises(ansible.MissingOutput):
        ansible.build_inventory({"vm_public_ip": "x"}, config.CloudName.aws, config.EnvName.prod)


def test_cli_inventory_writes_yaml(settings: config.Settings, fake_run: RunRecorder, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.chdir(settings.repo_root)
    fake_run.add(("terragrunt", "output"), stdout=json.dumps({k: {"value": v} for k, v in OUTPUTS.items()}))
    r = CliRunner().invoke(app, ["ansible", "inventory", "aws", "dev"])
    assert r.exit_code == 0, r.output
    path = settings.repo_root / "ansible/inventory/aws-dev.yml"
    assert yaml.safe_load(path.read_text())["all"]["hosts"]["api-aws-dev"]["ansible_host"] == "203.0.113.10"
```

- [ ] **Step 2: Run to verify failure** — Expected: ImportError.

- [ ] **Step 3: Implement `ansible.py`**

```python
"""Generate an Ansible YAML inventory from Terraform stack outputs."""

from pathlib import Path
from typing import Any

import yaml

from platformctl.config import CloudName, EnvName, Settings

REQUIRED_OUTPUTS = ("vm_public_ip", "vm_private_ip", "secret_store_id", "identity_id")


class MissingOutput(KeyError):
    pass


def build_inventory(outputs: dict[str, Any], cloud: CloudName, env: EnvName) -> dict[str, Any]:
    missing = [k for k in REQUIRED_OUTPUTS if k not in outputs]
    if missing:
        raise MissingOutput(f"terraform outputs missing: {', '.join(missing)}")
    host = f"api-{cloud.value}-{env.value}"
    return {
        "all": {
            "hosts": {host: {"ansible_host": outputs["vm_public_ip"], "private_ip": outputs["vm_private_ip"]}},
            "vars": {
                "cloud": cloud.value,
                "environment": env.value,
                "secret_store_id": outputs["secret_store_id"],
                "identity_id": outputs["identity_id"],
                "ansible_user": "platform",
                "ansible_python_interpreter": "/usr/bin/python3",
            },
            "children": {"api": {"hosts": {host: None}}},
        }
    }


def write_inventory(settings: Settings, cloud: CloudName, env: EnvName, inventory: dict[str, Any]) -> Path:
    path = settings.repo_root / "ansible" / "inventory" / f"{cloud.value}-{env.value}.yml"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(yaml.safe_dump(inventory, sort_keys=False))
    return path
```

- [ ] **Step 4: Add `ansible` sub-app to `cli.py`**

```python
ansible_app = typer.Typer(help="Ansible helpers")
app.add_typer(ansible_app, name="ansible")


@ansible_app.command("inventory")
def ansible_inventory(ctx: typer.Context, cloud: CloudName, env: EnvName) -> None:
    """Write ansible/inventory/<cloud>-<env>.yml from terragrunt outputs."""
    settings = get_settings(ctx)
    outputs = terraform.terragrunt_outputs(settings, cloud, env)
    path = ansible_mod.write_inventory(settings, cloud, env, ansible_mod.build_inventory(outputs, cloud, env))
    console.print(f"inventory written to {path}")
```
Add `from platformctl import ansible as ansible_mod` to imports. Create empty `ansible/inventory/.gitkeep`.

- [ ] **Step 5: Run all + lint** — Expected: pass.

- [ ] **Step 6: Commit**

```bash
git add platformctl ansible/inventory/.gitkeep
git commit -m "feat(platformctl): generate ansible inventory from terraform outputs

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>"
```

### Task 10: Supply-chain commands (sbom / sign / verify)

**Files:**
- Create: `platformctl/platformctl/supplychain.py`
- Modify: `platformctl/platformctl/cli.py`
- Test: `platformctl/tests/test_supplychain.py`

**Interfaces:**
- Consumes: `proc.run`
- Produces:
  - `supplychain.sbom(image: str, out: Path) -> Path` — `syft <image> -o spdx-json=<out>`
  - `supplychain.sign(image: str) -> None` — `cosign sign --yes <image>` (keyless; relies on OIDC in CI)
  - `supplychain.attest_sbom(image: str, sbom_path: Path) -> None` — `cosign attest --yes --predicate <sbom> --type spdxjson <image>`
  - `supplychain.verify(image: str, identity_regexp: str, issuer: str = "https://token.actions.githubusercontent.com") -> bool`
  - CLI: `platformctl sbom <image> [--out sbom.spdx.json]`, `platformctl sign <image>`, `platformctl verify <image> --identity-regexp '^https://github.com/OWNER/REPO/'`

- [ ] **Step 1: Write failing tests**

`platformctl/tests/test_supplychain.py`:
```python
from pathlib import Path

import pytest
from typer.testing import CliRunner

from platformctl import config, supplychain
from platformctl.cli import app
from tests.conftest import RunRecorder


def test_sbom_invokes_syft(tmp_path: Path, fake_run: RunRecorder) -> None:
    out = supplychain.sbom("ghcr.io/x/app:1", tmp_path / "sbom.json")
    assert fake_run.calls[0] == ("syft", "ghcr.io/x/app:1", "-o", f"spdx-json={out}")


def test_sign_and_attest(tmp_path: Path, fake_run: RunRecorder) -> None:
    supplychain.sign("img:1")
    supplychain.attest_sbom("img:1", tmp_path / "sbom.json")
    assert fake_run.calls[0] == ("cosign", "sign", "--yes", "img:1")
    assert fake_run.calls[1][:4] == ("cosign", "attest", "--yes", "--type")


def test_verify_true_false(fake_run: RunRecorder) -> None:
    assert supplychain.verify("img:1", "^https://github.com/o/r/") is True
    fake_run.add(("cosign", "verify"), returncode=1, stderr="no matching signatures")
    assert supplychain.verify("img:1", "^https://github.com/o/r/") is False
    assert "--certificate-oidc-issuer" in fake_run.calls[0]


def test_cli_verify_exit_code(settings: config.Settings, fake_run: RunRecorder, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.chdir(settings.repo_root)
    fake_run.add(("cosign", "verify"), returncode=1)
    r = CliRunner().invoke(app, ["verify", "img:1", "--identity-regexp", "^https://github.com/o/r/"])
    assert r.exit_code == 1 and "NOT verified" in r.output
```

- [ ] **Step 2: Run to verify failure** — Expected: ImportError.

- [ ] **Step 3: Implement `supplychain.py`**

```python
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
    proc.run(["cosign", "attest", "--yes", "--type", "spdxjson", "--predicate", str(sbom_path), image])


def verify(image: str, identity_regexp: str, issuer: str = GITHUB_ISSUER) -> bool:
    result = proc.run(
        ["cosign", "verify", "--certificate-identity-regexp", identity_regexp, "--certificate-oidc-issuer", issuer, image],
        ok_codes=frozenset({0, 1}),
    )
    return result.returncode == 0
```

- [ ] **Step 4: Add commands to `cli.py`**

```python
@app.command()
def sbom(ctx: typer.Context, image: str, out: Annotated[Path, typer.Option()] = Path("sbom.spdx.json")) -> None:
    """Generate an SPDX SBOM for IMAGE with syft."""
    console.print(f"SBOM written to {supplychain.sbom(image, out)}")


@app.command()
def sign(ctx: typer.Context, image: str, sbom_path: Annotated[Path | None, typer.Option("--sbom")] = None) -> None:
    """Keyless-sign IMAGE with cosign and optionally attach an SBOM attestation."""
    supplychain.sign(image)
    if sbom_path:
        supplychain.attest_sbom(image, sbom_path)
    console.print(f"[green]signed[/] {image}")


@app.command()
def verify(
    ctx: typer.Context,
    image: str,
    identity_regexp: Annotated[str, typer.Option(help="Regexp for the signing certificate identity")],
    issuer: Annotated[str, typer.Option()] = supplychain.GITHUB_ISSUER,
) -> None:
    """Verify IMAGE signature against an OIDC identity. Exit 1 if not verified."""
    if supplychain.verify(image, identity_regexp, issuer):
        console.print(f"[green]verified[/] {image}")
    else:
        console.print(f"[red]NOT verified[/] {image}")
        raise typer.Exit(code=1)
```
Add `from platformctl import supplychain` to imports.

- [ ] **Step 5: Run all + lint + coverage** — `make test && make lint` — Expected: pass, coverage ≥ 85% (adapters/azure.py and adapters/aws.py are excluded from the threshold by adding to root `pyproject.toml`: `[tool.coverage.run] omit = ["platformctl/platformctl/adapters/azure.py", "platformctl/platformctl/adapters/aws.py"]` — they require live SDKs).

- [ ] **Step 6: Commit**

```bash
git add platformctl pyproject.toml
git commit -m "feat(platformctl): sbom, sign and verify commands wrapping syft and cosign

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>"
```

---

## Phase 2 — Infrastructure as Code

### Task 11: Terraform `network` modules (Azure + AWS) with `terraform test`

**Files:**
- Create: `infra/terraform/modules/network/azure/{versions,variables,main,outputs}.tf`, `infra/terraform/modules/network/azure/tests/plan.tftest.hcl`
- Create: `infra/terraform/modules/network/aws/{versions,variables,main,outputs}.tf`, `infra/terraform/modules/network/aws/tests/plan.tftest.hcl`

**Interfaces:**
- Produces (Azure): inputs `project, environment, region, cidr, allowed_ssh_cidrs, tags, resource_group_name`; outputs `subnet_id, nsg_id, vnet_id`
- Produces (AWS): inputs `project, environment, region, cidr, allowed_ssh_cidrs, tags`; outputs `subnet_id, security_group_id, vpc_id`
- Both: variable validation rejects `0.0.0.0/0` and `::/0` in `allowed_ssh_cidrs`.

- [ ] **Step 1: Azure network module**

`infra/terraform/modules/network/azure/versions.tf`:
```hcl
terraform {
  required_version = ">= 1.7"
  required_providers {
    azurerm = {
      source  = "hashicorp/azurerm"
      version = "~> 4.0"
    }
  }
}
```

`infra/terraform/modules/network/azure/variables.tf`:
```hcl
variable "project" {
  description = "Short project slug used in resource names."
  type        = string
}

variable "environment" {
  description = "Deployment environment (dev|prod)."
  type        = string
  validation {
    condition     = contains(["dev", "prod"], var.environment)
    error_message = "environment must be dev or prod."
  }
}

variable "region" {
  description = "Azure location."
  type        = string
}

variable "resource_group_name" {
  description = "Existing resource group to deploy into."
  type        = string
}

variable "cidr" {
  description = "VNet address space."
  type        = string
  validation {
    condition     = can(cidrhost(var.cidr, 0))
    error_message = "cidr must be a valid IPv4 CIDR."
  }
}

variable "allowed_ssh_cidrs" {
  description = "CIDRs allowed to reach SSH. Never the whole internet."
  type        = list(string)
  validation {
    condition     = !contains(var.allowed_ssh_cidrs, "0.0.0.0/0") && !contains(var.allowed_ssh_cidrs, "::/0")
    error_message = "allowed_ssh_cidrs must not contain 0.0.0.0/0 or ::/0."
  }
}

variable "tags" {
  description = "Tags applied to every resource. project/environment/owner/cost-center are required by policy."
  type        = map(string)
}
```

`infra/terraform/modules/network/azure/main.tf`:
```hcl
locals {
  name = "${var.project}-${var.environment}"
}

resource "azurerm_virtual_network" "this" {
  name                = "vnet-${local.name}"
  location            = var.region
  resource_group_name = var.resource_group_name
  address_space       = [var.cidr]
  tags                = var.tags
}

resource "azurerm_subnet" "this" {
  name                 = "snet-${local.name}-app"
  resource_group_name  = var.resource_group_name
  virtual_network_name = azurerm_virtual_network.this.name
  address_prefixes     = [cidrsubnet(var.cidr, 8, 1)]
}

resource "azurerm_network_security_group" "this" {
  name                = "nsg-${local.name}-app"
  location            = var.region
  resource_group_name = var.resource_group_name
  tags                = var.tags
}

resource "azurerm_network_security_rule" "https_in" {
  name                        = "allow-https-in"
  priority                    = 100
  direction                   = "Inbound"
  access                      = "Allow"
  protocol                    = "Tcp"
  source_port_range           = "*"
  destination_port_range      = "443"
  source_address_prefix       = "Internet"
  destination_address_prefix  = "*"
  resource_group_name         = var.resource_group_name
  network_security_group_name = azurerm_network_security_group.this.name
}

resource "azurerm_network_security_rule" "ssh_in" {
  name                        = "allow-ssh-from-admin"
  priority                    = 110
  direction                   = "Inbound"
  access                      = "Allow"
  protocol                    = "Tcp"
  source_port_range           = "*"
  destination_port_range      = "22"
  source_address_prefixes     = var.allowed_ssh_cidrs
  destination_address_prefix  = "*"
  resource_group_name         = var.resource_group_name
  network_security_group_name = azurerm_network_security_group.this.name
}

resource "azurerm_network_security_rule" "deny_all_in" {
  name                        = "deny-all-in"
  priority                    = 4000
  direction                   = "Inbound"
  access                      = "Deny"
  protocol                    = "*"
  source_port_range           = "*"
  destination_port_range      = "*"
  source_address_prefix       = "*"
  destination_address_prefix  = "*"
  resource_group_name         = var.resource_group_name
  network_security_group_name = azurerm_network_security_group.this.name
}

resource "azurerm_subnet_network_security_group_association" "this" {
  subnet_id                 = azurerm_subnet.this.id
  network_security_group_id = azurerm_network_security_group.this.id
}
```

`infra/terraform/modules/network/azure/outputs.tf`:
```hcl
output "vnet_id" {
  value = azurerm_virtual_network.this.id
}

output "subnet_id" {
  value = azurerm_subnet.this.id
}

output "nsg_id" {
  value = azurerm_network_security_group.this.id
}
```

`infra/terraform/modules/network/azure/tests/plan.tftest.hcl`:
```hcl
mock_provider "azurerm" {}

variables {
  project             = "sap"
  environment         = "dev"
  region              = "eastus"
  resource_group_name = "rg-sap-dev"
  cidr                = "10.10.0.0/16"
  allowed_ssh_cidrs   = ["203.0.113.0/24"]
  tags                = { project = "sap", environment = "dev", owner = "platform", cost-center = "eng" }
}

run "https_is_the_only_internet_ingress" {
  command = plan

  assert {
    condition     = azurerm_network_security_rule.https_in.destination_port_range == "443" && azurerm_network_security_rule.https_in.source_address_prefix == "Internet"
    error_message = "HTTPS rule must allow 443 from Internet only."
  }
  assert {
    condition     = azurerm_network_security_rule.ssh_in.source_address_prefixes == toset(["203.0.113.0/24"])
    error_message = "SSH must be restricted to allowed_ssh_cidrs."
  }
  assert {
    condition     = azurerm_network_security_rule.deny_all_in.access == "Deny" && azurerm_network_security_rule.deny_all_in.priority == 4000
    error_message = "A catch-all deny rule must exist."
  }
  assert {
    condition     = azurerm_subnet.this.address_prefixes[0] == "10.10.1.0/24"
    error_message = "App subnet must be the second /24 of the VNet."
  }
}

run "rejects_world_open_ssh" {
  command = plan
  variables {
    allowed_ssh_cidrs = ["0.0.0.0/0"]
  }
  expect_failures = [var.allowed_ssh_cidrs]
}

run "rejects_unknown_environment" {
  command = plan
  variables {
    environment = "staging"
  }
  expect_failures = [var.environment]
}
```

- [ ] **Step 2: Run Azure network tests**

Run: `cd infra/terraform/modules/network/azure && terraform init -backend=false && terraform test && cd -`
Expected: `Success! 3 passed, 0 failed.`

- [ ] **Step 3: AWS network module**

`infra/terraform/modules/network/aws/versions.tf`:
```hcl
terraform {
  required_version = ">= 1.7"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}
```

`infra/terraform/modules/network/aws/variables.tf`: identical to the Azure file **without** `resource_group_name`, and with `region` described as "AWS region".

`infra/terraform/modules/network/aws/main.tf`:
```hcl
locals {
  name = "${var.project}-${var.environment}"
}

resource "aws_vpc" "this" {
  cidr_block           = var.cidr
  enable_dns_support   = true
  enable_dns_hostnames = true
  tags                 = merge(var.tags, { Name = "vpc-${local.name}" })
}

resource "aws_subnet" "public" {
  vpc_id                  = aws_vpc.this.id
  cidr_block              = cidrsubnet(var.cidr, 8, 1)
  map_public_ip_on_launch = false # public IP is attached explicitly by the compute module
  tags                    = merge(var.tags, { Name = "snet-${local.name}-app" })
}

resource "aws_internet_gateway" "this" {
  vpc_id = aws_vpc.this.id
  tags   = merge(var.tags, { Name = "igw-${local.name}" })
}

resource "aws_route_table" "public" {
  vpc_id = aws_vpc.this.id
  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.this.id
  }
  tags = merge(var.tags, { Name = "rt-${local.name}-public" })
}

resource "aws_route_table_association" "public" {
  subnet_id      = aws_subnet.public.id
  route_table_id = aws_route_table.public.id
}

resource "aws_security_group" "app" {
  name        = "sg-${local.name}-app"
  description = "App VM: HTTPS from internet, SSH from admin CIDRs"
  vpc_id      = aws_vpc.this.id
  tags        = var.tags
}

resource "aws_vpc_security_group_ingress_rule" "https" {
  security_group_id = aws_security_group.app.id
  description       = "HTTPS from internet"
  ip_protocol       = "tcp"
  from_port         = 443
  to_port           = 443
  cidr_ipv4         = "0.0.0.0/0"
  tags              = var.tags
}

resource "aws_vpc_security_group_ingress_rule" "ssh" {
  for_each          = toset(var.allowed_ssh_cidrs)
  security_group_id = aws_security_group.app.id
  description       = "SSH from admin CIDR"
  ip_protocol       = "tcp"
  from_port         = 22
  to_port           = 22
  cidr_ipv4         = each.value
  tags              = var.tags
}

resource "aws_vpc_security_group_egress_rule" "all" {
  security_group_id = aws_security_group.app.id
  description       = "Outbound for package updates and secret retrieval"
  ip_protocol       = "-1"
  cidr_ipv4         = "0.0.0.0/0"
  tags              = var.tags
}

# --- VPC flow logs → CloudWatch, KMS encrypted ---

resource "aws_kms_key" "logs" {
  description             = "Flow log encryption for ${local.name}"
  enable_key_rotation     = true
  deletion_window_in_days = 30
  tags                    = var.tags
}

resource "aws_cloudwatch_log_group" "flow" {
  name              = "/vpc/${local.name}/flow-logs"
  retention_in_days = 90
  kms_key_id        = aws_kms_key.logs.arn
  tags              = var.tags
}

data "aws_iam_policy_document" "flow_assume" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["vpc-flow-logs.amazonaws.com"]
    }
  }
}

data "aws_iam_policy_document" "flow_write" {
  statement {
    actions   = ["logs:CreateLogStream", "logs:PutLogEvents", "logs:DescribeLogGroups", "logs:DescribeLogStreams"]
    resources = ["${aws_cloudwatch_log_group.flow.arn}:*"]
  }
}

resource "aws_iam_role" "flow" {
  name               = "role-${local.name}-flow-logs"
  assume_role_policy = data.aws_iam_policy_document.flow_assume.json
  tags               = var.tags
}

resource "aws_iam_role_policy" "flow" {
  name   = "flow-logs-write"
  role   = aws_iam_role.flow.id
  policy = data.aws_iam_policy_document.flow_write.json
}

resource "aws_flow_log" "this" {
  vpc_id          = aws_vpc.this.id
  traffic_type    = "ALL"
  iam_role_arn    = aws_iam_role.flow.arn
  log_destination = aws_cloudwatch_log_group.flow.arn
  tags            = var.tags
}
```

`infra/terraform/modules/network/aws/outputs.tf`:
```hcl
output "vpc_id" {
  value = aws_vpc.this.id
}

output "subnet_id" {
  value = aws_subnet.public.id
}

output "security_group_id" {
  value = aws_security_group.app.id
}
```

`infra/terraform/modules/network/aws/tests/plan.tftest.hcl`:
```hcl
mock_provider "aws" {}

variables {
  project           = "sap"
  environment       = "dev"
  region            = "us-east-1"
  cidr              = "10.20.0.0/16"
  allowed_ssh_cidrs = ["203.0.113.0/24", "198.51.100.0/24"]
  tags              = { project = "sap", environment = "dev", owner = "platform", cost-center = "eng" }
}

run "ingress_rules" {
  command = plan

  assert {
    condition     = aws_vpc_security_group_ingress_rule.https.from_port == 443 && aws_vpc_security_group_ingress_rule.https.cidr_ipv4 == "0.0.0.0/0"
    error_message = "HTTPS must be open on 443."
  }
  assert {
    condition     = length(aws_vpc_security_group_ingress_rule.ssh) == 2
    error_message = "One SSH rule per allowed CIDR."
  }
  assert {
    condition     = aws_cloudwatch_log_group.flow.retention_in_days == 90 && aws_flow_log.this.traffic_type == "ALL"
    error_message = "Flow logs must capture ALL traffic for 90 days."
  }
  assert {
    condition     = aws_kms_key.logs.enable_key_rotation == true
    error_message = "Log KMS key must rotate."
  }
}

run "rejects_world_open_ssh" {
  command = plan
  variables {
    allowed_ssh_cidrs = ["::/0"]
  }
  expect_failures = [var.allowed_ssh_cidrs]
}
```

- [ ] **Step 4: Run AWS network tests and fmt**

Run: `cd infra/terraform/modules/network/aws && terraform init -backend=false && terraform test && cd - && terraform fmt -check -recursive infra/terraform`
Expected: `Success! 2 passed, 0 failed.`; fmt prints nothing.

- [ ] **Step 5: Commit**

```bash
git add infra
git commit -m "feat(infra): network modules for azure and aws with terraform tests

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>"
```

### Task 12: Terraform `compute` modules (Azure + AWS)

**Files:**
- Create: `infra/terraform/modules/compute/azure/{versions,variables,main,outputs}.tf` + `tests/plan.tftest.hcl`
- Create: `infra/terraform/modules/compute/aws/{versions,variables,main,outputs}.tf` + `tests/plan.tftest.hcl`

**Interfaces:**
- Azure inputs: `project, environment, region, resource_group_name, subnet_id, instance_size, ssh_public_key, tags`; outputs `vm_public_ip, vm_private_ip, identity_id, identity_principal_id`
- AWS inputs: `project, environment, region, subnet_id, security_group_id, instance_size, ssh_public_key, ami_id, tags`; outputs `vm_public_ip, vm_private_ip, identity_id (role ARN), iam_role_name`

- [ ] **Step 1: Azure compute module**

`versions.tf`: same as Task 11 Azure.

`variables.tf`:
```hcl
variable "project" { type = string }
variable "environment" { type = string }
variable "region" { type = string }
variable "resource_group_name" { type = string }
variable "subnet_id" { type = string }

variable "instance_size" {
  description = "VM size. The allow-list per environment is enforced by OPA policy."
  type        = string
  default     = "Standard_B2s"
}

variable "ssh_public_key" {
  description = "OpenSSH public key for the platform admin user."
  type        = string
  validation {
    condition     = can(regex("^(ssh-ed25519|ssh-rsa|ecdsa-sha2-nistp256) ", var.ssh_public_key))
    error_message = "ssh_public_key must be an OpenSSH public key."
  }
}

variable "tags" { type = map(string) }
```

`main.tf`:
```hcl
locals {
  name       = "${var.project}-${var.environment}"
  admin_user = "platform"
}

resource "azurerm_user_assigned_identity" "vm" {
  name                = "id-${local.name}-vm"
  location            = var.region
  resource_group_name = var.resource_group_name
  tags                = var.tags
}

resource "azurerm_public_ip" "vm" {
  name                = "pip-${local.name}-vm"
  location            = var.region
  resource_group_name = var.resource_group_name
  allocation_method   = "Static"
  sku                 = "Standard"
  tags                = var.tags
}

resource "azurerm_network_interface" "vm" {
  name                = "nic-${local.name}-vm"
  location            = var.region
  resource_group_name = var.resource_group_name
  tags                = var.tags

  ip_configuration {
    name                          = "primary"
    subnet_id                     = var.subnet_id
    private_ip_address_allocation = "Dynamic"
    public_ip_address_id          = azurerm_public_ip.vm.id
  }
}

resource "azurerm_linux_virtual_machine" "this" {
  name                            = "vm-${local.name}-app"
  location                        = var.region
  resource_group_name             = var.resource_group_name
  size                            = var.instance_size
  admin_username                  = local.admin_user
  disable_password_authentication = true
  network_interface_ids           = [azurerm_network_interface.vm.id]
  encryption_at_host_enabled      = true
  allow_extension_operations      = true # Ansible installs the Azure Monitor agent extension
  tags                            = var.tags

  admin_ssh_key {
    username   = local.admin_user
    public_key = var.ssh_public_key
  }

  identity {
    type         = "UserAssigned"
    identity_ids = [azurerm_user_assigned_identity.vm.id]
  }

  os_disk {
    caching              = "ReadWrite"
    storage_account_type = "Premium_LRS"
  }

  source_image_reference {
    publisher = "Canonical"
    offer     = "0001-com-ubuntu-server-jammy"
    sku       = "22_04-lts-gen2"
    version   = "latest"
  }

  boot_diagnostics {} # managed storage account
}
```

`outputs.tf`:
```hcl
output "vm_public_ip" {
  value = azurerm_public_ip.vm.ip_address
}

output "vm_private_ip" {
  value = azurerm_network_interface.vm.private_ip_address
}

output "identity_id" {
  value = azurerm_user_assigned_identity.vm.id
}

output "identity_principal_id" {
  value = azurerm_user_assigned_identity.vm.principal_id
}
```

`tests/plan.tftest.hcl`:
```hcl
mock_provider "azurerm" {}

variables {
  project             = "sap"
  environment         = "dev"
  region              = "eastus"
  resource_group_name = "rg-sap-dev"
  subnet_id           = "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/rg-sap-dev/providers/Microsoft.Network/virtualNetworks/vnet/subnets/snet"
  ssh_public_key      = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIExampleKeyForTestsOnly0000000000000000000 test"
  tags                = { project = "sap", environment = "dev", owner = "platform", cost-center = "eng" }
}

run "hardened_vm" {
  command = plan

  assert {
    condition     = azurerm_linux_virtual_machine.this.disable_password_authentication == true
    error_message = "Password auth must be disabled."
  }
  assert {
    condition     = azurerm_linux_virtual_machine.this.encryption_at_host_enabled == true
    error_message = "Encryption at host must be enabled."
  }
  assert {
    condition     = azurerm_linux_virtual_machine.this.identity[0].type == "UserAssigned"
    error_message = "VM must use a user-assigned managed identity."
  }
  assert {
    condition     = azurerm_public_ip.vm.sku == "Standard"
    error_message = "Public IP must be Standard SKU (zone-redundant, secure by default)."
  }
}

run "rejects_bad_key" {
  command = plan
  variables {
    ssh_public_key = "not-a-key"
  }
  expect_failures = [var.ssh_public_key]
}
```

- [ ] **Step 2: AWS compute module**

`versions.tf`: same as Task 11 AWS.

`variables.tf`: as Azure's but replace `resource_group_name` with `security_group_id` (string) and add:
```hcl
variable "ami_id" {
  description = "Ubuntu 22.04 AMI for the region. Replace the placeholder per docs/runbooks/deploy.md."
  type        = string
  validation {
    condition     = can(regex("^ami-[0-9a-f]{17}$", var.ami_id))
    error_message = "ami_id must look like ami-xxxxxxxxxxxxxxxxx."
  }
}
```
and `instance_size` default `"t3.small"`.

`main.tf`:
```hcl
locals {
  name = "${var.project}-${var.environment}"
}

data "aws_iam_policy_document" "assume" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["ec2.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "vm" {
  name               = "role-${local.name}-vm"
  assume_role_policy = data.aws_iam_policy_document.assume.json
  tags               = var.tags
}

resource "aws_iam_instance_profile" "vm" {
  name = "profile-${local.name}-vm"
  role = aws_iam_role.vm.name
  tags = var.tags
}

resource "aws_key_pair" "admin" {
  key_name   = "key-${local.name}-admin"
  public_key = var.ssh_public_key
  tags       = var.tags
}

resource "aws_kms_key" "disk" {
  description         = "Root volume encryption for ${local.name}"
  enable_key_rotation = true
  tags                = var.tags
}

resource "aws_eip" "vm" {
  domain = "vpc"
  tags   = merge(var.tags, { Name = "eip-${local.name}-vm" })
}

resource "aws_instance" "this" {
  ami                         = var.ami_id
  instance_type               = var.instance_size
  subnet_id                   = var.subnet_id
  vpc_security_group_ids      = [var.security_group_id]
  iam_instance_profile        = aws_iam_instance_profile.vm.name
  key_name                    = aws_key_pair.admin.key_name
  associate_public_ip_address = false
  monitoring                  = true
  ebs_optimized               = true
  tags                        = merge(var.tags, { Name = "vm-${local.name}-app" })

  metadata_options {
    http_endpoint               = "enabled"
    http_tokens                 = "required" # IMDSv2 only
    http_put_response_hop_limit = 1
  }

  root_block_device {
    volume_type = "gp3"
    volume_size = 20
    encrypted   = true
    kms_key_id  = aws_kms_key.disk.arn
  }
}

resource "aws_eip_association" "vm" {
  instance_id   = aws_instance.this.id
  allocation_id = aws_eip.vm.id
}
```

`outputs.tf`:
```hcl
output "vm_public_ip" {
  value = aws_eip.vm.public_ip
}

output "vm_private_ip" {
  value = aws_instance.this.private_ip
}

output "identity_id" {
  value = aws_iam_role.vm.arn
}

output "iam_role_name" {
  value = aws_iam_role.vm.name
}
```

`tests/plan.tftest.hcl`:
```hcl
mock_provider "aws" {}

variables {
  project           = "sap"
  environment       = "dev"
  region            = "us-east-1"
  subnet_id         = "subnet-0123456789abcdef0"
  security_group_id = "sg-0123456789abcdef0"
  ami_id            = "ami-0123456789abcdef0"
  ssh_public_key    = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIExampleKeyForTestsOnly0000000000000000000 test"
  tags              = { project = "sap", environment = "dev", owner = "platform", cost-center = "eng" }
}

run "hardened_instance" {
  command = plan

  assert {
    condition     = aws_instance.this.metadata_options[0].http_tokens == "required"
    error_message = "IMDSv2 must be required."
  }
  assert {
    condition     = aws_instance.this.root_block_device[0].encrypted == true
    error_message = "Root volume must be encrypted."
  }
  assert {
    condition     = aws_instance.this.monitoring == true && aws_instance.this.ebs_optimized == true
    error_message = "Detailed monitoring and EBS optimisation must be on."
  }
}

run "rejects_bad_ami" {
  command = plan
  variables {
    ami_id = "ami-123"
  }
  expect_failures = [var.ami_id]
}
```

- [ ] **Step 3: Run both compute test suites + fmt**

Run:
```bash
for d in infra/terraform/modules/compute/*; do (cd $d && terraform init -backend=false >/dev/null && terraform test) || exit 1; done
terraform fmt -check -recursive infra/terraform
```
Expected: 2 passed each; fmt clean.

- [ ] **Step 4: Commit**

```bash
git add infra
git commit -m "feat(infra): hardened compute modules for azure and aws

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>"
```

### Task 13: ARM Key Vault template and `secrets` modules

**Files:**
- Create: `infra/arm/keyvault.json`, `infra/arm/keyvault.parameters.json`
- Create: `infra/terraform/modules/secrets/azure/{versions,variables,main,outputs}.tf` + `tests/plan.tftest.hcl`
- Create: `infra/terraform/modules/secrets/aws/{versions,variables,main,outputs}.tf` + `tests/plan.tftest.hcl`

**Interfaces:**
- Azure inputs: `project, environment, region, resource_group_name, principal_id, tags`; outputs `secret_store_id, secret_store_uri`
- AWS inputs: `project, environment, region, iam_role_name, tags`; outputs `secret_store_id (secret ARN), secret_store_uri (secret name)`
- ARM template outputs: `keyVaultId`, `keyVaultUri`

- [ ] **Step 1: ARM template**

`infra/arm/keyvault.json`:
```json
{
  "$schema": "https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#",
  "contentVersion": "1.0.0.0",
  "metadata": {
    "description": "Key Vault with RBAC authorization, purge protection and public network access disabled. Deployed by the Terraform secrets/azure module."
  },
  "parameters": {
    "keyVaultName": {
      "type": "string",
      "minLength": 3,
      "maxLength": 24,
      "metadata": { "description": "Globally unique Key Vault name." }
    },
    "location": {
      "type": "string",
      "defaultValue": "[resourceGroup().location]",
      "metadata": { "description": "Azure region." }
    },
    "tenantId": {
      "type": "string",
      "defaultValue": "[subscription().tenantId]",
      "metadata": { "description": "Tenant that owns the vault." }
    },
    "tags": {
      "type": "object",
      "defaultValue": {},
      "metadata": { "description": "Resource tags." }
    }
  },
  "variables": {
    "diagnosticName": "[format('{0}-diag', parameters('keyVaultName'))]"
  },
  "resources": [
    {
      "type": "Microsoft.KeyVault/vaults",
      "apiVersion": "2023-07-01",
      "name": "[parameters('keyVaultName')]",
      "location": "[parameters('location')]",
      "tags": "[parameters('tags')]",
      "properties": {
        "tenantId": "[parameters('tenantId')]",
        "sku": { "family": "A", "name": "standard" },
        "enableRbacAuthorization": true,
        "enableSoftDelete": true,
        "softDeleteRetentionInDays": 90,
        "enablePurgeProtection": true,
        "publicNetworkAccess": "Disabled",
        "networkAcls": { "defaultAction": "Deny", "bypass": "AzureServices" }
      }
    }
  ],
  "outputs": {
    "keyVaultId": {
      "type": "string",
      "value": "[resourceId('Microsoft.KeyVault/vaults', parameters('keyVaultName'))]"
    },
    "keyVaultUri": {
      "type": "string",
      "value": "[reference(resourceId('Microsoft.KeyVault/vaults', parameters('keyVaultName')), '2023-07-01').vaultUri]"
    },
    "diagnosticSettingName": {
      "type": "string",
      "value": "[variables('diagnosticName')]"
    }
  }
}
```

`infra/arm/keyvault.parameters.json`:
```json
{
  "$schema": "https://schema.management.azure.com/schemas/2019-04-01/deploymentParameters.json#",
  "contentVersion": "1.0.0.0",
  "parameters": {
    "keyVaultName": { "value": "kv-sap-dev-REPLACE_ME_SUFFIX" },
    "tags": { "value": { "project": "sap", "environment": "dev", "owner": "platform", "cost-center": "eng" } }
  }
}
```
(The parameters file exists so the template can be validated/deployed standalone with `az deployment group validate`; Terraform passes its own parameters.)

- [ ] **Step 2: Azure secrets module (wraps the ARM template)**

`variables.tf`:
```hcl
variable "project" { type = string }
variable "environment" { type = string }
variable "region" { type = string }
variable "resource_group_name" { type = string }

variable "principal_id" {
  description = "Principal ID of the VM's managed identity that may read secrets."
  type        = string
}

variable "tags" { type = map(string) }
```

`main.tf`:
```hcl
locals {
  name = "${var.project}-${var.environment}"
  # Key Vault names are globally unique and ≤ 24 chars; a short hash of the RG keeps it stable.
  kv_name = substr("kv-${local.name}-${md5(var.resource_group_name)}", 0, 24)
}

resource "azurerm_resource_group_template_deployment" "keyvault" {
  name                = "kv-${local.name}"
  resource_group_name = var.resource_group_name
  deployment_mode     = "Incremental"
  template_content    = file("${path.module}/../../../../arm/keyvault.json")
  parameters_content = jsonencode({
    keyVaultName = { value = local.kv_name }
    location     = { value = var.region }
    tags         = { value = var.tags }
  })
  tags = var.tags
}

locals {
  arm_outputs = jsondecode(azurerm_resource_group_template_deployment.keyvault.output_content)
}

resource "azurerm_role_assignment" "vm_reads_secrets" {
  scope                = local.arm_outputs.keyVaultId.value
  role_definition_name = "Key Vault Secrets User"
  principal_id         = var.principal_id
}
```

`outputs.tf`:
```hcl
output "secret_store_id" {
  value = local.arm_outputs.keyVaultId.value
}

output "secret_store_uri" {
  value = local.arm_outputs.keyVaultUri.value
}
```

`tests/plan.tftest.hcl`:
```hcl
mock_provider "azurerm" {}

variables {
  project             = "sap"
  environment         = "dev"
  region              = "eastus"
  resource_group_name = "rg-sap-dev"
  principal_id        = "00000000-0000-0000-0000-000000000000"
  tags                = { project = "sap", environment = "dev", owner = "platform", cost-center = "eng" }
}

run "arm_wrapped_keyvault" {
  command = plan

  assert {
    condition     = azurerm_resource_group_template_deployment.keyvault.deployment_mode == "Incremental"
    error_message = "ARM deployment must be Incremental (never Complete — it would delete the RG contents)."
  }
  assert {
    condition     = length(jsondecode(azurerm_resource_group_template_deployment.keyvault.parameters_content).keyVaultName.value) <= 24 && startswith(jsondecode(azurerm_resource_group_template_deployment.keyvault.parameters_content).keyVaultName.value, "kv-sap-dev-")
    error_message = "Key Vault name must be ≤ 24 chars and prefixed."
  }
  assert {
    condition     = jsondecode(azurerm_resource_group_template_deployment.keyvault.template_content).resources[0].properties.enablePurgeProtection == true
    error_message = "ARM template must enable purge protection."
  }
  assert {
    condition     = jsondecode(azurerm_resource_group_template_deployment.keyvault.template_content).resources[0].properties.publicNetworkAccess == "Disabled"
    error_message = "ARM template must disable public network access."
  }
  assert {
    condition     = azurerm_role_assignment.vm_reads_secrets.role_definition_name == "Key Vault Secrets User"
    error_message = "VM identity must get read-only secret access."
  }
}
```

- [ ] **Step 3: AWS secrets module**

`variables.tf`:
```hcl
variable "project" { type = string }
variable "environment" { type = string }
variable "region" { type = string }

variable "iam_role_name" {
  description = "Name of the VM instance role that may read the secret."
  type        = string
}

variable "tags" { type = map(string) }
```

`main.tf`:
```hcl
locals {
  name = "${var.project}-${var.environment}"
}

resource "aws_kms_key" "secrets" {
  description             = "Secrets Manager encryption for ${local.name}"
  enable_key_rotation     = true
  deletion_window_in_days = 30
  tags                    = var.tags
}

resource "aws_kms_alias" "secrets" {
  name          = "alias/${local.name}-secrets"
  target_key_id = aws_kms_key.secrets.key_id
}

# The secret's *value* is never in Terraform. It is written by `platformctl secrets rotate --execute`.
resource "aws_secretsmanager_secret" "app" {
  name                    = "${local.name}/app"
  description             = "Runtime secret for the secure-api service"
  kms_key_id              = aws_kms_key.secrets.arn
  recovery_window_in_days = 30
  tags                    = var.tags
}

data "aws_iam_policy_document" "read_secret" {
  statement {
    sid       = "ReadAppSecret"
    actions   = ["secretsmanager:GetSecretValue", "secretsmanager:DescribeSecret"]
    resources = [aws_secretsmanager_secret.app.arn]
  }
  statement {
    sid       = "DecryptWithSecretsKey"
    actions   = ["kms:Decrypt"]
    resources = [aws_kms_key.secrets.arn]
  }
}

resource "aws_iam_role_policy" "vm_reads_secret" {
  name   = "read-app-secret"
  role   = var.iam_role_name
  policy = data.aws_iam_policy_document.read_secret.json
}
```

`outputs.tf`:
```hcl
output "secret_store_id" {
  value = aws_secretsmanager_secret.app.arn
}

output "secret_store_uri" {
  value = aws_secretsmanager_secret.app.name
}
```

`tests/plan.tftest.hcl`:
```hcl
mock_provider "aws" {}

variables {
  project       = "sap"
  environment   = "dev"
  region        = "us-east-1"
  iam_role_name = "role-sap-dev-vm"
  tags          = { project = "sap", environment = "dev", owner = "platform", cost-center = "eng" }
}

run "encrypted_secret_least_privilege" {
  command = plan

  assert {
    condition     = aws_kms_key.secrets.enable_key_rotation == true
    error_message = "Secrets KMS key must rotate."
  }
  assert {
    condition     = aws_secretsmanager_secret.app.recovery_window_in_days == 30
    error_message = "Accidental deletion must be recoverable for 30 days."
  }
  assert {
    condition     = aws_secretsmanager_secret.app.name == "sap-dev/app"
    error_message = "Secret name must follow <project>-<env>/app."
  }
}
```

- [ ] **Step 4: Run tests, fmt, ARM JSON check**

```bash
for d in infra/terraform/modules/secrets/*; do (cd $d && terraform init -backend=false >/dev/null && terraform test) || exit 1; done
terraform fmt -check -recursive infra/terraform && make arm-check
```
Expected: 1 passed each; fmt clean; `ARM JSON ok`.

- [ ] **Step 5: Commit**

```bash
git add infra
git commit -m "feat(infra): ARM key vault template wrapped by terraform, and aws secrets module

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>"
```

### Task 14: Stacks and Terragrunt environments

**Files:**
- Create: `infra/terraform/stacks/azure/{versions,variables,main,outputs}.tf`, `infra/terraform/stacks/aws/{versions,variables,main,outputs}.tf`
- Create: `infra/terragrunt.hcl`, `infra/envs/{dev,prod}/{azure,aws}/terragrunt.hcl`

**Interfaces:**
- Stack inputs (both): `project, environment, region, cidr, allowed_ssh_cidrs, instance_size, ssh_public_key, tags` (+ `ami_id` for AWS)
- Stack outputs (both): `vm_public_ip, vm_private_ip, secret_store_id, secret_store_uri, identity_id`
- `TG_BACKEND=local|remote` selects the state backend.

- [ ] **Step 1: Azure stack**

`infra/terraform/stacks/azure/versions.tf`: same as Task 11 Azure.

`infra/terraform/stacks/azure/variables.tf`:
```hcl
variable "project" { type = string }
variable "environment" { type = string }
variable "region" { type = string }
variable "cidr" { type = string }
variable "allowed_ssh_cidrs" { type = list(string) }
variable "instance_size" { type = string }
variable "ssh_public_key" { type = string }
variable "tags" { type = map(string) }
```

`infra/terraform/stacks/azure/main.tf`:
```hcl
resource "azurerm_resource_group" "this" {
  name     = "rg-${var.project}-${var.environment}"
  location = var.region
  tags     = var.tags
}

module "network" {
  source              = "../../modules/network/azure"
  project             = var.project
  environment         = var.environment
  region              = var.region
  resource_group_name = azurerm_resource_group.this.name
  cidr                = var.cidr
  allowed_ssh_cidrs   = var.allowed_ssh_cidrs
  tags                = var.tags
}

module "compute" {
  source              = "../../modules/compute/azure"
  project             = var.project
  environment         = var.environment
  region              = var.region
  resource_group_name = azurerm_resource_group.this.name
  subnet_id           = module.network.subnet_id
  instance_size       = var.instance_size
  ssh_public_key      = var.ssh_public_key
  tags                = var.tags
}

module "secrets" {
  source              = "../../modules/secrets/azure"
  project             = var.project
  environment         = var.environment
  region              = var.region
  resource_group_name = azurerm_resource_group.this.name
  principal_id        = module.compute.identity_principal_id
  tags                = var.tags
}
```

`infra/terraform/stacks/azure/outputs.tf`:
```hcl
output "vm_public_ip" { value = module.compute.vm_public_ip }
output "vm_private_ip" { value = module.compute.vm_private_ip }
output "secret_store_id" { value = module.secrets.secret_store_id }
output "secret_store_uri" { value = module.secrets.secret_store_uri }
output "identity_id" { value = module.compute.identity_id }
```

- [ ] **Step 2: AWS stack**

`versions.tf`: Task 11 AWS. `variables.tf`: Azure's plus
```hcl
variable "ami_id" { type = string }
```

`main.tf`:
```hcl
module "network" {
  source            = "../../modules/network/aws"
  project           = var.project
  environment       = var.environment
  region            = var.region
  cidr              = var.cidr
  allowed_ssh_cidrs = var.allowed_ssh_cidrs
  tags              = var.tags
}

module "compute" {
  source            = "../../modules/compute/aws"
  project           = var.project
  environment       = var.environment
  region            = var.region
  subnet_id         = module.network.subnet_id
  security_group_id = module.network.security_group_id
  instance_size     = var.instance_size
  ssh_public_key    = var.ssh_public_key
  ami_id            = var.ami_id
  tags              = var.tags
}

module "secrets" {
  source        = "../../modules/secrets/aws"
  project       = var.project
  environment   = var.environment
  region        = var.region
  iam_role_name = module.compute.iam_role_name
  tags          = var.tags
}
```
`outputs.tf`: identical to Azure's.

- [ ] **Step 3: Terragrunt root**

`infra/terragrunt.hcl`:
```hcl
# Root Terragrunt config. Each unit under envs/<env>/<cloud> includes this file.
# The unit path encodes environment and cloud, so units only declare inputs.

locals {
  path_parts   = split("/", path_relative_to_include())
  environment  = local.path_parts[1]
  cloud        = local.path_parts[2]
  backend_mode = get_env("TG_BACKEND", "local") # local | remote
  state_key    = "${local.environment}/${local.cloud}/terraform.tfstate"

  backend_configs = {
    local = {
      backend = "local"
      config  = { path = "${get_terragrunt_dir()}/.terragrunt-cache/terraform.tfstate" }
    }
    "remote-azure" = {
      backend = "azurerm"
      config = {
        resource_group_name  = "rg-tfstate-placeholder"
        storage_account_name = "tfstateplaceholder"
        container_name       = "tfstate"
        key                  = local.state_key
        use_oidc             = true
      }
    }
    "remote-aws" = {
      backend = "s3"
      config = {
        bucket         = "tfstate-placeholder"
        key            = local.state_key
        region         = "us-east-1"
        encrypt        = true
        dynamodb_table = "tfstate-placeholder-lock"
      }
    }
  }
  backend_key = local.backend_mode == "remote" ? "remote-${local.cloud}" : "local"
  backend     = lookup(local.backend_configs, local.backend_key)

  azure_provider = <<-EOT
    provider "azurerm" {
      features {}
      resource_provider_registrations = "none"
      subscription_id                 = "${get_env("ARM_SUBSCRIPTION_ID", "00000000-0000-0000-0000-000000000000")}"
    }
  EOT

  aws_provider = <<-EOT
    provider "aws" {
      region                      = "${get_env("AWS_REGION", "us-east-1")}"
      skip_credentials_validation = true
      skip_requesting_account_id  = true
      skip_metadata_api_check     = true
      skip_region_validation      = true
    }
  EOT
}

terraform {
  # The double slash makes Terragrunt copy all of infra/ into the cache and run in the stack
  # subfolder, so the stacks' relative module paths (../../modules/...) and the secrets module's
  # relative ARM path keep working.
  source = "${get_parent_terragrunt_dir()}//terraform/stacks/${local.cloud}"
}

remote_state {
  backend = local.backend.backend
  config  = local.backend.config
  generate = {
    path      = "backend.tf"
    if_exists = "overwrite_terragrunt"
  }
}

generate "provider" {
  path      = "provider.tf"
  if_exists = "overwrite_terragrunt"
  contents  = local.cloud == "azure" ? local.azure_provider : local.aws_provider
}

inputs = {
  project     = "sap"
  environment = local.environment
  tags = {
    project     = "sap"
    environment = local.environment
    owner       = "platform-team"
    cost-center = "engineering"
    managed-by  = "terragrunt"
  }
}
```

- [ ] **Step 4: Environment units**

`infra/envs/dev/azure/terragrunt.hcl`:
```hcl
include "root" {
  path = find_in_parent_folders("terragrunt.hcl")
}

inputs = {
  region            = "eastus"
  cidr              = "10.10.0.0/16"
  allowed_ssh_cidrs = ["203.0.113.0/24"] # replace with your admin egress CIDR
  instance_size     = "Standard_B2s"
  ssh_public_key    = get_env("PLATFORM_SSH_PUBLIC_KEY", "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIExampleKeyForTestsOnly0000000000000000000 placeholder")
}
```

`infra/envs/dev/aws/terragrunt.hcl`:
```hcl
include "root" {
  path = find_in_parent_folders("terragrunt.hcl")
}

inputs = {
  region            = "us-east-1"
  cidr              = "10.20.0.0/16"
  allowed_ssh_cidrs = ["203.0.113.0/24"]
  instance_size     = "t3.small"
  ami_id            = "ami-0123456789abcdef0" # placeholder: resolve per docs/runbooks/deploy.md
  ssh_public_key    = get_env("PLATFORM_SSH_PUBLIC_KEY", "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIExampleKeyForTestsOnly0000000000000000000 placeholder")
}
```

`infra/envs/prod/azure/terragrunt.hcl`: as dev/azure with `region = "eastus2"`, `cidr = "10.11.0.0/16"`, `instance_size = "Standard_D2s_v5"`.

`infra/envs/prod/aws/terragrunt.hcl`: as dev/aws with `region = "us-east-2"`, `cidr = "10.21.0.0/16"`, `instance_size = "t3.medium"`.

- [ ] **Step 5: Validate stacks and run a real terragrunt plan with dummy credentials**

```bash
make tf-fmt tf-validate
export ARM_CLIENT_ID=00000000-0000-0000-0000-000000000000 ARM_CLIENT_SECRET=REPLACE_ME_DUMMY ARM_TENANT_ID=00000000-0000-0000-0000-000000000000 ARM_SUBSCRIPTION_ID=00000000-0000-0000-0000-000000000000
export AWS_ACCESS_KEY_ID=REPLACE_ME_DUMMY AWS_SECRET_ACCESS_KEY=REPLACE_ME_DUMMY AWS_REGION=us-east-1
.venv/bin/platformctl plan aws dev --no-policy
.venv/bin/platformctl plan azure dev --no-policy
```
Expected: both print a plan table with ~20 (aws) / ~12 (azure) `create` rows, and `.platformctl/plans/{aws,azure}-dev.json` exist. If the azurerm provider refuses to plan with dummy credentials (error mentions obtaining a token), add `use_cli = false` and `use_msi = false` to `local.azure_provider` and retry; the plan needs no API calls because the stack has no data sources.

- [ ] **Step 6: Commit**

```bash
git add infra
git commit -m "feat(infra): composition stacks and terragrunt environments with selectable backend

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>"
```

---

## Phase 3 — Policy as code

### Task 15: OPA/Rego policies with unit tests, evaluated against real plan JSON

**Files:**
- Create: `policy/terraform/helpers.rego`, `policy/terraform/{ingress,encryption,tags,secrets,instances,protection}.rego` and matching `*_test.rego`
- Create: `policy/README.md`
- Modify: `Makefile` (remove `--data` from `policy-test`)

**Interfaces:**
- Consumes: Terraform plan JSON (`terraform show -json`) — `input.resource_changes[]`, `input.variables.environment.value`
- Produces: `deny contains msg` rules in namespaces `terraform.ingress`, `terraform.encryption`, `terraform.tags`, `terraform.secrets`, `terraform.instances`, `terraform.protection`; shared helpers in `terraform.helpers`
- `platformctl plan <cloud> <env>` (Task 4) runs these through Conftest.

- [ ] **Step 1: Shared helpers**

`policy/terraform/helpers.rego`:
```rego
package terraform.helpers

import rego.v1

# Resources that will exist after apply (created or updated), with their planned attributes.
planned contains r if {
	some r in input.resource_changes
	some action in r.change.actions
	action in {"create", "update"}
}

# Resources the plan would destroy (including replacements).
destroyed contains r if {
	some r in input.resource_changes
	"delete" in r.change.actions
}

environment := input.variables.environment.value

is_prod if environment == "prod"

# True when the attribute is neither known nor "known after apply".
missing(r, attr) if {
	not r.change.after[attr]
	not r.change.after_unknown[attr]
}
```

- [ ] **Step 2: Ingress policy + test**

`policy/terraform/ingress.rego`:
```rego
package terraform.ingress

import rego.v1

import data.terraform.helpers

world := {"*", "Internet", "0.0.0.0/0", "::/0"}

# Azure NSG: only 443 may be allowed inbound from the internet.
deny contains msg if {
	some r in helpers.planned
	r.type == "azurerm_network_security_rule"
	a := r.change.after
	a.direction == "Inbound"
	a.access == "Allow"
	a.source_address_prefix in world
	a.destination_port_range != "443"
	msg := sprintf("%s allows inbound %s from the internet; only 443 is permitted", [r.address, a.destination_port_range])
}

# AWS SG rule resources.
deny contains msg if {
	some r in helpers.planned
	r.type == "aws_vpc_security_group_ingress_rule"
	a := r.change.after
	a.cidr_ipv4 == "0.0.0.0/0"
	a.from_port != 443
	msg := sprintf("%s allows inbound port %v from 0.0.0.0/0; only 443 is permitted", [r.address, a.from_port])
}

# AWS legacy inline ingress blocks.
deny contains msg if {
	some r in helpers.planned
	r.type == "aws_security_group"
	some rule in r.change.after.ingress
	"0.0.0.0/0" in rule.cidr_blocks
	rule.from_port != 443
	msg := sprintf("%s inline ingress allows port %v from 0.0.0.0/0", [r.address, rule.from_port])
}
```

`policy/terraform/ingress_test.rego`:
```rego
package terraform.ingress_test

import rego.v1

import data.terraform.ingress

nsg(port, src) := {"resource_changes": [{
	"address": "azurerm_network_security_rule.x", "type": "azurerm_network_security_rule",
	"change": {"actions": ["create"], "after": {"direction": "Inbound", "access": "Allow", "source_address_prefix": src, "destination_port_range": port}},
}]}

sg(port, cidr) := {"resource_changes": [{
	"address": "aws_vpc_security_group_ingress_rule.x", "type": "aws_vpc_security_group_ingress_rule",
	"change": {"actions": ["create"], "after": {"cidr_ipv4": cidr, "from_port": port}},
}]}

test_azure_https_from_internet_ok if {
	count(ingress.deny) == 0 with input as nsg("443", "Internet")
}

test_azure_ssh_from_internet_denied if {
	count(ingress.deny) == 1 with input as nsg("22", "*")
}

test_azure_ssh_from_admin_cidr_ok if {
	count(ingress.deny) == 0 with input as nsg("22", "203.0.113.0/24")
}

test_aws_https_ok if {
	count(ingress.deny) == 0 with input as sg(443, "0.0.0.0/0")
}

test_aws_ssh_world_denied if {
	count(ingress.deny) == 1 with input as sg(22, "0.0.0.0/0")
}

test_deleted_resources_ignored if {
	count(ingress.deny) == 0 with input as {"resource_changes": [{
		"address": "a", "type": "aws_vpc_security_group_ingress_rule",
		"change": {"actions": ["delete"], "before": {"cidr_ipv4": "0.0.0.0/0", "from_port": 22}},
	}]}
}
```

- [ ] **Step 3: Encryption policy + test**

`policy/terraform/encryption.rego`:
```rego
package terraform.encryption

import rego.v1

import data.terraform.helpers

deny contains msg if {
	some r in helpers.planned
	r.type == "azurerm_linux_virtual_machine"
	r.change.after.encryption_at_host_enabled != true
	msg := sprintf("%s must set encryption_at_host_enabled = true", [r.address])
}

deny contains msg if {
	some r in helpers.planned
	r.type == "aws_instance"
	some disk in r.change.after.root_block_device
	disk.encrypted != true
	msg := sprintf("%s root volume must be encrypted", [r.address])
}

deny contains msg if {
	some r in helpers.planned
	r.type == "aws_secretsmanager_secret"
	helpers.missing(r, "kms_key_id")
	msg := sprintf("%s must use a customer-managed KMS key", [r.address])
}

deny contains msg if {
	some r in helpers.planned
	r.type == "aws_cloudwatch_log_group"
	helpers.missing(r, "kms_key_id")
	msg := sprintf("%s must be KMS encrypted", [r.address])
}

deny contains msg if {
	some r in helpers.planned
	r.type == "aws_kms_key"
	r.change.after.enable_key_rotation != true
	msg := sprintf("%s must enable key rotation", [r.address])
}
```

`policy/terraform/encryption_test.rego`:
```rego
package terraform.encryption_test

import rego.v1

import data.terraform.encryption

res(type, after, unknown) := {"resource_changes": [{"address": concat(".", [type, "x"]), "type": type, "change": {"actions": ["create"], "after": after, "after_unknown": unknown}}]}

test_vm_encrypted_ok if {
	count(encryption.deny) == 0 with input as res("azurerm_linux_virtual_machine", {"encryption_at_host_enabled": true}, {})
}

test_vm_unencrypted_denied if {
	count(encryption.deny) == 1 with input as res("azurerm_linux_virtual_machine", {"encryption_at_host_enabled": false}, {})
}

test_instance_root_unencrypted_denied if {
	count(encryption.deny) == 1 with input as res("aws_instance", {"root_block_device": [{"encrypted": false}]}, {})
}

test_secret_kms_known_after_apply_ok if {
	count(encryption.deny) == 0 with input as res("aws_secretsmanager_secret", {}, {"kms_key_id": true})
}

test_secret_no_kms_denied if {
	count(encryption.deny) == 1 with input as res("aws_secretsmanager_secret", {"kms_key_id": null}, {})
}

test_kms_rotation_denied if {
	count(encryption.deny) == 1 with input as res("aws_kms_key", {"enable_key_rotation": false}, {})
}
```

- [ ] **Step 4: Tags policy + test**

`policy/terraform/tags.rego`:
```rego
package terraform.tags

import rego.v1

import data.terraform.helpers

required := {"project", "environment", "owner", "cost-center"}

# Only resources that expose a known `tags` object are checked; resources without a tags
# attribute (subnets, role assignments) and tags known-after-apply are skipped.
deny contains msg if {
	some r in helpers.planned
	tags := r.change.after.tags
	is_object(tags)
	missing := required - {k | some k, _ in tags}
	count(missing) > 0
	msg := sprintf("%s is missing required tags: %v", [r.address, sort(missing)])
}
```

`policy/terraform/tags_test.rego`:
```rego
package terraform.tags_test

import rego.v1

import data.terraform.tags

res(t) := {"resource_changes": [{"address": "aws_vpc.x", "type": "aws_vpc", "change": {"actions": ["create"], "after": {"tags": t}}}]}

test_all_tags_ok if {
	count(tags.deny) == 0 with input as res({"project": "p", "environment": "dev", "owner": "o", "cost-center": "c", "extra": "e"})
}

test_missing_owner_denied if {
	msgs := tags.deny with input as res({"project": "p", "environment": "dev", "cost-center": "c"})
	count(msgs) == 1
	some m in msgs
	contains(m, "owner")
}

test_untagged_resource_type_skipped if {
	count(tags.deny) == 0 with input as {"resource_changes": [{"address": "azurerm_subnet.x", "type": "azurerm_subnet", "change": {"actions": ["create"], "after": {"name": "s"}}}]}
}
```

- [ ] **Step 5: Inline-secrets policy + test**

`policy/terraform/secrets.rego`:
```rego
package terraform.secrets

import rego.v1

import data.terraform.helpers

# Secret *values* never belong in IaC. These resource types carry values into state.
forbidden_types := {"aws_secretsmanager_secret_version", "azurerm_key_vault_secret"}

patterns := [
	`AKIA[0-9A-Z]{16}`,
	`-----BEGIN [A-Z ]*PRIVATE KEY-----`,
	`(?i)ghp_[A-Za-z0-9]{36}`,
	`(?i)xox[bap]-[0-9A-Za-z-]{10,}`,
]

deny contains msg if {
	some r in helpers.planned
	r.type in forbidden_types
	msg := sprintf("%s writes a secret value into Terraform state; use `platformctl secrets rotate --execute` instead", [r.address])
}

deny contains msg if {
	some r in helpers.planned
	walk(r.change.after, [path, value])
	is_string(value)
	some p in patterns
	regex.match(p, value)
	msg := sprintf("%s attribute %v looks like a credential", [r.address, concat(".", [sprintf("%v", [x]) | some x in path])])
}
```

`policy/terraform/secrets_test.rego`:
```rego
package terraform.secrets_test

import rego.v1

import data.terraform.secrets

res(type, after) := {"resource_changes": [{"address": concat(".", [type, "x"]), "type": type, "change": {"actions": ["create"], "after": after}}]}

test_secret_version_resource_denied if {
	count(secrets.deny) == 1 with input as res("aws_secretsmanager_secret_version", {"secret_string": "anything"})
}

test_access_key_pattern_denied if {
	count(secrets.deny) == 1 with input as res("aws_instance", {"user_data": "export AWS_ACCESS_KEY_ID=AKIAABCDEFGHIJKLMNOP"})
}

test_nested_private_key_denied if {
	count(secrets.deny) == 1 with input as res("aws_instance", {"metadata": {"k": "-----BEGIN RSA PRIVATE KEY-----"}})
}

test_clean_resource_ok if {
	count(secrets.deny) == 0 with input as res("aws_instance", {"ami": "ami-0123456789abcdef0", "tags": {"a": "b"}})
}
```

- [ ] **Step 6: Instance allow-list policy + test**

`policy/terraform/instances.rego`:
```rego
package terraform.instances

import rego.v1

import data.terraform.helpers

allowed := {
	"dev": {"Standard_B2s", "Standard_B2ms", "t3.micro", "t3.small"},
	"prod": {"Standard_D2s_v5", "Standard_D4s_v5", "t3.medium", "m6i.large"},
}

size(r) := r.change.after.size if r.type == "azurerm_linux_virtual_machine"

size(r) := r.change.after.instance_type if r.type == "aws_instance"

deny contains msg if {
	some r in helpers.planned
	s := size(r)
	not s in allowed[helpers.environment]
	msg := sprintf("%s size %q is not in the %s allow-list %v", [r.address, s, helpers.environment, sort(allowed[helpers.environment])])
}
```

`policy/terraform/instances_test.rego`:
```rego
package terraform.instances_test

import rego.v1

import data.terraform.instances

plan(env, type, attr, val) := {
	"variables": {"environment": {"value": env}},
	"resource_changes": [{"address": concat(".", [type, "x"]), "type": type, "change": {"actions": ["create"], "after": {attr: val}}}],
}

test_dev_small_ok if {
	count(instances.deny) == 0 with input as plan("dev", "aws_instance", "instance_type", "t3.small")
}

test_dev_large_denied if {
	count(instances.deny) == 1 with input as plan("dev", "aws_instance", "instance_type", "m6i.large")
}

test_prod_burstable_denied if {
	count(instances.deny) == 1 with input as plan("prod", "azurerm_linux_virtual_machine", "size", "Standard_B2s")
}

test_prod_d_series_ok if {
	count(instances.deny) == 0 with input as plan("prod", "azurerm_linux_virtual_machine", "size", "Standard_D2s_v5")
}
```

- [ ] **Step 7: Prod protection policy + test**

`policy/terraform/protection.rego`:
```rego
package terraform.protection

import rego.v1

import data.terraform.helpers

# Stateful resources that must never be destroyed by an automated prod plan.
stateful := {"aws_kms_key", "aws_secretsmanager_secret", "azurerm_resource_group_template_deployment", "azurerm_resource_group"}

deny contains msg if {
	helpers.is_prod
	some r in helpers.destroyed
	r.type in stateful
	msg := sprintf("prod plan would destroy stateful resource %s; requires a manual break-glass apply", [r.address])
}

deny contains msg if {
	some r in helpers.planned
	r.type == "azurerm_resource_group_template_deployment"
	r.change.after.deployment_mode != "Incremental"
	msg := sprintf("%s must use Incremental mode (Complete deletes unmanaged resources)", [r.address])
}

deny contains msg if {
	helpers.is_prod
	some r in helpers.planned
	r.type == "aws_secretsmanager_secret"
	r.change.after.recovery_window_in_days < 30
	msg := sprintf("%s recovery window must be >= 30 days in prod", [r.address])
}

deny contains msg if {
	helpers.is_prod
	some r in helpers.planned
	r.type == "aws_kms_key"
	r.change.after.deletion_window_in_days < 30
	msg := sprintf("%s deletion window must be >= 30 days in prod", [r.address])
}
```

`policy/terraform/protection_test.rego`:
```rego
package terraform.protection_test

import rego.v1

import data.terraform.protection

plan(env, changes) := {"variables": {"environment": {"value": env}}, "resource_changes": changes}

kms_delete := [{"address": "aws_kms_key.x", "type": "aws_kms_key", "change": {"actions": ["delete"], "before": {}}}]

test_prod_kms_destroy_denied if {
	count(protection.deny) == 1 with input as plan("prod", kms_delete)
}

test_dev_kms_destroy_ok if {
	count(protection.deny) == 0 with input as plan("dev", kms_delete)
}

test_complete_mode_denied if {
	count(protection.deny) == 1 with input as plan("dev", [{"address": "azurerm_resource_group_template_deployment.x", "type": "azurerm_resource_group_template_deployment", "change": {"actions": ["create"], "after": {"deployment_mode": "Complete"}}}])
}

test_prod_short_recovery_denied if {
	count(protection.deny) == 1 with input as plan("prod", [{"address": "aws_secretsmanager_secret.x", "type": "aws_secretsmanager_secret", "change": {"actions": ["create"], "after": {"recovery_window_in_days": 7}}}])
}
```

- [ ] **Step 8: Fix Makefile target and run unit tests**

In `Makefile`, change `policy-test` to:
```makefile
policy-test:
	conftest verify -p policy/terraform
	conftest fmt --check policy/terraform
```
Run: `conftest fmt policy/terraform && make policy-test`
Expected: `27 tests, 27 passed, 0 warnings, 0 failures`.

- [ ] **Step 9: Evaluate against the real plans from Task 14**

Run (with the dummy credential env vars from Task 14 step 5 still exported):
```bash
.venv/bin/platformctl plan aws dev
.venv/bin/platformctl plan azure dev
```
Expected: both print `Policy: PASS`. If a policy fails, the module is wrong, not the policy — fix the module (that is the point of the gate).

- [ ] **Step 10: `policy/README.md`**

```markdown
# Policy as code

OPA/Rego policies evaluated with [Conftest](https://www.conftest.dev/) against `terraform show -json` output.
`platformctl plan <cloud> <env>` runs them automatically; CI fails the PR on any `deny`.

| Namespace | What it enforces |
|---|---|
| `terraform.ingress` | Only 443 may be open to the internet (Azure NSG rules, AWS SG rules, inline SG blocks) |
| `terraform.encryption` | VM encryption at host, encrypted root volumes, CMK on secrets and log groups, KMS rotation |
| `terraform.tags` | `project`, `environment`, `owner`, `cost-center` on every taggable resource |
| `terraform.secrets` | No secret-value resources in IaC; no credential-shaped strings in any attribute |
| `terraform.instances` | Instance size allow-list per environment |
| `terraform.protection` | Prod never destroys stateful resources; ARM deployments are Incremental; ≥30-day recovery windows |

## Running

    make policy-test                                        # unit tests (conftest verify)
    conftest test .platformctl/plans/aws-dev.json -p policy/terraform --all-namespaces

## Writing a policy

1. Add `policy/terraform/<name>.rego` in package `terraform.<name>` using `import data.terraform.helpers`.
2. Add `<name>_test.rego` with at least one passing and one failing case.
3. Plan JSON quirks: unknown values live in `change.after_unknown`, not `change.after` — use `helpers.missing(r, attr)`.
```

- [ ] **Step 11: Commit**

```bash
git add policy Makefile
git commit -m "feat(policy): OPA policies for ingress, encryption, tags, secrets, sizing and prod protection

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>"
```

---

## Phase 4 — Ansible

### Task 16: `harden` role (CIS-inspired)

**Files:**
- Create: `ansible/ansible.cfg`, `ansible/requirements.yml`, `ansible/.ansible-lint`
- Create: `ansible/roles/harden/{meta/main.yml,defaults/main.yml,tasks/main.yml,tasks/{packages,ssh,sysctl,auditd,fail2ban,updates}.yml,handlers/main.yml,templates/{sshd_hardening.conf.j2,99-hardening.conf.j2,jail.local.j2,audit.rules.j2,issue.net.j2}}`

**Interfaces:**
- Produces: role `harden` with variables `harden_ssh_allowed_users` (default `["platform"]`), `harden_in_container` (auto-detected fact), `harden_auto_updates` (default true)

- [ ] **Step 1: Ansible config, collections, lint profile**

`ansible/ansible.cfg`:
```ini
[defaults]
inventory = inventory
roles_path = roles
host_key_checking = True
retry_files_enabled = False
interpreter_python = auto_silent
stdout_callback = yaml

[ssh_connection]
pipelining = True
```

`ansible/requirements.yml`:
```yaml
---
collections:
  - name: ansible.posix
    version: ">=1.5.0"
  - name: community.general
    version: ">=9.0.0"
```

`ansible/.ansible-lint`:
```yaml
---
profile: production
exclude_paths:
  - inventory/
  - .cache/
```

- [ ] **Step 2: Role metadata and defaults**

`ansible/roles/harden/meta/main.yml`:
```yaml
---
galaxy_info:
  author: platform-team
  description: CIS-inspired hardening for Ubuntu 22.04 application hosts
  license: MIT
  min_ansible_version: "2.15"
  platforms:
    - name: Ubuntu
      versions: [jammy]
dependencies: []
```

`ansible/roles/harden/defaults/main.yml`:
```yaml
---
harden_ssh_allowed_users:
  - platform
harden_ssh_port: 22
harden_auto_updates: true
harden_fail2ban_bantime: 1h
harden_fail2ban_maxretry: 5
harden_remove_packages:
  - telnet
  - rsh-client
  - talk
  - xinetd
harden_install_packages:
  - auditd
  - fail2ban
  - unattended-upgrades
  - ufw
  - chrony
```

- [ ] **Step 3: Tasks**

`ansible/roles/harden/tasks/main.yml`:
```yaml
---
- name: Detect container runtime (skip kernel/audit tasks inside Molecule containers)
  ansible.builtin.set_fact:
    harden_in_container: "{{ ansible_facts.virtualization_type in ['docker', 'container', 'containerd', 'podman'] }}"

- name: Packages
  ansible.builtin.include_tasks: packages.yml

- name: Login banner (before SSH so sshd -t can see the Banner file)
  ansible.builtin.template:
    src: issue.net.j2
    dest: /etc/issue.net
    owner: root
    group: root
    mode: "0644"

- name: SSH
  ansible.builtin.include_tasks: ssh.yml

- name: Kernel parameters
  ansible.builtin.include_tasks: sysctl.yml
  when: not harden_in_container

- name: Auditd
  ansible.builtin.include_tasks: auditd.yml
  when: not harden_in_container

- name: Fail2ban
  ansible.builtin.include_tasks: fail2ban.yml

- name: Automatic updates
  ansible.builtin.include_tasks: updates.yml
  when: harden_auto_updates
```

`ansible/roles/harden/tasks/packages.yml`:
```yaml
---
- name: Remove insecure legacy packages
  ansible.builtin.apt:
    name: "{{ harden_remove_packages }}"
    state: absent
    purge: true

- name: Install hardening packages
  ansible.builtin.apt:
    name: "{{ harden_install_packages }}"
    state: present
    update_cache: true
    cache_valid_time: 3600

- name: Set restrictive default umask
  ansible.builtin.lineinfile:
    path: /etc/login.defs
    regexp: '^UMASK\s'
    line: "UMASK 027"
```

`ansible/roles/harden/tasks/ssh.yml`:
```yaml
---
- name: Install SSH hardening drop-in
  ansible.builtin.template:
    src: sshd_hardening.conf.j2
    dest: /etc/ssh/sshd_config.d/00-hardening.conf
    owner: root
    group: root
    mode: "0600"
    validate: /usr/sbin/sshd -t -f %s
  notify: Restart sshd

- name: Ensure sshd is enabled
  ansible.builtin.service:
    name: ssh
    enabled: true
```

`ansible/roles/harden/tasks/sysctl.yml`:
```yaml
---
- name: Install kernel hardening parameters
  ansible.builtin.template:
    src: 99-hardening.conf.j2
    dest: /etc/sysctl.d/99-hardening.conf
    owner: root
    group: root
    mode: "0644"
  notify: Reload sysctl
```

`ansible/roles/harden/tasks/auditd.yml`:
```yaml
---
- name: Install audit rules
  ansible.builtin.template:
    src: audit.rules.j2
    dest: /etc/audit/rules.d/hardening.rules
    owner: root
    group: root
    mode: "0640"
  notify: Restart auditd

- name: Ensure auditd is running
  ansible.builtin.service:
    name: auditd
    state: started
    enabled: true
```

`ansible/roles/harden/tasks/fail2ban.yml`:
```yaml
---
- name: Configure fail2ban sshd jail
  ansible.builtin.template:
    src: jail.local.j2
    dest: /etc/fail2ban/jail.local
    owner: root
    group: root
    mode: "0644"
  notify: Restart fail2ban

- name: Ensure fail2ban is enabled
  ansible.builtin.service:
    name: fail2ban
    enabled: true
    state: "{{ 'started' if not harden_in_container else omit }}"
```

`ansible/roles/harden/tasks/updates.yml`:
```yaml
---
- name: Enable unattended security upgrades
  ansible.builtin.copy:
    dest: /etc/apt/apt.conf.d/20auto-upgrades
    owner: root
    group: root
    mode: "0644"
    content: |
      APT::Periodic::Update-Package-Lists "1";
      APT::Periodic::Unattended-Upgrade "1";
      APT::Periodic::AutocleanInterval "7";
```

`ansible/roles/harden/handlers/main.yml`:
```yaml
---
- name: Restart sshd
  ansible.builtin.service:
    name: ssh
    state: restarted
  when: not harden_in_container

- name: Reload sysctl
  ansible.builtin.command: sysctl --system
  changed_when: true

- name: Restart auditd
  ansible.builtin.service:
    name: auditd
    state: restarted

- name: Restart fail2ban
  ansible.builtin.service:
    name: fail2ban
    state: restarted
  when: not harden_in_container
```

- [ ] **Step 4: Templates**

`ansible/roles/harden/templates/sshd_hardening.conf.j2`:
```
# Managed by Ansible (roles/harden). Overrides /etc/ssh/sshd_config.
Port {{ harden_ssh_port }}
Protocol 2
PermitRootLogin no
PasswordAuthentication no
PubkeyAuthentication yes
ChallengeResponseAuthentication no
KbdInteractiveAuthentication no
PermitEmptyPasswords no
X11Forwarding no
AllowAgentForwarding no
AllowTcpForwarding no
MaxAuthTries 3
MaxSessions 4
LoginGraceTime 30
ClientAliveInterval 300
ClientAliveCountMax 2
LogLevel VERBOSE
Banner /etc/issue.net
AllowUsers {{ harden_ssh_allowed_users | join(' ') }}
KexAlgorithms curve25519-sha256,curve25519-sha256@libssh.org,diffie-hellman-group16-sha512,diffie-hellman-group18-sha512
Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr
MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com
```

`ansible/roles/harden/templates/99-hardening.conf.j2`:
```
# Managed by Ansible (roles/harden)
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.all.log_martians = 1
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.tcp_syncookies = 1
net.ipv6.conf.all.accept_redirects = 0
net.ipv6.conf.all.accept_ra = 0
kernel.randomize_va_space = 2
kernel.kptr_restrict = 2
kernel.dmesg_restrict = 1
kernel.yama.ptrace_scope = 1
fs.protected_hardlinks = 1
fs.protected_symlinks = 1
fs.suid_dumpable = 0
```

`ansible/roles/harden/templates/jail.local.j2`:
```
[DEFAULT]
bantime  = {{ harden_fail2ban_bantime }}
findtime = 10m
maxretry = {{ harden_fail2ban_maxretry }}
backend  = systemd

[sshd]
enabled = true
port    = {{ harden_ssh_port }}
```

`ansible/roles/harden/templates/audit.rules.j2`:
```
## Managed by Ansible (roles/harden)
-D
-b 8192
-f 1
-w /etc/passwd -p wa -k identity
-w /etc/group -p wa -k identity
-w /etc/shadow -p wa -k identity
-w /etc/sudoers -p wa -k scope
-w /etc/sudoers.d/ -p wa -k scope
-w /etc/ssh/sshd_config -p wa -k sshd
-w /etc/ssh/sshd_config.d/ -p wa -k sshd
-w /var/log/auth.log -p wa -k logins
-w /etc/secure-api/ -p wa -k app-secrets
-a always,exit -F arch=b64 -S execve -F euid=0 -k root-commands
-e 2
```

`ansible/roles/harden/templates/issue.net.j2`:
```
Authorised access only. Activity on this system is logged and audited.
```

- [ ] **Step 5: Lint**

Run: `make ansible-lint`
Expected: `Passed: 0 failure(s), 0 warning(s)`. Fix anything the production profile flags (typically `name` casing or FQCN).

- [ ] **Step 6: Commit**

```bash
git add ansible
git commit -m "feat(ansible): CIS-inspired harden role

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>"
```

### Task 17: `app_deploy` role, site playbook, Molecule scenario

**Files:**
- Create: `ansible/roles/app_deploy/{meta/main.yml,defaults/main.yml,tasks/main.yml,handlers/main.yml,templates/{secure-api.service.j2,fetch-secret.sh.j2,nginx-secure-api.conf.j2}}`
- Create: `ansible/playbooks/site.yml`, `ansible/molecule/default/{molecule.yml,converge.yml,verify.yml}`

**Interfaces:**
- Consumes inventory vars from Task 9: `cloud` (`azure|aws|local`), `environment`, `secret_store_id`, `identity_id`
- Produces: systemd unit `secure-api.service` listening on 127.0.0.1:8000; nginx on 443 proxying to it; `/etc/secure-api/env` populated at each service start by `/usr/local/sbin/fetch-secret.sh`

- [ ] **Step 1: Role metadata + defaults**

`ansible/roles/app_deploy/meta/main.yml`:
```yaml
---
galaxy_info:
  author: platform-team
  description: Deploys the secure-api FastAPI service under hardened systemd behind nginx TLS
  license: MIT
  min_ansible_version: "2.15"
  platforms:
    - name: Ubuntu
      versions: [jammy]
dependencies: []
```

`ansible/roles/app_deploy/defaults/main.yml`:
```yaml
---
app_deploy_user: secure-api
app_deploy_dir: /opt/secure-api
app_deploy_source: "{{ playbook_dir }}/../../app"
app_deploy_port: 8000
app_deploy_domain: ""           # set to enable ACME (certbot); empty = self-signed cert
app_deploy_acme_email: ""
app_deploy_secret_name: app     # Key Vault secret name / Secrets Manager secret id suffix
cloud: local                    # azure | aws | local (overridden by generated inventory)
environment: dev
secret_store_id: ""
identity_id: ""
```

- [ ] **Step 2: Tasks**

`ansible/roles/app_deploy/tasks/main.yml`:
```yaml
---
- name: Detect container runtime
  ansible.builtin.set_fact:
    app_deploy_in_container: "{{ ansible_facts.virtualization_type in ['docker', 'container', 'containerd', 'podman'] }}"

- name: Install runtime packages
  ansible.builtin.apt:
    name:
      - python3
      - python3-venv
      - nginx
      - curl
      - jq
      - "{{ 'awscli' if cloud == 'aws' else 'ca-certificates' }}"
    state: present
    update_cache: true
    cache_valid_time: 3600

- name: Create service user
  ansible.builtin.user:
    name: "{{ app_deploy_user }}"
    system: true
    shell: /usr/sbin/nologin
    home: "{{ app_deploy_dir }}"
    create_home: false

- name: Create directories
  ansible.builtin.file:
    path: "{{ item.path }}"
    state: directory
    owner: "{{ item.owner }}"
    group: "{{ item.owner }}"
    mode: "{{ item.mode }}"
  loop:
    - { path: "{{ app_deploy_dir }}", owner: root, mode: "0755" }
    - { path: "{{ app_deploy_dir }}/src", owner: root, mode: "0755" }
    - { path: /etc/secure-api, owner: root, mode: "0750" }
    - { path: /etc/nginx/tls, owner: root, mode: "0750" }

- name: Copy application source
  ansible.builtin.copy:
    src: "{{ app_deploy_source }}/"
    dest: "{{ app_deploy_dir }}/src/"
    owner: root
    group: root
    mode: "0644"
    directory_mode: "0755"
  notify: Restart secure-api

- name: Create virtualenv and install the app
  ansible.builtin.pip:
    name: "{{ app_deploy_dir }}/src"
    virtualenv: "{{ app_deploy_dir }}/venv"
    virtualenv_command: python3 -m venv
  notify: Restart secure-api

- name: Install secret fetcher
  ansible.builtin.template:
    src: fetch-secret.sh.j2
    dest: /usr/local/sbin/fetch-secret.sh
    owner: root
    group: root
    mode: "0750"

- name: Seed a local development secret when no cloud store is configured
  ansible.builtin.copy:
    dest: /etc/secure-api/env
    owner: root
    group: "{{ app_deploy_user }}"
    mode: "0640"
    content: "APP_SECRET=local-dev-only-not-a-real-secret\nAPP_ENV={{ environment }}\n"
  when: cloud == 'local'

- name: Install systemd unit
  ansible.builtin.template:
    src: secure-api.service.j2
    dest: /etc/systemd/system/secure-api.service
    owner: root
    group: root
    mode: "0644"
  notify:
    - Reload systemd
    - Restart secure-api

- name: Generate a self-signed certificate when no domain is configured
  ansible.builtin.command:
    cmd: >
      openssl req -x509 -newkey rsa:2048 -nodes -days 365
      -subj "/CN={{ ansible_facts.fqdn | default('secure-api.local') }}"
      -keyout /etc/nginx/tls/server.key -out /etc/nginx/tls/server.crt
    creates: /etc/nginx/tls/server.crt
  when: app_deploy_domain | length == 0

- name: Obtain an ACME certificate with certbot
  when: app_deploy_domain | length > 0 and not app_deploy_in_container
  block:
    - name: Install certbot
      ansible.builtin.apt:
        name: [certbot, python3-certbot-nginx]
        state: present
    - name: Request certificate
      ansible.builtin.command:
        cmd: certbot certonly --nginx --non-interactive --agree-tos -m {{ app_deploy_acme_email }} -d {{ app_deploy_domain }}
        creates: "/etc/letsencrypt/live/{{ app_deploy_domain }}/fullchain.pem"
    - name: Enable renewal timer
      ansible.builtin.systemd:
        name: certbot.timer
        enabled: true
        state: started

- name: Install nginx site
  ansible.builtin.template:
    src: nginx-secure-api.conf.j2
    dest: /etc/nginx/sites-available/secure-api.conf
    owner: root
    group: root
    mode: "0644"
  notify: Reload nginx

- name: Enable nginx site and disable default
  ansible.builtin.file:
    src: "{{ item.src | default(omit) }}"
    path: "{{ item.path }}"
    state: "{{ item.state }}"
  loop:
    - { path: /etc/nginx/sites-enabled/default, state: absent }
    - { src: /etc/nginx/sites-available/secure-api.conf, path: /etc/nginx/sites-enabled/secure-api.conf, state: link }
  notify: Reload nginx

- name: Enable and start services
  ansible.builtin.systemd:
    name: "{{ item }}"
    enabled: true
    state: started
    daemon_reload: true
  loop:
    - secure-api
    - nginx
```

`ansible/roles/app_deploy/handlers/main.yml`:
```yaml
---
- name: Reload systemd
  ansible.builtin.systemd:
    daemon_reload: true

- name: Restart secure-api
  ansible.builtin.systemd:
    name: secure-api
    state: restarted

- name: Reload nginx
  ansible.builtin.service:
    name: nginx
    state: reloaded
```

- [ ] **Step 3: Templates**

`ansible/roles/app_deploy/templates/secure-api.service.j2`:
```
[Unit]
Description=secure-api FastAPI service
After=network-online.target
Wants=network-online.target

[Service]
User={{ app_deploy_user }}
Group={{ app_deploy_user }}
WorkingDirectory={{ app_deploy_dir }}
{% if cloud != 'local' %}
ExecStartPre=+/usr/local/sbin/fetch-secret.sh
{% endif %}
EnvironmentFile=/etc/secure-api/env
ExecStart={{ app_deploy_dir }}/venv/bin/uvicorn secure_api.main:app --host 127.0.0.1 --port {{ app_deploy_port }}
Restart=on-failure
RestartSec=5

# Hardening
NoNewPrivileges=yes
PrivateTmp=yes
PrivateDevices=yes
ProtectSystem=strict
ProtectHome=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX
RestrictNamespaces=yes
RestrictRealtime=yes
LockPersonality=yes
MemoryDenyWriteExecute=yes
SystemCallArchitectures=native
SystemCallFilter=@system-service
CapabilityBoundingSet=
AmbientCapabilities=
UMask=0077

[Install]
WantedBy=multi-user.target
```

`ansible/roles/app_deploy/templates/fetch-secret.sh.j2`:
```bash
#!/usr/bin/env bash
# Managed by Ansible (roles/app_deploy). Runs as root before the service starts and
# writes /etc/secure-api/env from the cloud secret store using the VM's own identity.
# No credentials are stored on disk; the token comes from the instance metadata service.
set -euo pipefail
umask 077
OUT=/etc/secure-api/env
TMP="$(mktemp)"
trap 'rm -f "$TMP"' EXIT

{% if cloud == 'azure' %}
VAULT_URI="{{ secret_store_id | regex_replace('^.*/vaults/([^/]+)$', 'https://\\1.vault.azure.net') }}"
TOKEN="$(curl -sf -H 'Metadata: true' \
  'http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https%3A%2F%2Fvault.azure.net' \
  | jq -r .access_token)"
SECRET="$(curl -sf -H "Authorization: Bearer ${TOKEN}" \
  "${VAULT_URI}/secrets/{{ app_deploy_secret_name }}?api-version=7.4" | jq -r .value)"
{% elif cloud == 'aws' %}
SECRET="$(aws secretsmanager get-secret-value --secret-id '{{ secret_store_id }}' --query SecretString --output text)"
{% else %}
SECRET="local-dev-only-not-a-real-secret"
{% endif %}

printf 'APP_SECRET=%s\nAPP_ENV=%s\n' "${SECRET}" '{{ environment }}' > "$TMP"
chown root:{{ app_deploy_user }} "$TMP"
chmod 0640 "$TMP"
mv "$TMP" "$OUT"
trap - EXIT
```

`ansible/roles/app_deploy/templates/nginx-secure-api.conf.j2`:
```
# Managed by Ansible (roles/app_deploy)
server {
    listen 80 default_server;
    return 301 https://$host$request_uri;
}

server {
    listen 443 ssl http2 default_server;
    server_name {{ app_deploy_domain if app_deploy_domain else '_' }};

{% if app_deploy_domain %}
    ssl_certificate     /etc/letsencrypt/live/{{ app_deploy_domain }}/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/{{ app_deploy_domain }}/privkey.pem;
{% else %}
    ssl_certificate     /etc/nginx/tls/server.crt;
    ssl_certificate_key /etc/nginx/tls/server.key;
{% endif %}
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305;
    ssl_prefer_server_ciphers off;
    ssl_session_timeout 1d;
    ssl_session_tickets off;

    add_header Strict-Transport-Security "max-age=63072000; includeSubDomains" always;
    add_header X-Content-Type-Options nosniff always;
    add_header X-Frame-Options DENY always;
    add_header Referrer-Policy no-referrer always;
    server_tokens off;

    location / {
        proxy_pass         http://127.0.0.1:{{ app_deploy_port }};
        proxy_set_header   Host $host;
        proxy_set_header   X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header   X-Forwarded-Proto https;
        proxy_read_timeout 30s;
    }
}
```

- [ ] **Step 4: Site playbook**

`ansible/playbooks/site.yml`:
```yaml
---
- name: Harden and deploy the secure-api hosts
  hosts: api
  become: true
  gather_facts: true
  roles:
    - role: harden
    - role: app_deploy
```

- [ ] **Step 5: Molecule scenario**

`ansible/molecule/default/molecule.yml`:
```yaml
---
dependency:
  name: galaxy
  options:
    requirements-file: requirements.yml
driver:
  name: docker
platforms:
  - name: secure-api-jammy
    image: geerlingguy/docker-ubuntu2204-ansible:latest
    pre_build_image: true
    privileged: true
    cgroupns_mode: host
    volumes:
      - /sys/fs/cgroup:/sys/fs/cgroup:rw
    command: /lib/systemd/systemd
provisioner:
  name: ansible
  config_options:
    defaults:
      roles_path: ../../roles
  inventory:
    host_vars:
      secure-api-jammy:
        cloud: local
        environment: dev
        app_deploy_source: "{{ lookup('env', 'MOLECULE_PROJECT_DIRECTORY') }}/../app"
verifier:
  name: ansible
```

`ansible/molecule/default/converge.yml`:
```yaml
---
- name: Converge
  hosts: all
  become: true
  roles:
    - role: harden
    - role: app_deploy
```

`ansible/molecule/default/verify.yml`:
```yaml
---
- name: Verify
  hosts: all
  become: true
  gather_facts: false
  tasks:
    - name: Read sshd hardening drop-in
      ansible.builtin.slurp:
        src: /etc/ssh/sshd_config.d/00-hardening.conf
      register: sshd_conf

    - name: Assert SSH hardening
      ansible.builtin.assert:
        that:
          - "'PermitRootLogin no' in (sshd_conf.content | b64decode)"
          - "'PasswordAuthentication no' in (sshd_conf.content | b64decode)"
          - "'AllowUsers platform' in (sshd_conf.content | b64decode)"

    - name: Assert unattended upgrades configured
      ansible.builtin.stat:
        path: /etc/apt/apt.conf.d/20auto-upgrades
      register: upgrades
      failed_when: not upgrades.stat.exists

    - name: Assert legacy packages absent
      ansible.builtin.command: dpkg -s telnet
      register: telnet
      changed_when: false
      failed_when: telnet.rc == 0

    - name: Assert service unit is hardened
      ansible.builtin.slurp:
        src: /etc/systemd/system/secure-api.service
      register: unit
    - name: Check unit directives
      ansible.builtin.assert:
        that:
          - "'ProtectSystem=strict' in (unit.content | b64decode)"
          - "'NoNewPrivileges=yes' in (unit.content | b64decode)"
          - "'CapabilityBoundingSet=' in (unit.content | b64decode)"

    - name: Assert secret file permissions
      ansible.builtin.stat:
        path: /etc/secure-api/env
      register: envfile
    - name: Check secret file mode
      ansible.builtin.assert:
        that:
          - envfile.stat.mode == '0640'
          - envfile.stat.pw_name == 'root'

    - name: Wait for the app to answer
      ansible.builtin.uri:
        url: http://127.0.0.1:8000/healthz
        return_content: true
      register: health
      retries: 10
      delay: 3
      until: health.status == 200

    - name: Assert health payload
      ansible.builtin.assert:
        that: health.json.status == 'ok'

    - name: Assert nginx serves TLS
      ansible.builtin.uri:
        url: https://127.0.0.1/healthz
        validate_certs: false
        return_content: true
      register: tls
      failed_when: tls.status != 200
```

- [ ] **Step 6: Lint and (in CI only) Molecule**

Run: `make ansible-lint` — Expected: pass.
Run: `make molecule` — Expected locally: `SKIP: molecule (docker not available)`. In CI (Task 19) this must fully pass; the executor of Task 19 iterates on this scenario until it does. Molecule cannot run before Task 18 exists because `app_deploy` installs `app/`.

- [ ] **Step 7: Commit**

```bash
git add ansible
git commit -m "feat(ansible): app_deploy role with hardened systemd, nginx TLS, identity-based secret fetch, and molecule scenario

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>"
```

---

## Phase 5 — Application

### Task 18: FastAPI service, tests, distroless Dockerfile

**Files:**
- Create: `app/src/secure_api/{settings,main}.py`, `app/tests/test_api.py`, `app/Dockerfile`, `app/.dockerignore`, `app/README.md`

**Interfaces:**
- Produces: `GET /healthz` → `{"status":"ok"}`; `GET /api/v1/status` → `{"version","environment","secret_configured","secret_fingerprint"}`; env vars `APP_SECRET` (required), `APP_ENV` (default `dev`)

- [ ] **Step 1: Write failing tests**

`app/tests/test_api.py`:
```python
import pytest
from fastapi.testclient import TestClient


@pytest.fixture
def client(monkeypatch: pytest.MonkeyPatch) -> TestClient:
    monkeypatch.setenv("APP_SECRET", "test-secret-value")
    monkeypatch.setenv("APP_ENV", "test")
    from secure_api.main import create_app

    return TestClient(create_app())


def test_healthz(client: TestClient) -> None:
    r = client.get("/healthz")
    assert r.status_code == 200 and r.json() == {"status": "ok"}


def test_status_never_leaks_secret(client: TestClient) -> None:
    r = client.get("/api/v1/status")
    body = r.json()
    assert r.status_code == 200
    assert body["environment"] == "test" and body["secret_configured"] is True
    assert len(body["secret_fingerprint"]) == 12
    assert "test-secret-value" not in r.text


def test_missing_secret_fails_fast(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("APP_SECRET", raising=False)
    from secure_api.main import create_app

    with pytest.raises(Exception, match="APP_SECRET"):
        create_app()


def test_security_headers(client: TestClient) -> None:
    r = client.get("/healthz")
    assert r.headers["x-content-type-options"] == "nosniff"
    assert r.headers["cache-control"] == "no-store"
```

- [ ] **Step 2: Run to verify failure** — `.venv/bin/pytest app/tests -q` — Expected: ImportError.

- [ ] **Step 3: Implement**

`app/src/secure_api/settings.py`:
```python
"""Runtime settings. APP_SECRET is injected by fetch-secret.sh (VM) or the container runtime."""

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="APP_")

    secret: str = Field(min_length=8, description="Runtime secret from Key Vault / Secrets Manager")
    env: str = "dev"
```

`app/src/secure_api/main.py`:
```python
"""Minimal FastAPI service. The interesting part is what it does NOT do: log or return the secret."""

import hashlib
from collections.abc import Awaitable, Callable

from fastapi import FastAPI, Request, Response
from pydantic import ValidationError

from secure_api import __version__
from secure_api.settings import Settings


def create_app(settings: Settings | None = None) -> FastAPI:
    try:
        cfg = settings or Settings()
    except ValidationError as exc:
        raise RuntimeError("APP_SECRET is required (min 8 chars) and APP_ENV is optional") from exc
    app = FastAPI(title="secure-api", version=__version__, docs_url=None, redoc_url=None, openapi_url=None)

    @app.middleware("http")
    async def security_headers(request: Request, call_next: Callable[[Request], Awaitable[Response]]) -> Response:
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Cache-Control"] = "no-store"
        return response

    @app.get("/healthz")
    async def healthz() -> dict[str, str]:
        return {"status": "ok"}

    @app.get("/api/v1/status")
    async def status() -> dict[str, str | bool]:
        fingerprint = hashlib.sha256(cfg.secret.encode()).hexdigest()[:12]
        return {
            "version": __version__,
            "environment": cfg.env,
            "secret_configured": True,
            "secret_fingerprint": fingerprint,
        }

    return app


def _module_app() -> FastAPI | None:
    """uvicorn imports `secure_api.main:app`; tests call create_app() directly."""
    import os

    return create_app() if os.environ.get("APP_SECRET") else None


app = _module_app()
```

`app/Dockerfile`:
```dockerfile
# syntax=docker/dockerfile:1.7
# Stage 1: install into an isolated prefix. Python 3.11 matches the distroless runtime below.
FROM python:3.11-slim@sha256:REPLACE_ME_PYTHON_DIGEST AS build
WORKDIR /build
COPY pyproject.toml ./
COPY src ./src
RUN pip install --no-cache-dir --upgrade pip \
 && pip install --no-cache-dir --prefix=/install .

# Stage 2: runtime — distroless, non-root, no shell, no package manager, no pip
FROM gcr.io/distroless/python3-debian12:nonroot@sha256:REPLACE_ME_DISTROLESS_DIGEST
WORKDIR /app
COPY --from=build /install/lib/python3.11/site-packages /app/site-packages
ENV PYTHONPATH=/app/site-packages PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
USER nonroot:nonroot
EXPOSE 8000
ENTRYPOINT ["python3", "-m", "uvicorn", "secure_api.main:app", "--host", "0.0.0.0", "--port", "8000"]
```

`app/.dockerignore`:
```
tests/
__pycache__/
*.pyc
.pytest_cache/
```

- [ ] **Step 4: Pin base-image digests without Docker**

Run this script to resolve the digests and substitute them into the Dockerfile:
```bash
PY_TOKEN=$(curl -s "https://auth.docker.io/token?service=registry.docker.io&scope=repository:library/python:pull" | jq -r .token)
PY_DIGEST=$(curl -sI -H "Authorization: Bearer $PY_TOKEN" -H "Accept: application/vnd.oci.image.index.v1+json, application/vnd.docker.distribution.manifest.list.v2+json" https://registry-1.docker.io/v2/library/python/manifests/3.11-slim | grep -i docker-content-digest | awk '{print $2}' | tr -d '\r')
DL_DIGEST=$(curl -sI -H "Accept: application/vnd.oci.image.index.v1+json, application/vnd.docker.distribution.manifest.list.v2+json" https://gcr.io/v2/distroless/python3-debian12/manifests/nonroot | grep -i docker-content-digest | awk '{print $2}' | tr -d '\r')
echo "python: $PY_DIGEST"; echo "distroless: $DL_DIGEST"
sed -i '' "s|sha256:REPLACE_ME_PYTHON_DIGEST|$PY_DIGEST|; s|sha256:REPLACE_ME_DISTROLESS_DIGEST|$DL_DIGEST|" app/Dockerfile
grep -c REPLACE_ME app/Dockerfile   # must print 0
```
Expected: two `sha256:` digests printed, Dockerfile contains none of the placeholders.

- [ ] **Step 5: `app/README.md`**

```markdown
# secure-api

A deliberately small FastAPI service whose job is to prove the platform's secret-handling path end to end.

| Endpoint | Purpose |
|---|---|
| `GET /healthz` | Liveness for nginx, Molecule and load balancers |
| `GET /api/v1/status` | Reports version, environment and a SHA-256 *fingerprint* of the runtime secret — never the secret |

## Configuration

| Env var | Required | Source in production |
|---|---|---|
| `APP_SECRET` | yes (≥ 8 chars) | `/etc/secure-api/env`, written at service start by `fetch-secret.sh` from Key Vault / Secrets Manager using the VM identity |
| `APP_ENV` | no (default `dev`) | same file |

The app refuses to start without `APP_SECRET` — fail-fast beats a half-configured service.

## Run locally

    make bootstrap
    APP_SECRET=local-dev-only .venv/bin/uvicorn secure_api.main:app --app-dir app/src --reload

## Tests

    .venv/bin/pytest app/tests

## Container

Multi-stage build to `gcr.io/distroless/python3-debian12:nonroot` (no shell, no package manager, non-root),
both base images pinned by digest. Built, scanned with Trivy, signed with cosign and shipped with an SPDX SBOM by `release.yml`.
```

- [ ] **Step 6: Run tests + lint** — `.venv/bin/pytest app/tests -q && make lint` — Expected: 4 passed; mypy clean.

- [ ] **Step 7: Commit**

```bash
git add app
git commit -m "feat(app): fastapi service with fail-fast secret handling and distroless image

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>"
```

---

## Phase 6 — CI/CD

### Task 19: Action pinning tool, reusable workflows, `ci.yml`, Dependabot

**Files:**
- Create: `platformctl/platformctl/actions.py`, `platformctl/tests/test_actions.py`
- Modify: `platformctl/platformctl/cli.py`
- Create: `.github/dependabot.yml`, `.github/workflows/_reusable-python.yml`, `.github/workflows/_reusable-terraform.yml`, `.github/workflows/_reusable-security.yml`, `.github/workflows/ci.yml`

**Interfaces:**
- Produces:
  - `actions.find_unpinned(text: str) -> list[actions.Use]` where `Use(repo: str, path: str, ref: str, line: int)`
  - `actions.resolve_sha(repo: str, ref: str) -> str` — via `gh api` (annotated tags dereferenced)
  - `actions.pin_text(text: str, resolver: Callable[[str, str], str]) -> str` — rewrites `uses: owner/repo[/path]@ref` → `@<sha> # ref`; skips `slsa-framework/slsa-github-generator` (must stay tag-pinned) and local `./` actions
  - CLI: `platformctl actions pin [--check] [--dir .github/workflows]` — `--check` exits 1 if anything is unpinned
  - Workflows callable as `uses: ./.github/workflows/_reusable-*.yml`

- [ ] **Step 1: Write failing tests for `actions`**

`platformctl/tests/test_actions.py`:
```python
from pathlib import Path

import pytest
from typer.testing import CliRunner

from platformctl import actions, config
from platformctl.cli import app
from tests.conftest import RunRecorder

WORKFLOW = """
jobs:
  a:
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5.2.0
        with: {python-version: "3.12"}
      - uses: docker/build-push-action@0123456789abcdef0123456789abcdef01234567 # v6.0.0
      - uses: ./.github/actions/local
      - uses: slsa-framework/slsa-github-generator/.github/workflows/generator_container_slsa3.yml@v2.0.0
      - uses: aquasecurity/trivy-action/sub/path@0.24.0
"""


def test_find_unpinned() -> None:
    found = actions.find_unpinned(WORKFLOW)
    assert [(u.repo, u.path, u.ref) for u in found] == [
        ("actions/checkout", "", "v4"),
        ("actions/setup-python", "", "v5.2.0"),
        ("aquasecurity/trivy-action", "/sub/path", "0.24.0"),
    ]


def test_pin_text_rewrites_with_comment() -> None:
    out = actions.pin_text(WORKFLOW, resolver=lambda repo, ref: "a" * 40)
    assert "uses: actions/checkout@" + "a" * 40 + " # v4" in out
    assert "uses: aquasecurity/trivy-action/sub/path@" + "a" * 40 + " # 0.24.0" in out
    assert "docker/build-push-action@0123456789abcdef0123456789abcdef01234567 # v6.0.0" in out
    assert "slsa-github-generator/.github/workflows/generator_container_slsa3.yml@v2.0.0" in out


def test_resolve_sha_dereferences_annotated_tag(fake_run: RunRecorder) -> None:
    fake_run.add(("gh", "api", "repos/actions/checkout/git/ref/tags/v4"), stdout='{"object": {"type": "tag", "sha": "' + "t" * 40 + '"}}')
    fake_run.add(("gh", "api", "repos/actions/checkout/git/tags/" + "t" * 40), stdout='{"object": {"sha": "' + "c" * 40 + '"}}')
    assert actions.resolve_sha("actions/checkout", "v4") == "c" * 40


def test_resolve_sha_lightweight_tag(fake_run: RunRecorder) -> None:
    fake_run.add(("gh", "api", "repos/o/r/git/ref/tags/v1"), stdout='{"object": {"type": "commit", "sha": "' + "d" * 40 + '"}}')
    assert actions.resolve_sha("o/r", "v1") == "d" * 40


def test_resolve_sha_falls_back_to_branch(fake_run: RunRecorder) -> None:
    fake_run.add(("gh", "api", "repos/o/r/git/ref/tags/main"), returncode=1, stderr="Not Found")
    fake_run.add(("gh", "api", "repos/o/r/git/ref/heads/main"), stdout='{"object": {"type": "commit", "sha": "' + "e" * 40 + '"}}')
    assert actions.resolve_sha("o/r", "main") == "e" * 40


def test_cli_check_mode(settings: config.Settings, monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.chdir(settings.repo_root)
    wf = settings.repo_root / ".github/workflows"
    wf.mkdir(parents=True)
    (wf / "ci.yml").write_text(WORKFLOW)
    r = CliRunner().invoke(app, ["actions", "pin", "--check"])
    assert r.exit_code == 1 and "actions/checkout@v4" in r.output
    monkeypatch.setattr(actions, "resolve_sha", lambda repo, ref: "f" * 40)
    r = CliRunner().invoke(app, ["actions", "pin"])
    assert r.exit_code == 0
    assert CliRunner().invoke(app, ["actions", "pin", "--check"]).exit_code == 0
```

- [ ] **Step 2: Run to verify failure** — Expected: ImportError.

- [ ] **Step 3: Implement `actions.py`**

```python
"""Pin GitHub Actions `uses:` references to commit SHAs (supply-chain hygiene)."""

import json
import re
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

from platformctl import proc

_USES = re.compile(r"^(?P<indent>\s*-?\s*uses:\s*)(?P<repo>[\w.-]+/[\w.-]+)(?P<path>(?:/[\w.-]+)*)@(?P<ref>[^\s#]+)(?P<rest>.*)$")
_SHA = re.compile(r"^[0-9a-f]{40}$")
SKIP_REPOS = {"slsa-framework/slsa-github-generator"}  # SLSA verifies the generator by tag; SHA pins are rejected


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
    assert isinstance(obj, dict)
    if obj["type"] == "tag":  # annotated tag → dereference to the commit
        tag = _gh(f"repos/{repo}/git/tags/{obj['sha']}")
        if tag is None:
            raise LookupError(f"{repo}@{ref}: cannot dereference annotated tag")
        inner = tag["object"]
        assert isinstance(inner, dict)
        return str(inner["sha"])
    return str(obj["sha"])


def pin_text(text: str, resolver: Callable[[str, str], str]) -> str:
    lines = text.splitlines(keepends=True)
    for use in find_unpinned(text):
        idx = use.line - 1
        m = _USES.match(lines[idx].rstrip("\n"))
        assert m is not None
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
```

- [ ] **Step 4: Add `actions` sub-app to `cli.py`**

```python
actions_app = typer.Typer(help="GitHub Actions hygiene")
app.add_typer(actions_app, name="actions")


@actions_app.command("pin")
def actions_pin(
    ctx: typer.Context,
    check: Annotated[bool, typer.Option("--check", help="Only report unpinned references; exit 1 if any")] = False,
    directory: Annotated[Path, typer.Option("--dir")] = Path(".github/workflows"),
) -> None:
    """Pin every `uses:` reference to a commit SHA, keeping the tag as a comment."""
    settings = get_settings(ctx)
    wf_dir = settings.repo_root / directory
    if check:
        unpinned = [(p.name, u) for p in sorted(wf_dir.glob("*.yml")) for u in actions_mod.find_unpinned(p.read_text())]
        for name, u in unpinned:
            console.print(f"[red]unpinned[/] {name}:{u.line} {u.repo}{u.path}@{u.ref}")
        if unpinned:
            raise typer.Exit(code=1)
        console.print("[green]all actions pinned[/]")
        return
    for path in actions_mod.pin_directory(wf_dir, actions_mod.resolve_sha):
        console.print(f"pinned {path.relative_to(settings.repo_root)}")
```
Add `from platformctl import actions as actions_mod` to imports.

- [ ] **Step 5: Run tests + lint** — Expected: pass.

- [ ] **Step 6: Dependabot**

`.github/dependabot.yml`:
```yaml
version: 2
updates:
  - package-ecosystem: github-actions
    directory: /
    schedule: { interval: weekly }
  - package-ecosystem: pip
    directory: /platformctl
    schedule: { interval: weekly }
  - package-ecosystem: pip
    directory: /app
    schedule: { interval: weekly }
  - package-ecosystem: docker
    directory: /app
    schedule: { interval: weekly }
  - package-ecosystem: terraform
    directories:
      - /infra/terraform/modules/network/azure
      - /infra/terraform/modules/network/aws
      - /infra/terraform/modules/compute/azure
      - /infra/terraform/modules/compute/aws
      - /infra/terraform/modules/secrets/azure
      - /infra/terraform/modules/secrets/aws
    schedule: { interval: weekly }
```

- [ ] **Step 7: Reusable workflows (write with tags; Step 10 pins them)**

`.github/workflows/_reusable-python.yml`:
```yaml
name: _python
on:
  workflow_call:

permissions: {}

jobs:
  python:
    runs-on: ubuntu-latest
    permissions:
      contents: read
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: "3.12"
          cache: pip
      - run: pip install -e "./platformctl[dev]" -e "./app[dev]"
      - run: ruff check . && ruff format --check .
      - run: mypy
      - run: pytest --cov --cov-report=xml --cov-report=term
      - uses: actions/upload-artifact@v4
        with:
          name: coverage
          path: coverage.xml
```

`.github/workflows/_reusable-terraform.yml`:
```yaml
name: _terraform
on:
  workflow_call:
    inputs:
      cloud:
        required: true
        type: string
      environment:
        required: true
        type: string

permissions: {}

env:
  TERRAFORM_VERSION: "1.9.8"
  TERRAGRUNT_VERSION: "0.67.16"
  CONFTEST_VERSION: "0.56.0"
  # Dummy credentials: providers are configured to skip validation; plan makes no API calls.
  ARM_CLIENT_ID: 00000000-0000-0000-0000-000000000000
  ARM_CLIENT_SECRET: REPLACE_ME_DUMMY
  ARM_TENANT_ID: 00000000-0000-0000-0000-000000000000
  ARM_SUBSCRIPTION_ID: 00000000-0000-0000-0000-000000000000
  AWS_ACCESS_KEY_ID: REPLACE_ME_DUMMY
  AWS_SECRET_ACCESS_KEY: REPLACE_ME_DUMMY
  AWS_REGION: us-east-1
  TG_BACKEND: local

jobs:
  terraform:
    name: ${{ inputs.cloud }}/${{ inputs.environment }}
    runs-on: ubuntu-latest
    permissions:
      contents: read
    steps:
      - uses: actions/checkout@v4
      - uses: hashicorp/setup-terraform@v3
        with:
          terraform_version: ${{ env.TERRAFORM_VERSION }}
          terraform_wrapper: false
      - name: Install terragrunt and conftest
        run: |
          curl -fsSL -o /usr/local/bin/terragrunt "https://github.com/gruntwork-io/terragrunt/releases/download/v${TERRAGRUNT_VERSION}/terragrunt_linux_amd64"
          chmod +x /usr/local/bin/terragrunt
          curl -fsSL "https://github.com/open-policy-agent/conftest/releases/download/v${CONFTEST_VERSION}/conftest_${CONFTEST_VERSION}_Linux_x86_64.tar.gz" | tar -xz -C /usr/local/bin conftest
      - uses: actions/setup-python@v5
        with:
          python-version: "3.12"
      - run: pip install -e ./platformctl
      - run: terraform fmt -check -recursive infra/terraform
      - name: Validate modules and stacks
        run: |
          for d in infra/terraform/modules/*/* infra/terraform/stacks/*; do
            (cd "$d" && terraform init -backend=false -input=false >/dev/null && terraform validate) || exit 1
          done
      - name: Module unit tests
        run: |
          for d in infra/terraform/modules/*/${{ inputs.cloud }}; do
            (cd "$d" && terraform init -backend=false -input=false >/dev/null && terraform test) || exit 1
          done
      - name: Policy unit tests
        run: conftest verify -p policy/terraform
      - name: Plan + policy gate
        run: platformctl plan ${{ inputs.cloud }} ${{ inputs.environment }}
      - uses: actions/upload-artifact@v4
        if: always()
        with:
          name: plan-${{ inputs.cloud }}-${{ inputs.environment }}
          path: .platformctl/plans/${{ inputs.cloud }}-${{ inputs.environment }}.json
```

`.github/workflows/_reusable-security.yml`:
```yaml
name: _security
on:
  workflow_call:

permissions: {}

env:
  GITLEAKS_VERSION: "8.20.1"
  TFSEC_VERSION: "1.28.11"
  TRIVY_VERSION: "0.56.2"

jobs:
  scan:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      security-events: write
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0 # gitleaks scans history
      - uses: actions/setup-python@v5
        with:
          python-version: "3.12"
      - run: pip install -e ./platformctl checkov
      - name: Install scanners
        run: |
          curl -fsSL "https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS_VERSION}/gitleaks_${GITLEAKS_VERSION}_linux_x64.tar.gz" | tar -xz -C /usr/local/bin gitleaks
          curl -fsSL -o /usr/local/bin/tfsec "https://github.com/aquasecurity/tfsec/releases/download/v${TFSEC_VERSION}/tfsec-linux-amd64" && chmod +x /usr/local/bin/tfsec
          curl -fsSL "https://github.com/aquasecurity/trivy/releases/download/v${TRIVY_VERSION}/trivy_${TRIVY_VERSION}_Linux-64bit.tar.gz" | tar -xz -C /usr/local/bin trivy
      - name: Scan (checkov, tfsec, gitleaks, trivy) → SARIF
        run: platformctl scan --fail-on high --out results.sarif
      - uses: github/codeql-action/upload-sarif@v3
        if: always()
        with:
          sarif_file: results.sarif
          category: platformctl-scan
      - name: Verify all actions are SHA-pinned
        run: platformctl actions pin --check
```

- [ ] **Step 8: `ci.yml`**

```yaml
name: ci
on:
  pull_request:
  push:
    branches: [main]

permissions: {}

concurrency:
  group: ci-${{ github.ref }}
  cancel-in-progress: true

jobs:
  python:
    uses: ./.github/workflows/_reusable-python.yml

  terraform:
    strategy:
      fail-fast: false
      matrix:
        cloud: [azure, aws]
        environment: [dev, prod]
    uses: ./.github/workflows/_reusable-terraform.yml
    with:
      cloud: ${{ matrix.cloud }}
      environment: ${{ matrix.environment }}

  security:
    uses: ./.github/workflows/_reusable-security.yml

  arm:
    runs-on: ubuntu-latest
    permissions:
      contents: read
    steps:
      - uses: actions/checkout@v4
      - name: JSON syntax
        run: python3 -c "import json; json.load(open('infra/arm/keyvault.json')); json.load(open('infra/arm/keyvault.parameters.json'))"
      - name: arm-ttk
        shell: pwsh
        run: |
          git clone --depth 1 https://github.com/Azure/arm-ttk.git /tmp/arm-ttk
          Import-Module /tmp/arm-ttk/arm-ttk/arm-ttk.psd1
          $results = Test-AzTemplate -TemplatePath infra/arm -Skip 'apiVersions-Should-Be-Recent'
          $results | Format-Table -AutoSize
          if ($results | Where-Object { -not $_.Passed }) { exit 1 }

  ansible:
    runs-on: ubuntu-latest
    permissions:
      contents: read
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: "3.12"
      - run: pip install ansible ansible-lint "molecule>=6" "molecule-plugins[docker]"
      - run: ansible-galaxy collection install -r ansible/requirements.yml
      - run: cd ansible && ansible-lint
      - run: cd ansible && molecule test
        env:
          MOLECULE_PROJECT_DIRECTORY: ${{ github.workspace }}/ansible

  app:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      security-events: write
    steps:
      - uses: actions/checkout@v4
      - uses: docker/setup-buildx-action@v3
      - uses: docker/build-push-action@v6
        with:
          context: app
          load: true
          tags: secure-api:ci
          cache-from: type=gha
          cache-to: type=gha,mode=max
      - name: Smoke test container
        run: |
          docker run -d --rm --name api -e APP_SECRET=ci-only-secret -p 8000:8000 secure-api:ci
          for i in $(seq 1 15); do curl -fsS http://127.0.0.1:8000/healthz && break || sleep 1; done
          curl -fsS http://127.0.0.1:8000/api/v1/status | grep -q '"secret_configured":true'
          docker stop api
      - uses: aquasecurity/trivy-action@0.28.0
        with:
          image-ref: secure-api:ci
          format: sarif
          output: trivy-image.sarif
          severity: HIGH,CRITICAL
          exit-code: "1"
      - uses: github/codeql-action/upload-sarif@v3
        if: always()
        with:
          sarif_file: trivy-image.sarif
          category: trivy-image
```

- [ ] **Step 9: Push to GitHub and create the repository if needed**

```bash
gh auth status
gh repo view >/dev/null 2>&1 || gh repo create phil-DevSecOps-projects --public --source=. --remote=origin --push
git push -u origin main
```

- [ ] **Step 10: Pin every action to a SHA**

```bash
.venv/bin/platformctl actions pin
.venv/bin/platformctl actions pin --check
git diff --stat .github
```
Expected: every `uses:` now reads `owner/repo@<40-hex> # vX`; `--check` prints `all actions pinned`.

- [ ] **Step 11: Commit, push, watch CI, iterate until green**

```bash
git add .github platformctl
git commit -m "ci: reusable python/terraform/security workflows, SHA-pinned actions, dependabot

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>"
git push
gh run watch --exit-status
```
Expected: all jobs green. Likely first-run failures and their fixes:
- **Molecule**: a task fails inside the container → guard it with `when: not harden_in_container` / `app_deploy_in_container` and re-push. `sysctl`, `auditd` and `sshd restart` are already guarded.
- **Trivy image HIGH/CRITICAL in the base image**: re-run Task 18 Step 4 to bump digests; if the finding is in a distroless OS package with no fix, add a `.trivyignore` in `app/` with the CVE id and a one-line justification and pass `trivyignores: app/.trivyignore` to the action.
- **arm-ttk** test name failures: add the exact test name to the `-Skip` list only with a comment explaining why.
- **`platformctl scan --fail-on high`** finds a real issue: fix the IaC; suppressions go in `.checkov.yaml` / `#tfsec:ignore:<id>` with justification.

### Task 20: `release.yml` (sign, SBOM, SLSA) and `apply.yml` (manual, environment-gated)

**Files:**
- Create: `.github/workflows/release.yml`, `.github/workflows/apply.yml`
- Create: `.github/CODEOWNERS`

- [ ] **Step 1: `release.yml`**

```yaml
name: release
on:
  push:
    tags: ["v*.*.*"]

permissions: {}

env:
  IMAGE: ghcr.io/${{ github.repository }}/secure-api

jobs:
  build:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      packages: write
      id-token: write # keyless cosign
    outputs:
      digest: ${{ steps.build.outputs.digest }}
      image: ${{ env.IMAGE }}
    steps:
      - uses: actions/checkout@v4
      - uses: docker/setup-buildx-action@v3
      - uses: docker/login-action@v3
        with:
          registry: ghcr.io
          username: ${{ github.actor }}
          password: ${{ secrets.GITHUB_TOKEN }}
      - uses: docker/metadata-action@v5
        id: meta
        with:
          images: ${{ env.IMAGE }}
          tags: type=semver,pattern={{version}}
      - uses: docker/build-push-action@v6
        id: build
        with:
          context: app
          push: true
          tags: ${{ steps.meta.outputs.tags }}
          labels: ${{ steps.meta.outputs.labels }}
          provenance: false # SLSA provenance is produced by the dedicated job below
      - uses: sigstore/cosign-installer@v3
      - uses: anchore/sbom-action/download-syft@v0
      - uses: actions/setup-python@v5
        with:
          python-version: "3.12"
      - run: pip install -e ./platformctl
      - name: SBOM, sign, attest
        run: |
          REF="${IMAGE}@${{ steps.build.outputs.digest }}"
          platformctl sbom "$REF" --out sbom.spdx.json
          platformctl sign "$REF" --sbom sbom.spdx.json
          platformctl verify "$REF" --identity-regexp "^https://github.com/${{ github.repository }}/"
      - uses: actions/upload-artifact@v4
        with:
          name: sbom
          path: sbom.spdx.json

  provenance:
    needs: build
    permissions:
      actions: read
      id-token: write
      packages: write
    # SLSA generator must be referenced by tag; platformctl actions pin skips it on purpose.
    uses: slsa-framework/slsa-github-generator/.github/workflows/generator_container_slsa3.yml@v2.0.0
    with:
      image: ${{ needs.build.outputs.image }}
      digest: ${{ needs.build.outputs.digest }}
      registry-username: ${{ github.actor }}
    secrets:
      registry-password: ${{ secrets.GITHUB_TOKEN }}
```

- [ ] **Step 2: `apply.yml`**

```yaml
# Manual, environment-gated apply.
#
# THIS WORKFLOW DOES NOT RUN IN THIS REPOSITORY AS PUBLISHED. It needs:
#   1. A GitHub environment named `prod` (and/or `dev`) with required reviewers.
#   2. Azure: an app registration with a federated credential for this repo, and
#      environment secrets AZURE_CLIENT_ID, AZURE_TENANT_ID, AZURE_SUBSCRIPTION_ID.
#   3. AWS: an IAM role trusting token.actions.githubusercontent.com, secret AWS_ROLE_ARN.
#   4. Remote state: replace the `tfstate-placeholder` names in infra/terragrunt.hcl.
# See docs/runbooks/deploy.md. No long-lived cloud credentials are ever stored.
name: apply
on:
  workflow_dispatch:
    inputs:
      cloud:
        type: choice
        options: [azure, aws]
        required: true
      environment:
        type: choice
        options: [dev, prod]
        required: true

permissions: {}

jobs:
  apply:
    runs-on: ubuntu-latest
    environment: ${{ inputs.environment }}
    permissions:
      contents: read
      id-token: write
    env:
      TG_BACKEND: remote
      TERRAFORM_VERSION: "1.9.8"
      TERRAGRUNT_VERSION: "0.67.16"
    steps:
      - uses: actions/checkout@v4
      - uses: hashicorp/setup-terraform@v3
        with:
          terraform_version: ${{ env.TERRAFORM_VERSION }}
          terraform_wrapper: false
      - run: |
          curl -fsSL -o /usr/local/bin/terragrunt "https://github.com/gruntwork-io/terragrunt/releases/download/v${TERRAGRUNT_VERSION}/terragrunt_linux_amd64"
          chmod +x /usr/local/bin/terragrunt
      - uses: azure/login@v2
        if: inputs.cloud == 'azure'
        with:
          client-id: ${{ secrets.AZURE_CLIENT_ID }}
          tenant-id: ${{ secrets.AZURE_TENANT_ID }}
          subscription-id: ${{ secrets.AZURE_SUBSCRIPTION_ID }}
      - uses: aws-actions/configure-aws-credentials@v4
        if: inputs.cloud == 'aws'
        with:
          role-to-assume: ${{ secrets.AWS_ROLE_ARN }}
          aws-region: us-east-1
      - uses: actions/setup-python@v5
        with:
          python-version: "3.12"
      - run: pip install -e ./platformctl
      - name: Plan with policy gate
        run: platformctl plan ${{ inputs.cloud }} ${{ inputs.environment }}
        env:
          ARM_USE_OIDC: "true"
          ARM_CLIENT_ID: ${{ secrets.AZURE_CLIENT_ID }}
          ARM_TENANT_ID: ${{ secrets.AZURE_TENANT_ID }}
          ARM_SUBSCRIPTION_ID: ${{ secrets.AZURE_SUBSCRIPTION_ID }}
      - name: Apply
        run: cd infra/envs/${{ inputs.environment }}/${{ inputs.cloud }} && terragrunt apply -auto-approve -input=false
        env:
          ARM_USE_OIDC: "true"
          ARM_CLIENT_ID: ${{ secrets.AZURE_CLIENT_ID }}
          ARM_TENANT_ID: ${{ secrets.AZURE_TENANT_ID }}
          ARM_SUBSCRIPTION_ID: ${{ secrets.AZURE_SUBSCRIPTION_ID }}
      - name: Generate inventory for Ansible
        run: platformctl ansible inventory ${{ inputs.cloud }} ${{ inputs.environment }}
      - uses: actions/upload-artifact@v4
        with:
          name: inventory-${{ inputs.cloud }}-${{ inputs.environment }}
          path: ansible/inventory/
```

- [ ] **Step 3: CODEOWNERS**

`.github/CODEOWNERS`:
```
# Changes to policy, workflows and secrets handling need a platform-team review.
/policy/                @phillipj
/.github/workflows/     @phillipj
/infra/terraform/modules/secrets/ @phillipj
```
(Replace `@phillipj` with the GitHub handle from `gh api user --jq .login`.)

- [ ] **Step 4: Pin, verify, commit, push**

```bash
.venv/bin/platformctl actions pin && .venv/bin/platformctl actions pin --check
git add .github
git commit -m "ci: keyless-signed release with SBOM and SLSA provenance; manual OIDC apply workflow

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>"
git push && gh run watch --exit-status
```
Expected: `ci` green (release/apply do not trigger on push to main).

- [ ] **Step 5: Cut `v0.1.0` to exercise the release pipeline**

```bash
git tag -a v0.1.0 -m "v0.1.0: first signed release" && git push origin v0.1.0
gh run watch --exit-status
```
Expected: `release` workflow green; `ghcr.io/<owner>/phil-devsecops-projects/secure-api:0.1.0` exists with `.sig` and `.att` tags and SLSA provenance. If the GHCR package is private by default, make it public in the package settings so `cosign verify` works anonymously.

---

## Phase 7 — Documentation

### Task 21: Architecture, threat model, ADRs, runbooks, directory READMEs

**Files:**
- Create: `docs/architecture.md`, `docs/threat-model.md`, `docs/adr/0001-multi-cloud-module-contract.md` … `docs/adr/0006-arm-wrapped-in-terraform.md`, `docs/runbooks/{deploy,rotate-secrets,respond-to-drift,revoke-signing}.md`, `infra/README.md`, `ansible/README.md`, `platformctl/README.md`

- [ ] **Step 1: `docs/architecture.md`**

````markdown
# Architecture

## Infrastructure topology

```mermaid
flowchart LR
  subgraph Azure["Azure (stack: infra/terraform/stacks/azure)"]
    direction TB
    ARG[Resource group] --> AVN[VNet 10.10.0.0/16]
    AVN --> ASN[Subnet app 10.10.1.0/24]
    ASN --> ANSG[NSG: 443 from Internet, 22 from admin CIDRs, deny all]
    ASN --> AVM[Ubuntu 22.04 VM\nencryption at host, user-assigned identity]
    AKV[Key Vault via ARM template\nRBAC, purge protection, no public network] -. Key Vault Secrets User .-> AVM
  end
  subgraph AWS["AWS (stack: infra/terraform/stacks/aws)"]
    direction TB
    VPC[VPC 10.20.0.0/16] --> SN[Public subnet 10.20.1.0/24]
    SN --> SG[SG: 443 from 0.0.0.0/0, 22 per admin CIDR]
    SN --> EC2[Ubuntu 22.04 EC2\nIMDSv2, encrypted gp3, instance profile]
    VPC --> FL[Flow logs → CloudWatch, KMS]
    SM[Secrets Manager + CMK] -. GetSecretValue .-> EC2
  end
  Admin((Admin CIDR)) -- 22 --> AVM & EC2
  Internet((Internet)) -- 443 --> AVM & EC2
```

Both stacks expose the same outputs (`vm_public_ip`, `vm_private_ip`, `secret_store_id`, `secret_store_uri`, `identity_id`), which is what lets `platformctl ansible inventory` and the Ansible roles be cloud-agnostic.

## Pipeline

```mermaid
flowchart LR
  PR[Pull request] --> L[ruff · mypy · pytest ≥85%]
  PR --> T[terraform fmt · validate · terraform test\n×{azure,aws}×{dev,prod}]
  T --> P[terragrunt plan → JSON\nplatformctl plan]
  P --> O{OPA / Conftest\n6 policy namespaces}
  PR --> S[platformctl scan\ncheckov · tfsec · gitleaks · trivy → SARIF]
  S --> ST[(GitHub Security tab)]
  PR --> A[ansible-lint · Molecule converge+verify]
  PR --> R[arm-ttk]
  PR --> C[docker build · smoke · trivy image]
  O -->|deny| X[❌ PR blocked]
  Tag[git tag v*] --> B[build → GHCR]
  B --> G[syft SBOM · cosign keyless sign+attest · verify]
  B --> V[SLSA L3 provenance]
  M[workflow_dispatch] --> E{environment: prod\nrequired reviewer}
  E --> OIDC[OIDC federation\nno stored cloud secrets] --> AP[terragrunt apply\nTG_BACKEND=remote] --> INV[platformctl ansible inventory]
```

## Identity and secret flow

```mermaid
sequenceDiagram
  participant TF as Terraform
  participant KV as Key Vault / Secrets Manager
  participant OP as Operator (platformctl)
  participant VM as VM (managed identity)
  participant SVC as secure-api.service
  TF->>KV: create store + grant VM identity read-only
  Note over TF,KV: no secret values in Terraform or state
  OP->>KV: platformctl secrets rotate app --execute
  KV-->>OP: new version id (value never printed)
  SVC->>VM: ExecStartPre fetch-secret.sh (root)
  VM->>KV: IMDS token → GET secret (Azure) / aws secretsmanager (AWS)
  KV-->>VM: value
  VM->>SVC: /etc/secure-api/env (0640 root:secure-api)
  SVC->>SVC: start as non-root, ProtectSystem=strict, secret only in memory
```

## Component responsibilities

| Component | Owns | Does not own |
|---|---|---|
| Terraform modules | resources, security defaults, variable validation | environment values, state config |
| Terragrunt | env/cloud layering, backend and provider generation | resource definitions |
| ARM template | Key Vault definition | who can read it (Terraform role assignment) |
| OPA policies | what a plan may contain | how resources are built |
| Ansible | OS hardening, service deployment, secret fetch script | provisioning |
| platformctl | orchestration, parsing, reporting, gating | any cloud resource definition |
| GitHub Actions | ordering, isolation, permissions, artifacts | logic (delegates to platformctl / make) |
````

- [ ] **Step 2: `docs/threat-model.md`**

```markdown
# Threat model (STRIDE)

Scope: the deployed VM + app, the secret path, and the delivery pipeline. Assets: the runtime secret, the signing identity, Terraform state, admin SSH access.

| Threat | Category | Mitigation | Where |
|---|---|---|---|
| Attacker brute-forces SSH | Spoofing | Key-only auth, `AllowUsers`, fail2ban, SSH restricted to admin CIDRs, catch-all NSG deny | `ansible/roles/harden`, `modules/network/*` |
| Stolen CI token used to reach cloud | Spoofing | No long-lived cloud credentials; `apply.yml` uses OIDC federation scoped to environment + required reviewer | `.github/workflows/apply.yml` |
| Malicious PR alters a workflow to exfiltrate secrets | Tampering | `permissions: {}` at workflow level, minimal per-job; CODEOWNERS on workflows; actions SHA-pinned | `.github/` |
| Compromised third-party action | Tampering | SHA pinning enforced by `platformctl actions pin --check`; Dependabot updates | `platformctl/actions.py` |
| Image substituted between build and deploy | Tampering | cosign keyless signature + SLSA L3 provenance; `platformctl verify` before use | `release.yml`, `supplychain.py` |
| Secret leaks via logs or API | Information disclosure | App returns only a SHA-256 fingerprint; `Cache-Control: no-store`; secret file 0640; `platformctl secrets` never prints values | `app/`, `app_deploy` |
| Secret committed to git | Information disclosure | gitleaks pre-commit + CI on full history; OPA `terraform.secrets` denies secret-value resources and credential-shaped strings | `.gitleaks.toml`, `policy/` |
| Terraform state exposed | Information disclosure | Remote backends encrypted (S3 SSE, Azure Storage); no secret values in state by design | `infra/terragrunt.hcl` |
| Operator disputes a prod change | Repudiation | auditd rules on identity, sudoers and `/etc/secure-api`; GitHub environment approvals; signed provenance | `harden/templates/audit.rules.j2` |
| App compromised via HTTP | Elevation of privilege | Non-root service user, `NoNewPrivileges`, empty capability set, `ProtectSystem=strict`, syscall filter; nginx TLS 1.2+ only | `secure-api.service.j2`, nginx template |
| IMDS credential theft from a compromised container/process | Elevation of privilege | IMDSv2 required, hop limit 1 (AWS); user-assigned identity with read-only secret role (Azure) | `modules/compute/*`, `modules/secrets/*` |
| Automated prod plan destroys stateful resources | Denial of service | OPA `terraform.protection` denies destroy of KMS/secret/vault/RG in prod; 30-day recovery windows | `policy/terraform/protection.rego` |
| Oversized instance / cost blow-up | Denial of service (budget) | Per-environment instance allow-list | `policy/terraform/instances.rego` |

## Accepted risks

- Single VM per cloud, no HA — this is a reference platform, not a production SLA.
- Self-signed TLS when no domain is configured; ACME path exists and is used when `app_deploy_domain` is set.
- Public IP on the VM. A bastion/private endpoint variant is listed under future work in the README.
```

- [ ] **Step 3: ADRs**

`docs/adr/0001-multi-cloud-module-contract.md`:
```markdown
# ADR-0001: One variable/output contract across Azure and AWS modules

**Status:** Accepted · **Date:** 2026-09-21

## Context
The platform targets two clouds. Cloud-specific modules are unavoidable, but every consumer above them (stacks, Terragrunt inputs, `platformctl`, Ansible inventory) should not care which cloud it is talking to.

## Decision
Each module family (`network`, `compute`, `secrets`) has an `azure/` and an `aws/` implementation sharing the same core inputs (`project`, `environment`, `region`, `tags`, plus family-specific ones like `cidr`, `allowed_ssh_cidrs`, `instance_size`, `ssh_public_key`). Cloud-specific extras (`resource_group_name`, `ami_id`) are allowed only where there is no sensible abstraction. Both stacks emit identical outputs: `vm_public_ip`, `vm_private_ip`, `secret_store_id`, `secret_store_uri`, `identity_id`.

## Consequences
- `platformctl ansible inventory` and the Ansible roles are cloud-agnostic; the only cloud switch is the `cloud` inventory var used by `fetch-secret.sh`.
- Adding a third cloud means implementing three modules against a known contract, not redesigning callers.
- Some Azure/AWS features without an equivalent (e.g. Azure `encryption_at_host`) stay inside the module as hard defaults rather than surfacing as inputs.
```

`docs/adr/0002-terragrunt-over-workspaces.md`:
```markdown
# ADR-0002: Terragrunt for environment layering instead of Terraform workspaces

**Status:** Accepted · **Date:** 2026-09-21

## Context
Two clouds × two environments need distinct state, distinct provider config and distinct inputs. Workspaces share one backend and one provider block and make "which env am I in" implicit.

## Decision
Use Terragrunt. The unit path `infra/envs/<env>/<cloud>` encodes environment and cloud; the root `terragrunt.hcl` derives both from `path_relative_to_include()`, generates the provider block, selects the backend from `TG_BACKEND` (`local` for CI/dev, `remote` for apply), and points `terraform.source` at the right stack.

## Consequences
- Units are four tiny files of inputs; no duplicated backend/provider boilerplate.
- CI can plan with `TG_BACKEND=local` and dummy credentials without touching any real backend.
- One more tool to install; pinned in workflows and `brew install terragrunt` locally.
```

`docs/adr/0003-opa-conftest-over-sentinel.md`:
```markdown
# ADR-0003: OPA/Rego via Conftest for policy-as-code

**Status:** Accepted · **Date:** 2026-09-21

## Context
Policies must run in GitHub Actions and locally with no vendor account, be unit-testable, and evaluate the *plan* (what will change), not just static HCL.

## Decision
Write policies in Rego under `policy/terraform`, evaluate them with Conftest against `terraform show -json` output, and unit-test them with `conftest verify`. Checkov runs alongside for breadth of built-in rules; OPA holds the organisation-specific rules.

## Alternatives
- **HashiCorp Sentinel** — requires Terraform Cloud/Enterprise; not runnable locally or in plain GitHub Actions.
- **Checkov custom policies only** — YAML/Python rules are less expressive for cross-resource logic (e.g. "prod may not destroy stateful resources").

## Consequences
- Plan JSON quirks (`after_unknown`) must be handled; `helpers.missing()` centralises that.
- Policies are versioned with the code they govern and reviewed via CODEOWNERS.
```

`docs/adr/0004-validate-only-ci.md`:
```markdown
# ADR-0004: CI validates and plans; it never applies

**Status:** Accepted · **Date:** 2026-09-21

## Context
This repository must be fully verifiable by anyone who clones it, with zero cloud accounts and zero cost, while still demonstrating a production-shaped delivery path.

## Decision
`ci.yml` runs formatting, validation, `terraform test` with mock providers, a real `terragrunt plan` with dummy credentials (providers configured to skip validation; stacks contain no data sources that would call an API), OPA policy, scanners, Molecule and container tests. Applying is a separate `workflow_dispatch` workflow bound to a GitHub environment with required reviewers and OIDC federation, documented as requiring account setup.

## Consequences
- The green badge proves correctness and policy compliance, not that the resources exist.
- `apply.yml` cannot be exercised in this repo; the runbook explains the one-time setup.
- No cloud secret of any kind is ever stored in GitHub.
```

`docs/adr/0005-keyless-cosign.md`:
```markdown
# ADR-0005: Keyless container signing with cosign and GitHub OIDC

**Status:** Accepted · **Date:** 2026-09-21

## Context
Signing with a long-lived private key means storing that key in CI and rotating it. The repo already forbids stored cloud secrets; a signing key would be the one exception.

## Decision
`release.yml` signs with `cosign sign --yes` using the workflow's OIDC identity (Sigstore Fulcio + Rekor). The SPDX SBOM is attached as an attestation and SLSA L3 provenance is generated by the official `slsa-github-generator` container workflow. `platformctl verify` checks `--certificate-identity-regexp ^https://github.com/<owner>/<repo>/` and the GitHub issuer.

## Consequences
- No signing secrets to store or rotate; revocation is "stop trusting that workflow identity" (see runbook `revoke-signing.md`).
- Verification depends on the public Sigstore infrastructure.
- The SLSA generator must be referenced by tag, so `platformctl actions pin` skips it explicitly.
```

`docs/adr/0006-arm-wrapped-in-terraform.md`:
```markdown
# ADR-0006: Key Vault defined as an ARM template, deployed through Terraform

**Status:** Accepted · **Date:** 2026-09-21

## Context
ARM templates are a first-class skill on this platform, but an ARM file that nothing deploys is a demo, not infrastructure. Key Vault is the resource where ARM's native support (RBAC mode, purge protection, network ACLs, diagnostic settings) is most complete.

## Decision
`infra/arm/keyvault.json` is the source of truth for the vault. The Terraform `secrets/azure` module deploys it with `azurerm_resource_group_template_deployment` in `Incremental` mode, decodes its outputs, and layers the RBAC role assignment on top. The template is validated by `arm-ttk` in CI and can also be deployed standalone with `az deployment group create`.

## Consequences
- One resource, one definition, two valid entry points (Terraform or az CLI).
- OPA denies `Complete` deployment mode because it would delete unmanaged resources in the resource group.
- Template outputs are the contract between ARM and Terraform; renaming them is a breaking change.
```

- [ ] **Step 4: Runbooks**

`docs/runbooks/deploy.md`:
```markdown
# Runbook: first deployment

Prerequisites (one-time, per cloud):

## Azure
1. `az ad app create --display-name sap-github-oidc`, then add a federated credential for `repo:<owner>/<repo>:environment:prod`.
2. Grant the app **Contributor** on the subscription (or a dedicated resource group) and **Key Vault Data Access Administrator** so it can create the role assignment.
3. Create the state storage account and replace `tfstateplaceholder` / `rg-tfstate-placeholder` in `infra/terragrunt.hcl`.
4. Add environment secrets `AZURE_CLIENT_ID`, `AZURE_TENANT_ID`, `AZURE_SUBSCRIPTION_ID` to the `prod` environment.

## AWS
1. Create the GitHub OIDC provider in IAM (`token.actions.githubusercontent.com`).
2. Create a role trusting `repo:<owner>/<repo>:environment:prod` with permissions for EC2, VPC, IAM (role/profile/policy), KMS, Secrets Manager, CloudWatch Logs, S3/DynamoDB for state.
3. Create the state bucket + lock table and replace `tfstate-placeholder` in `infra/terragrunt.hcl`.
4. Add `AWS_ROLE_ARN` to the `prod` environment.
5. Resolve the Ubuntu 22.04 AMI for the region and replace `ami-0123456789abcdef0` in `infra/envs/<env>/aws/terragrunt.hcl`:
   `aws ssm get-parameter --name /aws/service/canonical/ubuntu/server/22.04/stable/current/amd64/hvm/ebs-gp2/ami-id --query Parameter.Value --output text`

## Both
6. Set `PLATFORM_SSH_PUBLIC_KEY` as an environment variable/secret (your admin public key) and replace `203.0.113.0/24` with your admin egress CIDR.
7. Create the GitHub environment `prod` with at least one required reviewer.

## Deploy
1. Actions → **apply** → Run workflow → choose cloud and environment. Approve when prompted.
2. Download the `inventory-<cloud>-<env>` artifact into `ansible/inventory/`.
3. Seed the runtime secret: `platformctl --config platformctl.toml secrets rotate app --execute` with `adapter = "<cloud>"` in `platformctl.toml` (Azure: export `AZURE_KEY_VAULT_URL`).
4. `cd ansible && ansible-playbook -i inventory/<cloud>-<env>.yml playbooks/site.yml -e app_deploy_domain=<fqdn> -e app_deploy_acme_email=<email>`
5. `curl https://<fqdn>/api/v1/status` — expect `secret_configured: true`.
6. Record the baseline: `platformctl drift <cloud> <env> --accept`.
```

`docs/runbooks/rotate-secrets.md`:
```markdown
# Runbook: rotate the runtime secret

Rotation is dry-run by default and never prints values.

1. Preview: `platformctl secrets rotate app` → shows how many active versions would be deprecated.
2. Execute: `platformctl secrets rotate app --execute` → new version written, previous versions disabled/tagged `deprecated`.
3. Roll the service so it re-reads the store: `ansible -i inventory/<cloud>-<env>.yml api -b -m systemd -a "name=secure-api state=restarted"`.
   `ExecStartPre=fetch-secret.sh` fetches the current version on every start.
4. Verify: the `secret_fingerprint` in `GET /api/v1/status` changes.
5. Audit: `platformctl secrets list app` shows the version history.

Rollback: re-enable the previous version in the console and restart the service. Deprecated Azure versions stay recoverable (soft delete, 90 days); AWS keeps `AWSPREVIOUS` for 24h before purge.

Schedule: rotate every 90 days or immediately on suspected exposure. `platformctl certs check` covers certificates on the same cadence.
```

`docs/runbooks/respond-to-drift.md`:
```markdown
# Runbook: responding to drift

`platformctl drift <cloud> <env>` exits 2 when a plan would change anything relative to the accepted baseline and writes a markdown report with `--report drift.md`.

1. Read the report: which addresses are new since the last accepted plan?
2. Classify:
   - **Console change by a human** (tags, NSG rule added by hand): revert in the console or codify it in a PR. Never accept undocumented manual changes.
   - **Provider default change after upgrade**: review, then `platformctl drift <cloud> <env> --accept` after the PR merges.
   - **Security-relevant** (new ingress rule, encryption disabled): treat as an incident — check auditd/CloudTrail/Activity Log for who made the change, revert immediately via `apply`.
3. After remediation, re-run drift; it must exit 0. Then `--accept` to update the baseline.

Automate: schedule `platformctl drift` daily in a cron workflow once accounts exist; page on exit code 2.
```

`docs/runbooks/revoke-signing.md`:
```markdown
# Runbook: compromised signing identity

Signing is keyless; the "identity" is the `release.yml` workflow in this repository. A compromise means someone could run that workflow (stolen maintainer account, malicious merge).

1. Freeze: disable the `release` workflow in Actions and set branch protection to require reviews from a second maintainer.
2. Identify the window: Rekor holds an immutable log. Search `rekor-cli search --email <identity>` or via the Sigstore search UI for entries in the suspicious period.
3. Revoke trust: consumers must add the compromised time window to their verification, e.g. `cosign verify ... --certificate-identity-regexp ... ` plus an explicit denylist of digests published from this repo's `SECURITY.md`.
4. Rebuild: fix the cause, rotate the maintainer credentials, re-tag and re-release. New signatures come from the same identity but a later timestamp; the SLSA provenance records the exact commit.
5. Publish an advisory listing affected digests.
```

- [ ] **Step 5: Directory READMEs**

`infra/README.md`:
```markdown
# infra

| Path | Purpose |
|---|---|
| `terraform/modules/{network,compute,secrets}/{azure,aws}` | Reusable modules, one contract per family (ADR-0001), each with `tests/plan.tftest.hcl` |
| `terraform/stacks/{azure,aws}` | Composition roots wiring the three modules |
| `envs/<env>/<cloud>/terragrunt.hcl` | Per-environment inputs only |
| `terragrunt.hcl` | Derives env/cloud from the path, generates provider + backend (ADR-0002) |
| `arm/keyvault.json` | Key Vault ARM template deployed by `modules/secrets/azure` (ADR-0006) |

## Local commands

    make tf-fmt tf-validate tf-test      # no credentials needed
    platformctl plan aws dev             # real terragrunt plan with dummy creds + OPA gate
    TG_BACKEND=remote terragrunt plan    # only after docs/runbooks/deploy.md setup

Dummy credentials for plan-only runs are documented in `.github/workflows/_reusable-terraform.yml`.
```

`ansible/README.md`:
```markdown
# ansible

| Role | Purpose |
|---|---|
| `harden` | CIS-inspired: SSH drop-in, sysctl, auditd, fail2ban, unattended-upgrades, legacy package removal, banner |
| `app_deploy` | Service user, venv install of `app/`, hardened systemd unit, identity-based secret fetch, nginx TLS (ACME or self-signed) |

Inventory is generated, not hand-written: `platformctl ansible inventory <cloud> <env>` writes `inventory/<cloud>-<env>.yml` from Terraform outputs. The `cloud` var selects how `fetch-secret.sh` reaches the secret store (`azure` → IMDS + Key Vault REST, `aws` → `aws secretsmanager`, `local` → dev value for Molecule).

    make ansible-lint
    make molecule          # needs Docker; runs converge + verify on Ubuntu 22.04 with systemd
    ansible-playbook -i inventory/aws-dev.yml playbooks/site.yml
```

`platformctl/README.md`:
```markdown
# platformctl

Typed Python CLI that orchestrates the platform. Every external tool call goes through `proc.run()` (logged, timed, typed errors); every cloud call goes through a `CloudAdapter` (`fake` for tests/CI, `azure`, `aws`).

| Command | Does |
|---|---|
| `plan <cloud> <env> [--no-policy]` | terragrunt plan → JSON → change table → OPA/Conftest gate (exit 1 on deny) |
| `scan [--fail-on high] [--tool …] [--out results.sarif]` | checkov, tfsec, gitleaks, trivy → one SARIF; exit 1 above threshold |
| `drift <cloud> <env> [--accept] [--report f.md]` | plan vs accepted baseline; exit 2 on drift |
| `ansible inventory <cloud> <env>` | Terraform outputs → `ansible/inventory/<cloud>-<env>.yml` |
| `secrets rotate <name> [--execute]` · `secrets list <name>` | new version + deprecate old; dry-run default; values never printed |
| `certs check [--warn-days N] [--no-probe]` | store certificates + live TLS probes; exit 1 if expiring |
| `sbom` · `sign` · `verify` | syft SBOM, cosign keyless sign/attest, verify by OIDC identity |
| `actions pin [--check]` | SHA-pin GitHub Actions `uses:` references |

Config: `platformctl.toml` at the repo root (found by walking up from cwd).

    make test        # pytest + hypothesis, coverage ≥ 85%
    make lint        # ruff + mypy --strict
```

- [ ] **Step 6: Commit**

```bash
git add docs infra/README.md ansible/README.md platformctl/README.md
git commit -m "docs: architecture diagrams, STRIDE threat model, ADRs, runbooks and directory guides

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>"
```

### Task 22: Root README and final verification

**Files:**
- Create: `README.md`

- [ ] **Step 1: Resolve the GitHub owner for badges**

Run: `gh repo view --json nameWithOwner --jq .nameWithOwner` → use the result wherever `OWNER/REPO` appears below.

- [ ] **Step 2: Write `README.md`**

````markdown
# secure-api-platform

[![ci](https://github.com/OWNER/REPO/actions/workflows/ci.yml/badge.svg)](https://github.com/OWNER/REPO/actions/workflows/ci.yml)
[![release](https://github.com/OWNER/REPO/actions/workflows/release.yml/badge.svg)](https://github.com/OWNER/REPO/actions/workflows/release.yml)
![python](https://img.shields.io/badge/python-3.12-blue) ![terraform](https://img.shields.io/badge/terraform-%E2%89%A51.7-844fba) ![license](https://img.shields.io/badge/license-MIT-green)

A reference DevSecOps platform: a small FastAPI service deployed onto CIS-hardened VMs in **Azure and AWS** with Terraform/Terragrunt + an ARM template, configured by Ansible, orchestrated by a typed Python CLI (`platformctl`), and gated by OPA policy and security scanners in GitHub Actions. Releases are keyless-signed with an SBOM and SLSA provenance.

**Everything in CI runs with zero cloud credentials.** The pipeline proves the infrastructure is correct, policy-compliant, scanned and signed; applying is a separate, manually-triggered, reviewer-gated workflow that uses OIDC federation (no stored secrets) once accounts exist.

```mermaid
flowchart LR
  Dev[PR] --> CI[ci.yml]
  CI --> Py[platformctl tests]
  CI --> TF[terraform test · terragrunt plan]
  TF --> OPA{OPA gate}
  CI --> Sec[checkov · tfsec · gitleaks · trivy → SARIF]
  CI --> Ans[ansible-lint · Molecule]
  CI --> Img[docker build · trivy image]
  Tag[tag v*] --> Rel[GHCR · cosign · SBOM · SLSA]
  Manual[workflow_dispatch] --> Env{env: prod\nreviewer} --> OIDC --> Apply[terragrunt apply] --> Inv[ansible inventory] --> Play[site.yml: harden + app_deploy]
```

## Skills → where to look

| Skill | Evidence |
|---|---|
| Infrastructure as code | [`infra/terraform/modules`](infra/terraform/modules) — 3 module families × 2 clouds, variable validation, `terraform test` with mock providers |
| Terraform / Terragrunt | [`infra/terragrunt.hcl`](infra/terragrunt.hcl) derives env+cloud from path, generates provider and backend; [ADR-0002](docs/adr/0002-terragrunt-over-workspaces.md) |
| ARM templates | [`infra/arm/keyvault.json`](infra/arm/keyvault.json) deployed by [`modules/secrets/azure`](infra/terraform/modules/secrets/azure/main.tf); validated by arm-ttk in CI; [ADR-0006](docs/adr/0006-arm-wrapped-in-terraform.md) |
| Ansible | [`ansible/roles/harden`](ansible/roles/harden), [`ansible/roles/app_deploy`](ansible/roles/app_deploy), Molecule scenario with systemd container |
| Workflow orchestration | [`platformctl`](platformctl) — plan → policy → scan → drift → inventory → sign/verify, one typed CLI |
| Cloud-native automation | Dynamic inventory from Terraform outputs; VM identity fetches secrets at service start ([`fetch-secret.sh.j2`](ansible/roles/app_deploy/templates/fetch-secret.sh.j2)) — no credentials on disk |
| GitHub / GitHub Actions | [`.github/workflows`](.github/workflows) — reusable workflows, matrix plans, SHA-pinned actions (enforced by [`platformctl actions pin --check`](platformctl/platformctl/actions.py)), least-privilege `permissions`, SARIF to Security tab, Dependabot, CODEOWNERS |
| Advanced Python | [`platformctl/platformctl`](platformctl/platformctl) — typer + pydantic + structlog, adapter pattern, hypothesis property tests, `mypy --strict`, ≥ 85% coverage |
| Secure by design | [Threat model](docs/threat-model.md); hardened systemd unit; IMDSv2; encryption everywhere; fail-fast app |
| Policy as code | [`policy/terraform`](policy/terraform) — 6 OPA namespaces with unit tests, evaluated on real plan JSON; Checkov alongside |
| CI/CD with integrated security | [`ci.yml`](.github/workflows/ci.yml): fmt → validate → test → plan → OPA → scanners → Molecule → image scan, all blocking |
| Secrets management | Key Vault (RBAC, purge protection) and Secrets Manager (CMK); no secret values in IaC ([policy](policy/terraform/secrets.rego)); [`platformctl secrets rotate`](platformctl/platformctl/secrets.py); [runbook](docs/runbooks/rotate-secrets.md) |
| Certificate management | ACME via certbot with renewal timer, TLS 1.2+ nginx; [`platformctl certs check`](platformctl/platformctl/certs.py) |
| Supply chain | [`release.yml`](.github/workflows/release.yml): distroless digest-pinned image, syft SBOM, cosign keyless sign + attest, SLSA L3 provenance; [ADR-0005](docs/adr/0005-keyless-cosign.md) |

## Quickstart

```bash
git clone https://github.com/OWNER/REPO && cd REPO
make bootstrap          # venv, editable installs, pre-commit hooks
make ci                 # everything CI runs that doesn't need Docker (~3 min)
.venv/bin/platformctl --help
```

Requires: Python 3.12+, Terraform ≥ 1.7, terragrunt, conftest, checkov, gitleaks, tfsec, trivy (`brew install hashicorp/tap/terraform terragrunt conftest checkov gitleaks tfsec trivy`).

Try the gate on a real plan (no cloud account needed — providers skip credential validation):

```bash
export ARM_CLIENT_ID=00000000-0000-0000-0000-000000000000 ARM_CLIENT_SECRET=x ARM_TENANT_ID=00000000-0000-0000-0000-000000000000 ARM_SUBSCRIPTION_ID=00000000-0000-0000-0000-000000000000
export AWS_ACCESS_KEY_ID=x AWS_SECRET_ACCESS_KEY=x AWS_REGION=us-east-1
.venv/bin/platformctl plan aws dev
```

## Repository map

```
platformctl/   Python CLI (orchestration, parsing, gating)        docs/architecture.md   diagrams
infra/         Terraform modules, stacks, Terragrunt envs, ARM    docs/threat-model.md   STRIDE
ansible/       harden + app_deploy roles, Molecule                docs/adr/              decisions
policy/        OPA/Rego + tests                                   docs/runbooks/         operations
app/           FastAPI service + distroless Dockerfile            .github/workflows/     ci, release, apply
```

## What does *not* happen without cloud accounts

- `apply.yml` never runs here. [docs/runbooks/deploy.md](docs/runbooks/deploy.md) lists the one-time OIDC and state-backend setup.
- Placeholders that must be replaced before a real apply: `tfstate-placeholder*` (backends), `ami-0123456789abcdef0`, `203.0.113.0/24` (admin CIDR), `PLATFORM_SSH_PUBLIC_KEY`.
- The `azure` and `aws` adapters in `platformctl` are exercised only against live SDKs; CI uses the `fake` adapter.

## Future work

Bastion/private-endpoint variant with no public VM IP · multi-region · HashiCorp Vault as a third adapter · cost estimation (Infracost) in the plan gate · scheduled drift detection once accounts exist.

## License

MIT — see [LICENSE](LICENSE).
````

- [ ] **Step 3: Definition-of-done checks**

```bash
make ci
grep -rn "TODO\|TBD" --include='*.py' --include='*.tf' --include='*.yml' --include='*.yaml' --include='*.md' --include='*.rego' --include='*.json' . | grep -v docs/superpowers | grep -v .venv    # must be empty
for d in app infra ansible policy platformctl; do test -f $d/README.md || echo "missing $d/README.md"; done
ls docs/adr | wc -l      # 6
ls docs/runbooks | wc -l # 4
.venv/bin/platformctl actions pin --check
```
Expected: `CI (local subset) passed`; no TODO/TBD; all READMEs present; 6 ADRs; 4 runbooks; all pinned.

- [ ] **Step 4: Commit, push, confirm green**

```bash
git add README.md
git commit -m "docs: root README with skill-to-artifact map and quickstart

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>"
git push && gh run watch --exit-status && gh run list --limit 3
```
Expected: `ci` green on `main`. Open the repo in a browser and confirm the badges render and the Security tab shows the `platformctl-scan` and `trivy-image` categories.
