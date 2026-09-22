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
