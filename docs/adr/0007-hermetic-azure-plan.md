# ADR-0007: Hermetic `terraform plan` for Azure via an az CLI shim

**Status:** Accepted · **Date:** 2026-09-21

## Context
The AWS provider can plan with dummy keys (`skip_credentials_validation` and friends). The azurerm provider cannot: at configure time it acquires a token and decodes its claims ("building account"), then lists resource providers. With no Azure account, `terragrunt plan azure …` fails before touching a single resource — which would have left the Azure half of the pipeline as validate-only.

## Decision
When `platformctl` detects no real credentials and `TG_BACKEND=local`, it injects a hermetic environment (`terraform.hermetic_env`):

1. `ARM_USE_CLI=true` with `scripts/az-shim/az` first on `PATH`. The shim answers `az version`, `az account show/list` and `az account get-access-token` with a self-minted, **unsigned** JWT. The provider only decodes claims locally; signature verification happens at the Azure API, which a create-only plan never calls.
2. `TC_TEST_VIA_VCR=1` — the provider's own hook for recorded (VCR) tests — skips the resource-provider listing.

The shim is a test double. It is never used when real credentials are present, and `apply.yml` sets `TG_BACKEND=remote` and OIDC variables, which disables it.

## Consequences
- Both clouds produce real plan JSON in CI, so OPA policies are evaluated on what Terraform would actually do, for all four cloud/env units.
- The approach depends on provider internals. If a future azurerm release validates tokens locally or removes `TC_TEST_VIA_VCR`, the Azure plan job must fall back to `terraform validate` + `terraform test` (mock providers), which already run. The threat model lists this as an accepted risk.
- Stacks must not use data sources that call the API; the module tests and the hermetic plan both enforce that indirectly.
