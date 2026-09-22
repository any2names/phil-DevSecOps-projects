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
- Plan JSON quirks (`after_unknown`, explicit `null`) must be handled; `helpers.missing()` centralises that.
- Policies are versioned with the code they govern and reviewed via CODEOWNERS.
- The gate proved its worth immediately: the first prod plan surfaced a KMS key with no explicit deletion window.
