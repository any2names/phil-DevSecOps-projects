# ADR-0004: CI validates and plans; it never applies

**Status:** Accepted · **Date:** 2026-09-21

## Context
This repository must be fully verifiable by anyone who clones it, with zero cloud accounts and zero cost, while still demonstrating a production-shaped delivery path.

## Decision
`ci.yml` runs formatting, validation, `terraform test` with mock providers, a real `terragrunt plan` with no credentials ([ADR-0007](0007-hermetic-azure-plan.md)), OPA policy, scanners, Molecule and container tests. Applying is a separate `workflow_dispatch` workflow bound to a GitHub environment with required reviewers and OIDC federation, documented as requiring account setup.

## Consequences
- The green badge proves correctness and policy compliance, not that the resources exist.
- `apply.yml` cannot be exercised in this repo; the runbook explains the one-time setup.
- No cloud secret of any kind is ever stored in GitHub.
