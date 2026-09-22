# ADR-0002: Terragrunt for environment layering instead of Terraform workspaces

**Status:** Accepted · **Date:** 2026-09-21

## Context
Two clouds × two environments need distinct state, distinct provider config and distinct inputs. Workspaces share one backend and one provider block and make "which env am I in" implicit.

## Decision
Use Terragrunt. The unit path `infra/envs/<env>/<cloud>` encodes environment and cloud; the root `terragrunt.hcl` derives both from `path_relative_to_include()`, generates the provider block, selects the backend from `TG_BACKEND` (`local` for CI/dev, `remote` for apply), and points `terraform.source` at the right stack using the `//` convention so relative module paths survive the cache copy.

## Consequences
- Units are four tiny files of inputs; no duplicated backend/provider boilerplate.
- CI can plan with `TG_BACKEND=local` without touching any real backend.
- One more tool to install; pinned in workflows and `brew install terragrunt` locally.
