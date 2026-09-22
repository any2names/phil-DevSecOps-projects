# ADR-0006: Key Vault defined as an ARM template, deployed through Terraform

**Status:** Accepted · **Date:** 2026-09-21

## Context
ARM templates are a first-class skill on this platform, but an ARM file that nothing deploys is a demo, not infrastructure. Key Vault is the resource where ARM's native support (RBAC mode, purge protection, network ACLs) is most complete.

## Decision
`infra/arm/keyvault.json` is the source of truth for the vault. The Terraform `secrets/azure` module deploys it with `azurerm_resource_group_template_deployment` in `Incremental` mode, decodes its outputs, and layers the RBAC role assignment on top. The template is validated by `arm-ttk` in CI and can also be deployed standalone with `az deployment group create`.

## Consequences
- One resource, one definition, two valid entry points (Terraform or az CLI).
- OPA denies `Complete` deployment mode because it would delete unmanaged resources in the resource group.
- Template outputs are the contract between ARM and Terraform; renaming them is a breaking change.
