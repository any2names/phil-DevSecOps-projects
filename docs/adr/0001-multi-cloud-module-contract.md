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
