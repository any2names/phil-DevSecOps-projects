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
    platformctl plan aws dev             # real terragrunt plan, hermetic (ADR-0007) + OPA gate
    platformctl plan azure prod
    TG_BACKEND=remote terragrunt plan    # only after docs/runbooks/deploy.md setup

No credentials of any kind are needed for `plan`: platformctl injects a hermetic environment
(dummy AWS keys; `scripts/az-shim` + `TC_TEST_VIA_VCR` for Azure) when none are present.
