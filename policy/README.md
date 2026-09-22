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
3. Plan JSON quirks: unknown values live in `change.after_unknown`, not `change.after`, and explicitly
   null attributes are "defined" in Rego — use `helpers.missing(r, attr)` rather than `not r.change.after[attr]`.
