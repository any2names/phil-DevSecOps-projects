# Threat model (STRIDE)

Scope: the deployed VM + app, the secret path, and the delivery pipeline. Assets: the runtime secret, the signing identity, Terraform state, admin SSH access.

| Threat | Category | Mitigation | Where |
|---|---|---|---|
| Attacker brute-forces SSH | Spoofing | Key-only auth, `AllowUsers`, fail2ban, SSH restricted to admin CIDRs, catch-all NSG deny | `ansible/roles/harden`, `modules/network/*` |
| Stolen CI token used to reach cloud | Spoofing | No long-lived cloud credentials; `apply.yml` uses OIDC federation scoped to environment + required reviewer | `.github/workflows/apply.yml` |
| Malicious PR alters a workflow to exfiltrate secrets | Tampering | `permissions: {}` at workflow level, minimal per-job; CODEOWNERS on workflows; actions SHA-pinned | `.github/` |
| Compromised third-party action | Tampering | SHA pinning enforced by `platformctl actions pin --check`; Dependabot updates | `platformctl/actions.py` |
| Image substituted between build and deploy | Tampering | cosign keyless signature + SLSA L3 provenance; `platformctl verify` before use | `release.yml`, `supplychain.py` |
| Secret leaks via logs or API | Information disclosure | App returns only a keyed-HMAC fingerprint (rotation marker, not a brute-force oracle); `Cache-Control: no-store`; secret file 0640; `platformctl secrets` never prints values | `app/`, `app_deploy` |
| Secret committed to git | Information disclosure | gitleaks pre-commit + CI on full history; OPA `terraform.secrets` denies secret-value resources and credential-shaped strings | `.gitleaks.toml`, `policy/` |
| Terraform state exposed | Information disclosure | Remote backends encrypted (S3 SSE, Azure Storage); no secret values in state by design | `infra/terragrunt.hcl` |
| Operator disputes a prod change | Repudiation | auditd rules on identity, sudoers and `/etc/secure-api`; GitHub environment approvals; signed provenance | `harden/templates/audit.rules.j2` |
| App compromised via HTTP | Elevation of privilege | Non-root service user, `NoNewPrivileges`, empty capability set, `ProtectSystem=strict`, syscall filter; nginx TLS 1.2+ only; OpenAPI docs disabled | `secure-api.service.j2`, nginx template |
| IMDS credential theft from a compromised process | Elevation of privilege | IMDSv2 required, hop limit 1 (AWS); user-assigned identity with read-only secret role (Azure) | `modules/compute/*`, `modules/secrets/*` |
| Automated prod plan destroys stateful resources | Denial of service | OPA `terraform.protection` denies destroy of KMS/secret/vault/RG in prod; 30-day recovery windows | `policy/terraform/protection.rego` |
| Oversized instance / cost blow-up | Denial of service (budget) | Per-environment instance allow-list | `policy/terraform/instances.rego` |

## Accepted risks

- Single VM per cloud, no HA — this is a reference platform, not a production SLA.
- Self-signed TLS when no domain is configured; the ACME path exists and is used when `app_deploy_domain` is set.
- Public IP on the VM. A bastion/private-endpoint variant is listed under future work in the README.
- The hermetic Azure plan ([ADR-0007](adr/0007-hermetic-azure-plan.md)) relies on provider internals; if a future azurerm release validates tokens at configure time, the Azure plan job degrades to validate + `terraform test` only.
