# ansible

| Role | Purpose |
|---|---|
| `harden` | CIS-inspired: SSH drop-in, sysctl, auditd, fail2ban, unattended-upgrades, legacy package removal, banner |
| `app_deploy` | Service user, venv install of `app/`, hardened systemd unit, identity-based secret fetch, nginx TLS (ACME or self-signed) |

Inventory is generated, not hand-written: `platformctl ansible inventory <cloud> <env>` writes `inventory/<cloud>-<env>.yml` from Terraform outputs. The `cloud` var selects how `fetch-secret.sh` reaches the secret store (`azure` → IMDS + Key Vault REST, `aws` → `aws secretsmanager`, `local` → dev value for Molecule).

    make ansible-lint      # production profile
    make molecule          # needs Docker; runs converge + verify on Ubuntu 22.04 with systemd
    ansible-playbook -i inventory/aws-dev.yml playbooks/site.yml
