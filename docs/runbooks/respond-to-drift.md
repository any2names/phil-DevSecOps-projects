# Runbook: responding to drift

`platformctl drift <cloud> <env>` exits 2 when a plan would change anything relative to the accepted baseline and writes a markdown report with `--report drift.md`.

1. Read the report: which addresses are new since the last accepted plan?
2. Classify:
   - **Console change by a human** (tags, NSG rule added by hand): revert in the console or codify it in a PR. Never accept undocumented manual changes.
   - **Provider default change after upgrade**: review, then `platformctl drift <cloud> <env> --accept` after the PR merges.
   - **Security-relevant** (new ingress rule, encryption disabled): treat as an incident — check auditd/CloudTrail/Activity Log for who made the change, revert immediately via `apply`.
3. After remediation, re-run drift; it must exit 0. Then `--accept` to update the baseline.

Automate: schedule `platformctl drift` daily in a cron workflow once accounts exist; page on exit code 2.
