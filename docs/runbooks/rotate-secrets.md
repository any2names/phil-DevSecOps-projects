# Runbook: rotate the runtime secret

Rotation is dry-run by default and never prints values.

1. Preview: `platformctl secrets rotate app` → shows that a rotation would happen and how many active versions would be deprecated.
2. Execute: `platformctl secrets rotate app --execute` → new version written, previous versions disabled/tagged `deprecated`.
3. Roll the service so it re-reads the store: `ansible -i inventory/<cloud>-<env>.yml api -b -m systemd -a "name=secure-api state=restarted"`.
   `ExecStartPre=fetch-secret.sh` fetches the current version on every start.
4. Verify: the `secret_fingerprint` in `GET /api/v1/status` changes.
5. Audit: `platformctl secrets list app` shows the version history.

Rollback: re-enable the previous version in the console and restart the service. Deprecated Azure versions stay recoverable (soft delete, 90 days); AWS keeps `AWSPREVIOUS` for 24h before purge.

Schedule: rotate every 90 days or immediately on suspected exposure. `platformctl certs check` covers certificates on the same cadence.
