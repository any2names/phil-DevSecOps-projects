# secure-api

A deliberately small FastAPI service whose job is to prove the platform's secret-handling path end to end.

| Endpoint | Purpose |
|---|---|
| `GET /healthz` | Liveness for nginx, Molecule and load balancers |
| `GET /api/v1/status` | Reports version, environment and a keyed-HMAC *fingerprint* of the runtime secret (a rotation marker, not a hash that could be brute-forced) — never the secret |

OpenAPI docs are disabled (`/docs`, `/openapi.json` → 404): an internal service has no business advertising its surface.

## Configuration

| Env var | Required | Source in production |
|---|---|---|
| `APP_SECRET` | yes (≥ 16 chars) | `/etc/secure-api/env`, written at service start by `fetch-secret.sh` from Key Vault / Secrets Manager using the VM identity |
| `APP_ENV` | no (default `dev`) | same file |

The app refuses to start without `APP_SECRET` — fail-fast beats a half-configured service.

## Run locally

    make bootstrap
    APP_SECRET=local-dev-only .venv/bin/uvicorn secure_api.main:app --app-dir app/src --reload

## Tests

    .venv/bin/pytest app/tests

## Container

Multi-stage build on a digest-pinned `python:3.11-slim`: build tooling stays in stage 1, the runtime applies Debian
security updates at build time, runs as a non-root system user and ships a `HEALTHCHECK`. `gcr.io/distroless/python3`
was evaluated first but lagged Debian security fixes by 19 fixable HIGH CVEs, failing the Trivy gate — a scan that
passes beats a smaller attack surface that doesn't.
Built, smoke-tested, scanned with Trivy in `ci.yml`; signed with cosign and shipped with an SPDX SBOM by `release.yml`.
