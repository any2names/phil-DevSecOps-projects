"""Minimal FastAPI service. The notable part is what it does NOT do: log or return the secret."""

import hashlib
import hmac
import os
from collections.abc import Awaitable, Callable

from fastapi import FastAPI, Request, Response
from pydantic import ValidationError

from secure_api import __version__
from secure_api.settings import Settings


def create_app(settings: Settings | None = None) -> FastAPI:
    try:
        cfg = settings or Settings()  # type: ignore[call-arg]  # populated from APP_* env
    except ValidationError as exc:
        raise RuntimeError("APP_SECRET is required (min 16 chars); APP_ENV is optional") from exc
    app = FastAPI(
        title="secure-api",
        version=__version__,
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
    )

    @app.middleware("http")
    async def security_headers(
        request: Request, call_next: Callable[[Request], Awaitable[Response]]
    ) -> Response:
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Cache-Control"] = "no-store"
        return response

    @app.get("/healthz")
    async def healthz() -> dict[str, str]:
        return {"status": "ok"}

    @app.get("/api/v1/status")
    async def status() -> dict[str, str | bool]:
        # Rotation marker, not a hash of the secret: keyed HMAC over a constant, so the
        # fingerprint changes when the secret does but cannot be used as a brute-force
        # oracle against short inputs (min length 16 is enforced in settings).
        fingerprint = hmac.new(cfg.secret.encode(), b"secure-api/fingerprint", hashlib.sha256)
        fingerprint_hex = fingerprint.hexdigest()[:12]
        return {
            "version": __version__,
            "environment": cfg.env,
            "secret_configured": True,
            "secret_fingerprint": fingerprint_hex,
        }

    return app


def _module_app() -> FastAPI | None:
    """uvicorn imports `secure_api.main:app`; tests call create_app() directly."""
    return create_app() if os.environ.get("APP_SECRET") else None


app = _module_app()
