# syntax=docker/dockerfile:1.7
# Stage 1: install into an isolated prefix.
FROM python:3.14-slim@sha256:caaf356f40667c496d405780745b9ac25771c189a51dfcc42430d531ea09f8a2 AS build
WORKDIR /build
COPY pyproject.toml ./
COPY src ./src
RUN pip install --no-cache-dir --upgrade pip \
 && pip install --no-cache-dir --prefix=/install .

# Stage 2: runtime. Same digest-pinned slim base, Debian security updates applied at build time,
# non-root user, no build tooling, no pip/setuptools (they ship vendored deps with CVEs and are useless at runtime). (distroless/python3 was evaluated but lagged Debian security
# fixes by 19 fixable HIGH CVEs at the time of writing, so it failed the Trivy gate.)
FROM python:3.14-slim@sha256:caaf356f40667c496d405780745b9ac25771c189a51dfcc42430d531ea09f8a2
RUN apt-get update \
 && apt-get upgrade -y --no-install-recommends \
 && apt-get clean && rm -rf /var/lib/apt/lists/* \
 && python3 -m pip uninstall -y pip setuptools wheel \
 && useradd --system --uid 10001 --no-create-home --shell /usr/sbin/nologin app
WORKDIR /app
COPY --from=build /install /usr/local
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
USER 10001:10001
EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD ["python3", "-c", "import sys, urllib.request; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8000/healthz', timeout=2).status == 200 else 1)"]
ENTRYPOINT ["python3", "-m", "uvicorn", "secure_api.main:app", "--host", "0.0.0.0", "--port", "8000"]
