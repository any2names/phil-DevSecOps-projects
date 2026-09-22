# syntax=docker/dockerfile:1.7
# Stage 1: install into an isolated prefix. Python 3.11 matches the distroless runtime below.
FROM python:3.11-slim@sha256:da047cb8f9d1d98e5c070f5300ba9f7274e33b8fc0e5be5ed88740aed1b95ba9 AS build
WORKDIR /build
COPY pyproject.toml ./
COPY src ./src
RUN pip install --no-cache-dir --upgrade pip \
 && pip install --no-cache-dir --prefix=/install .

# Stage 2: runtime — distroless, non-root, no shell, no package manager, no pip
FROM gcr.io/distroless/python3-debian12:nonroot@sha256:7d1042ce588ab97019fe95c24ffca7bc5a82ccdac572511d5e09bda4435c89c5
WORKDIR /app
COPY --from=build /install/lib/python3.11/site-packages /app/site-packages
ENV PYTHONPATH=/app/site-packages PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
USER nonroot:nonroot
EXPOSE 8000
ENTRYPOINT ["python3", "-m", "uvicorn", "secure_api.main:app", "--host", "0.0.0.0", "--port", "8000"]
