# syntax=docker/dockerfile:1
#
# Multi-stage build: a builder stage installs the package into a venv,
# then the runtime stage copies only that venv (and the app itself) into a
# slim image, running as a non-root user — principle of least privilege
# applied to the container, not just to the application's own permission
# model.
#
# Build (from the repo root):
#   docker build -f docker/Dockerfile -t ir-soar:latest .
#
# Or simply:
#   docker compose -f docker/docker-compose.yml build

# ---- Build stage -----------------------------------------------------------
FROM python:3.11-slim AS builder

WORKDIR /build

# build-essential is only needed in case any dependency lacks a prebuilt
# wheel for this platform; it does NOT ship in the final runtime image.
RUN apt-get update \
    && apt-get install -y --no-install-recommends build-essential \
    && rm -rf /var/lib/apt/lists/*

COPY pyproject.toml requirements.txt README.md ./
COPY src ./src

RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"
RUN pip install --no-cache-dir --upgrade pip \
    && pip install --no-cache-dir .

# ---- Runtime stage ----------------------------------------------------------
FROM python:3.11-slim AS runtime

LABEL org.opencontainers.image.title="ir-soar" \
      org.opencontainers.image.description="Lightweight Incident Response Playbook + SOAR-style automation framework"

# Non-root user — the container never runs as root, independent of
# whatever host-level Docker permissions exist.
RUN groupadd --gid 1000 irsoar \
    && useradd --uid 1000 --gid irsoar --create-home --shell /bin/bash irsoar

COPY --from=builder /opt/venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH" \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

WORKDIR /app

# Config, playbooks, and docs are baked into the image so it runs
# standalone out of the box, but docker-compose.yml also volume-mounts
# config/ and playbooks/ read-only over these so a user can edit either
# without rebuilding the image.
COPY config ./config
COPY playbooks ./playbooks
COPY docs ./docs

# Writable output directories, created ahead of time and owned by the
# non-root user — everything else in /app is effectively read-only at
# runtime from the application's perspective.
RUN mkdir -p /app/logs /app/evidence && chown -R irsoar:irsoar /app

USER irsoar

# Sane, safe defaults if the container is run with no arguments at all:
# print help rather than doing anything. Real invocations override CMD,
# e.g.:
#   docker run --rm ir-soar:latest run --playbook phishing_lateral_movement --dry-run
ENTRYPOINT ["ir-soar"]
CMD ["--help"]
