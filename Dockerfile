# syntax=docker/dockerfile:1.7
# Cyber Intelligence Platform: one image for migrate / ingest / web / ai services.
# Base image pinned by digest (Dependabot proposes updates; CI rebuilds and scans).
ARG PYTHON_IMAGE=python:3.12-slim-bookworm@sha256:935c3c5b12357a7e10caa9c1e6ca5692344d97cf229832ef584be2cec9fc03df

FROM ${PYTHON_IMAGE} AS build
ENV PIP_NO_CACHE_DIR=1 PIP_DISABLE_PIP_VERSION_CHECK=1 PYTHONDONTWRITEBYTECODE=1
WORKDIR /src
COPY deploy/requirements.lock ./
# Every dependency hash-verified; nothing resolved at build time.
RUN python -m venv /opt/venv \
 && /opt/venv/bin/pip install --require-hashes --no-deps -r requirements.lock
COPY pyproject.toml README.md ./
COPY src ./src
RUN /opt/venv/bin/pip install --no-deps --no-build-isolation . \
 && /opt/venv/bin/pip uninstall -y setuptools pip \
 && find /opt/venv -name '__pycache__' -prune -exec rm -rf {} +

FROM ${PYTHON_IMAGE} AS runtime
LABEL org.opencontainers.image.source="https://github.com/frimpongemanuele/cyber-intel-platform" \
      org.opencontainers.image.description="Self-hosted cyber threat intelligence platform" \
      org.opencontainers.image.licenses="MIT"
# Unprivileged user; the same uid/gid owns the Docker secret files on the host
# (deploy/scripts/make-secrets.sh), so no secret is world-readable.
RUN groupadd --gid 10001 cit \
 && useradd --uid 10001 --gid 10001 --no-create-home --shell /usr/sbin/nologin cit \
 && rm -rf /usr/local/lib/python3.12/site-packages/pip* /usr/local/bin/pip*
COPY --from=build /opt/venv /opt/venv
COPY config /app/config
ENV PATH=/opt/venv/bin:$PATH \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONHASHSEED=random
WORKDIR /app
USER 10001:10001
# No default command: each Compose service states exactly what it runs.
ENTRYPOINT ["python", "-m"]
CMD ["cyberintel.web.healthcheck"]
