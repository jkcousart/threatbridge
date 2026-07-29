# syntax=docker/dockerfile:1.7

ARG PYTHON_BUILDER_IMAGE=python:3.13.14-slim@sha256:6771159cd4fa5d9bba1258caf0b82e6b73458c694d178ad97c5e925c2d0e1a91
ARG PYTHON_RUNTIME_IMAGE=python:3.13.14-slim@sha256:6771159cd4fa5d9bba1258caf0b82e6b73458c694d178ad97c5e925c2d0e1a91

FROM ${PYTHON_BUILDER_IMAGE} AS builder

USER 0
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /build

RUN python -m venv --copies /opt/build-venv \
    && python -m venv --copies /opt/runtime-venv

COPY requirements/build.txt /build/requirements/build.txt
RUN /opt/build-venv/bin/python -m pip install \
        --require-hashes \
        -r requirements/build.txt

COPY pyproject.toml README.md LICENSE NOTICE ./
COPY threatbridge ./threatbridge
COPY integrations ./integrations
COPY catalog ./catalog
RUN /opt/build-venv/bin/python -m pip wheel \
        --no-deps \
        --no-build-isolation \
        --wheel-dir /tmp/wheels \
        .

COPY requirements/runtime.txt /build/requirements/runtime.txt
RUN /opt/runtime-venv/bin/python -m pip install \
        --require-hashes \
        -r requirements/runtime.txt \
    && /opt/runtime-venv/bin/python -m pip install \
        --no-deps \
        /tmp/wheels/threatbridge-*.whl \
    && /opt/runtime-venv/bin/python -m pip check \
    && rm -rf \
        /opt/runtime-venv/bin/pip \
        /opt/runtime-venv/bin/pip3 \
        /opt/runtime-venv/bin/pip3.* \
        /opt/runtime-venv/lib/python*/site-packages/pip \
        /opt/runtime-venv/lib/python*/site-packages/pip-*.dist-info

COPY manage.py /runtime/app/manage.py
COPY LICENSE NOTICE /runtime/app/
RUN DJANGO_DEBUG=false \
       DJANGO_SECRET_KEY="$(python -c 'import secrets; print(secrets.token_urlsafe(64))')" \
       DJANGO_ALLOWED_HOSTS=build.example.invalid \
       DJANGO_CSRF_TRUSTED_ORIGINS=https://build.example.invalid \
       DJANGO_SECURE_HSTS_SECONDS=3600 \
       DJANGO_STATIC_ROOT=/runtime/app/staticfiles \
       DATABASE_URL=postgresql://build@database.example.invalid/threatbridge \
       THREATBRIDGE_DATA_DIR=/runtime/app/data \
       THREATBRIDGE_ALLOWED_OUTBOUND_HOSTS=outbound.example.invalid \
       /opt/runtime-venv/bin/python /runtime/app/manage.py collectstatic --noinput \
    && mkdir -p /runtime/app/data \
    && chmod 0755 /runtime/app /runtime/app/staticfiles \
    && chmod 0755 /runtime/app/manage.py \
    && chmod 0644 /runtime/app/LICENSE /runtime/app/NOTICE \
    && chmod 0750 /runtime/app/data \
    && /opt/runtime-venv/bin/python -c 'import importlib.util, pathlib, sysconfig, catalog, integrations, threatbridge; site = pathlib.Path(sysconfig.get_paths()["purelib"]).resolve(); modules = (catalog, integrations, threatbridge); assert all(pathlib.Path(module.__file__).resolve().is_relative_to(site) for module in modules); assert importlib.util.find_spec("pip") is None' \
    && test ! -e /runtime/app/.secrets \
    && test ! -e /runtime/app/catalog \
    && test ! -e /runtime/app/integrations \
    && test ! -e /runtime/app/threatbridge \
    && test ! -e /runtime/app/requirements \
    && test ! -e /runtime/app/scripts \
    && test ! -e /runtime/app/.github \
    && test ! -e /runtime/app/build \
    && test ! -e /runtime/app/data/incoming \
    && test -z "$(find /runtime/app -mindepth 1 -maxdepth 1 -name '*.egg-info' -print -quit)" \
    && test -z "$(find /opt/runtime-venv/lib/python*/site-packages/catalog /opt/runtime-venv/lib/python*/site-packages/integrations /opt/runtime-venv/lib/python*/site-packages/threatbridge -type d -name tests -print -quit)" \
    && test -z "$(find /runtime/app -xdev \( -type f -o -type d \) -perm -0002 -print -quit)"

FROM ${PYTHON_RUNTIME_IMAGE} AS runtime

# Provenance metadata. THREATBRIDGE_REVISION and THREATBRIDGE_CREATED are supplied by
# the documented build command; they are descriptive labels only and never secrets.
ARG THREATBRIDGE_VERSION=0.3.0
ARG THREATBRIDGE_REVISION=unknown
ARG THREATBRIDGE_CREATED=unknown
# Re-declare so the globally scoped digest is readable inside this stage.
ARG PYTHON_RUNTIME_IMAGE

LABEL org.opencontainers.image.title="ThreatBridge" \
      org.opencontainers.image.description="Threat-informed integration, evidence, and control-correlation platform" \
      org.opencontainers.image.version="${THREATBRIDGE_VERSION}" \
      org.opencontainers.image.revision="${THREATBRIDGE_REVISION}" \
      org.opencontainers.image.created="${THREATBRIDGE_CREATED}" \
      org.opencontainers.image.licenses="Apache-2.0" \
      org.opencontainers.image.source="https://github.com/jkcousart/threatbridge" \
      org.opencontainers.image.url="https://github.com/jkcousart/threatbridge" \
      org.opencontainers.image.documentation="https://github.com/jkcousart/threatbridge/blob/main/docs/deployment-hardening.md" \
      org.opencontainers.image.base.name="${PYTHON_RUNTIME_IMAGE}"

ENV PATH=/opt/runtime-venv/bin:${PATH} \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    DJANGO_STATIC_ROOT=/app/staticfiles \
    THREATBRIDGE_DATA_DIR=/app/data

WORKDIR /app

COPY --from=builder --chown=65532:65532 /opt/runtime-venv /opt/runtime-venv
COPY --from=builder --chown=65532:65532 /runtime/app /app

USER 65532:65532
ENTRYPOINT []
EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=30s --retries=5 \
    CMD ["python", "-c", "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/readyz', timeout=3).read()"]

CMD ["gunicorn", "threatbridge.wsgi:application", "--bind", "0.0.0.0:8000", "--workers", "3", "--timeout", "90", "--access-logfile", "-", "--error-logfile", "-"]
