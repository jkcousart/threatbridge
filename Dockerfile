FROM python:3.14.7-slim@sha256:656d12e70054d5fda18a045e2494c96701e9792dd1445f95b3d038df954f57e9 AS builder

WORKDIR /build

COPY requirements/build.txt /build/requirements/build.txt
RUN python -m pip install --no-cache-dir --require-hashes -r requirements/build.txt

COPY pyproject.toml README.md LICENSE NOTICE ./
COPY threatbridge ./threatbridge
COPY integrations ./integrations
COPY catalog ./catalog
RUN python -m pip wheel \
        --no-cache-dir \
        --no-deps \
        --no-build-isolation \
        --wheel-dir /tmp/wheels \
        .

FROM python:3.14.7-slim@sha256:656d12e70054d5fda18a045e2494c96701e9792dd1445f95b3d038df954f57e9

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    DJANGO_STATIC_ROOT=/app/staticfiles \
    THREATBRIDGE_DATA_DIR=/app/data

WORKDIR /app

RUN addgroup --system threatbridge \
    && adduser --system --ingroup threatbridge threatbridge

COPY requirements/runtime.txt /tmp/requirements/runtime.txt
RUN python -m pip install \
        --no-cache-dir \
        --require-hashes \
        -r /tmp/requirements/runtime.txt

COPY --from=builder /tmp/wheels /tmp/wheels
RUN python -m pip install --no-cache-dir --no-deps /tmp/wheels/threatbridge-*.whl \
    && rm -rf /tmp/wheels /tmp/requirements

COPY manage.py LICENSE NOTICE /app/
RUN DJANGO_DEBUG=false \
       DJANGO_SECRET_KEY="$(python -c 'import secrets; print(secrets.token_urlsafe(64))')" \
       DJANGO_ALLOWED_HOSTS=build.example.invalid \
       DJANGO_CSRF_TRUSTED_ORIGINS=https://build.example.invalid \
       DJANGO_SECURE_HSTS_SECONDS=3600 \
       DATABASE_URL=postgresql://build@database.example.invalid/threatbridge \
       THREATBRIDGE_ALLOWED_OUTBOUND_HOSTS=outbound.example.invalid \
       python manage.py collectstatic --noinput \
    && mkdir -p /app/data \
    && python -c 'import pathlib, sysconfig, catalog, integrations, threatbridge; site = pathlib.Path(sysconfig.get_paths()["purelib"]).resolve(); modules = (catalog, integrations, threatbridge); assert all(pathlib.Path(module.__file__).resolve().is_relative_to(site) for module in modules)' \
    && find /app -type d -exec chmod 0755 {} + \
    && find /app -type f -exec chmod 0644 {} + \
    && chmod 0755 /app/manage.py \
    && chown threatbridge:threatbridge /app/data \
    && chmod 0750 /app/data \
    && test ! -e /app/.secrets \
    && test ! -e /app/catalog \
    && test ! -e /app/integrations \
    && test ! -e /app/threatbridge \
    && test ! -e /app/requirements \
    && test ! -e /app/scripts \
    && test ! -e /app/.github \
    && test ! -e /app/build \
    && test ! -e /app/data/incoming \
    && test -z "$(find /app -mindepth 1 -maxdepth 1 -name '*.egg-info' -print -quit)" \
    && test -z "$(find /usr/local/lib/python*/site-packages/catalog /usr/local/lib/python*/site-packages/integrations /usr/local/lib/python*/site-packages/threatbridge -type d -name tests -print -quit)" \
    && test -z "$(find /app -xdev \( -type f -o -type d \) -perm -0002 -print -quit)"

USER threatbridge
EXPOSE 8000

CMD ["gunicorn", "threatbridge.wsgi:application", "--bind", "0.0.0.0:8000", "--workers", "3", "--timeout", "90"]
