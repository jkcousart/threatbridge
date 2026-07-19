FROM python:3.13-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

RUN addgroup --system threatbridge \
    && adduser --system --ingroup threatbridge threatbridge

COPY . .
RUN pip install --no-cache-dir . \
    && DJANGO_DEBUG=false \
       DJANGO_SECRET_KEY="$(python -c 'import secrets; print(secrets.token_urlsafe(64))')" \
       DJANGO_ALLOWED_HOSTS=build.example.invalid \
       DJANGO_CSRF_TRUSTED_ORIGINS=https://build.example.invalid \
       DJANGO_SECURE_HSTS_SECONDS=3600 \
       DATABASE_URL=postgresql://build@database.example.invalid/threatbridge \
       THREATBRIDGE_ALLOWED_OUTBOUND_HOSTS=outbound.example.invalid \
       python manage.py collectstatic --noinput \
    && rm -rf /app/build /app/*.egg-info /app/data/incoming \
    && mkdir -p /app/data \
    && find /app -type d -exec chmod 0755 {} + \
    && find /app -type f -exec chmod 0644 {} + \
    && chmod 0755 /app/manage.py \
    && chown threatbridge:threatbridge /app/data \
    && chmod 0750 /app/data \
    && test ! -e /app/.secrets \
    && test ! -e /app/build \
    && test ! -e /app/data/incoming \
    && test -z "$(find /app -mindepth 1 -maxdepth 1 -name '*.egg-info' -print -quit)" \
    && test -z "$(find /app -xdev \( -type f -o -type d \) -perm -0002 -print -quit)"

USER threatbridge
EXPOSE 8000

CMD ["gunicorn", "threatbridge.wsgi:application", "--bind", "0.0.0.0:8000", "--workers", "3", "--timeout", "90"]
