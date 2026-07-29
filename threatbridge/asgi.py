import os

from django.core.asgi import get_asgi_application

from threatbridge.runtime import require_explicit_debug_configuration

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "threatbridge.settings")
require_explicit_debug_configuration()
application = get_asgi_application()
