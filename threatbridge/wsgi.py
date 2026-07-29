import os

from django.core.wsgi import get_wsgi_application

from threatbridge.runtime import require_explicit_debug_configuration

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "threatbridge.settings")
require_explicit_debug_configuration()
application = get_wsgi_application()
