from django.apps import AppConfig


class CatalogConfig(AppConfig):
    default_auto_field = "django.db.models.BigAutoField"
    name = "catalog"

    def ready(self):
        from threatbridge import checks  # noqa: F401

    verbose_name = "ThreatBridge Catalog"
