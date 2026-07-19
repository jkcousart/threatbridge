from django.urls import path
from rest_framework.routers import DefaultRouter

from .views import (
    ExternalObjectViewSet,
    FileImportPreviewView,
    FileImportView,
    IntegrationTypeView,
    IntegrationViewSet,
    SyncRunViewSet,
)

router = DefaultRouter()
router.register("integrations", IntegrationViewSet)
router.register("sync-runs", SyncRunViewSet)
router.register("external-objects", ExternalObjectViewSet)

urlpatterns = [
    path("integration-types/", IntegrationTypeView.as_view(), name="integration-types"),
    path("file-imports/preview/", FileImportPreviewView.as_view(), name="file-import-preview"),
    path("file-imports/", FileImportView.as_view(), name="file-import"),
]
urlpatterns += router.urls
