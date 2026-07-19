from django.shortcuts import get_object_or_404
from rest_framework import mixins, status, viewsets
from rest_framework.decorators import action
from rest_framework.parsers import FormParser, MultiPartParser
from rest_framework.response import Response
from rest_framework.views import APIView

from catalog.services.audit import record_security_event
from threatbridge.authorization import (
    HasNamedPermission,
    Permissions,
    is_allowed,
    require_permission,
)

from .evidence import delete_source_evidence, restore_source_evidence
from .file_imports import create_file_import, inspect_uploaded_file
from .models import ExternalObject, Integration, SyncRun
from .registry import available_adapters
from .secrets import sanitized_connector_error
from .serializers import (
    ExternalObjectSerializer,
    FileImportSerializer,
    FilePreviewSerializer,
    IntegrationSerializer,
    SyncRunSerializer,
)
from .services import run_integration_sync, test_integration


class IntegrationTypeView(APIView):
    permission_classes = [HasNamedPermission]

    def get_required_permission(self):
        return Permissions.VIEW_INTEGRATIONS

    def get(self, request):
        return Response(available_adapters())


class IntegrationViewSet(
    mixins.CreateModelMixin,
    mixins.ListModelMixin,
    mixins.RetrieveModelMixin,
    mixins.UpdateModelMixin,
    viewsets.GenericViewSet,
):
    queryset = Integration.objects.all()
    serializer_class = IntegrationSerializer

    permission_classes = [HasNamedPermission]

    def get_required_permission(self):
        return {
            "list": Permissions.VIEW_INTEGRATIONS,
            "retrieve": Permissions.VIEW_INTEGRATIONS,
            "adapter_types": Permissions.VIEW_INTEGRATIONS,
            "test": (
                Permissions.VIEW_INTEGRATIONS,
                Permissions.TEST_INTEGRATIONS,
            ),
            "sync": (
                Permissions.VIEW_INTEGRATIONS,
                Permissions.SYNCHRONIZE_INTEGRATIONS,
            ),
            "update": (
                Permissions.VIEW_INTEGRATIONS,
                Permissions.CONFIGURE_INTEGRATIONS,
            ),
            "partial_update": (
                Permissions.VIEW_INTEGRATIONS,
                Permissions.CONFIGURE_INTEGRATIONS,
            ),
            "create": (
                Permissions.VIEW_INTEGRATIONS,
                Permissions.CONFIGURE_INTEGRATIONS,
            ),
        }.get(self.action, Permissions.CONFIGURE_INTEGRATIONS)

    def perform_create(self, serializer):
        integration = serializer.save()
        record_security_event(
            event_type="integration.configuration_changed",
            origin="rest:integration_create",
            outcome="succeeded",
            actor=self.request.user,
            target_type="integration",
            target_identifier=integration.pk,
            metadata={"operation": "created"},
        )

    def perform_update(self, serializer):
        integration = serializer.save()
        record_security_event(
            event_type="integration.configuration_changed",
            origin="rest:integration_update",
            outcome="succeeded",
            actor=self.request.user,
            target_type="integration",
            target_identifier=integration.pk,
            metadata={"operation": "updated"},
        )

    @action(detail=False, methods=["get"], url_path="adapter-types")
    def adapter_types(self, request):
        return Response(available_adapters())

    @action(detail=True, methods=["post"])
    def test(self, request, pk=None):
        integration = self.get_object()
        try:
            result = test_integration(
                integration,
                actor=request.user,
                origin="rest:integration_test",
            )
            return Response(result)
        except Exception as exc:
            return Response(
                {"ok": False, "error": sanitized_connector_error(exc)},
                status=status.HTTP_400_BAD_REQUEST,
            )

    @action(detail=True, methods=["post"])
    def sync(self, request, pk=None):
        integration = self.get_object()
        try:
            run = run_integration_sync(
                integration,
                actor=request.user,
                origin="rest:integration_sync",
            )
            return Response(SyncRunSerializer(run).data, status=status.HTTP_201_CREATED)
        except Exception as exc:
            return Response(
                {"error": sanitized_connector_error(exc)},
                status=status.HTTP_400_BAD_REQUEST,
            )


class SyncRunViewSet(viewsets.ReadOnlyModelViewSet):
    queryset = SyncRun.objects.select_related("integration").prefetch_related("record_errors")
    serializer_class = SyncRunSerializer
    permission_classes = [HasNamedPermission]

    def get_required_permission(self):
        return Permissions.VIEW_INTEGRATIONS

    def get_queryset(self):
        queryset = super().get_queryset()
        integration = self.request.query_params.get("integration")
        status_value = self.request.query_params.get("status")
        if integration:
            queryset = queryset.filter(integration__slug=integration)
        if status_value:
            queryset = queryset.filter(status=status_value)
        return queryset


class ExternalObjectViewSet(viewsets.ReadOnlyModelViewSet):
    queryset = ExternalObject.objects.select_related("integration")
    serializer_class = ExternalObjectSerializer
    permission_classes = [HasNamedPermission]

    def get_required_permission(self):
        return {
            "delete_evidence": (
                Permissions.VIEW_RESTRICTED_SOURCE_EVIDENCE,
                Permissions.DELETE_SOURCE_EVIDENCE,
            ),
            "restore": (
                Permissions.VIEW_RESTRICTED_SOURCE_EVIDENCE,
                Permissions.VIEW_DELETED_SOURCE_EVIDENCE,
                Permissions.RESTORE_DELETED_SOURCE_EVIDENCE,
            ),
        }.get(self.action, Permissions.VIEW_RESTRICTED_SOURCE_EVIDENCE)

    def get_queryset(self):
        include_deleted = self.request.query_params.get("include_deleted") == "true"
        if include_deleted:
            require_permission(
                self.request.user,
                Permissions.VIEW_DELETED_SOURCE_EVIDENCE,
            )
            queryset = ExternalObject.all_objects.select_related("integration")
        else:
            queryset = super().get_queryset()
        integration = self.request.query_params.get("integration")
        object_type = self.request.query_params.get("object_type")
        natural_key = self.request.query_params.get("natural_key")
        projection_status = self.request.query_params.get("projection_status")
        if integration:
            queryset = queryset.filter(integration__slug=integration)
        if object_type:
            queryset = queryset.filter(object_type=object_type)
        if natural_key:
            queryset = queryset.filter(natural_key=natural_key)
        if projection_status:
            queryset = queryset.filter(projection_status=projection_status)
        return queryset.order_by("id")

    @action(detail=True, methods=["post"], url_path="delete-evidence")
    def delete_evidence(self, request, pk=None):
        source_object = get_object_or_404(ExternalObject.objects, pk=pk)
        try:
            deleted = delete_source_evidence(
                source_object,
                actor=request.user,
                reason=request.data.get("reason", ""),
                origin="rest:evidence_delete",
            )
        except ValueError as exc:
            return Response(
                {"reason": [str(exc)]},
                status=status.HTTP_400_BAD_REQUEST,
            )
        return Response({"id": deleted.pk, "is_deleted": True})

    @action(detail=True, methods=["post"])
    def restore(self, request, pk=None):
        source_object = get_object_or_404(ExternalObject.all_objects, pk=pk)
        try:
            restored = restore_source_evidence(
                source_object,
                actor=request.user,
                reason=request.data.get("reason", ""),
                origin="rest:evidence_restore",
            )
        except ValueError as exc:
            return Response(
                {"reason": [str(exc)]},
                status=status.HTTP_400_BAD_REQUEST,
            )
        return Response({"id": restored.pk, "is_deleted": False})

class FileImportPreviewView(APIView):
    permission_classes = [HasNamedPermission]
    parser_classes = [MultiPartParser, FormParser]

    def get_required_permission(self):
        return Permissions.IMPORT_SOURCE_FILES

    def post(self, request):
        serializer = FilePreviewSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        data = serializer.validated_data
        try:
            inspection = inspect_uploaded_file(
                data["file"],
                records_key=data.get("records_key", ""),
                delimiter=data.get("delimiter", ""),
                object_type=data.get("object_type", "auto"),
            )
        except ValueError as exc:
            return Response({"error": str(exc)}, status=status.HTTP_400_BAD_REQUEST)
        return Response(inspection.as_dict())


class FileImportView(APIView):
    permission_classes = [HasNamedPermission]
    parser_classes = [MultiPartParser, FormParser]

    def get_required_permission(self):
        return Permissions.IMPORT_SOURCE_FILES

    def post(self, request):
        serializer = FileImportSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        data = serializer.validated_data
        integration = None
        if data.get("integration_id"):
            require_permission(request.user, Permissions.VIEW_INTEGRATIONS)
            require_permission(request.user, Permissions.CONFIGURE_INTEGRATIONS)
            integration = get_object_or_404(Integration, pk=data["integration_id"])
        try:
            result = create_file_import(
                uploaded_file=data["file"],
                name=data.get("name", ""),
                object_type=data.get("object_type", "auto"),
                id_fields=data.get("id_fields", ""),
                records_key=data.get("records_key", ""),
                natural_key_field=data.get("natural_key_field", ""),
                updated_at_field=data.get("updated_at_field", ""),
                field_map=data.get("field_map", {}),
                delimiter=data.get("delimiter", ""),
                strict_records=data.get("strict_records", False),
                sync_now=data.get("sync_now", True),
                integration=integration,
                actor=request.user,
                origin="rest:file_import",
            )
        except (ValueError, OSError):
            return Response(
                {"error": "The file import could not be completed."},
                status=status.HTTP_400_BAD_REQUEST,
            )

        sync_run = result.run
        payload = {
            "integration_id": result.integration.pk,
            "integration": (
                IntegrationSerializer(result.integration).data
                if is_allowed(request.user, Permissions.VIEW_INTEGRATIONS)
                else None
            ),
            "inspection": result.inspection.as_dict(),
            "sync_run": (
                {
                    "id": sync_run.pk,
                    "status": sync_run.status,
                    "records_received": sync_run.records_received,
                    "records_accepted": sync_run.records_accepted,
                    "records_rejected": sync_run.records_rejected,
                    "records_projected": sync_run.records_projected,
                    "projection_failures": sync_run.projection_failures,
                }
                if sync_run
                else None
            ),
        }
        return Response(payload, status=status.HTTP_201_CREATED)
