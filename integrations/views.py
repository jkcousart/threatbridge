from rest_framework import status, viewsets
from rest_framework.decorators import action
from rest_framework.parsers import FormParser, MultiPartParser
from rest_framework.permissions import IsAdminUser, IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView

from .file_imports import create_file_import, inspect_uploaded_file
from .models import ExternalObject, Integration, SyncRun
from .registry import available_adapters
from .serializers import (
    ExternalObjectSerializer,
    FileImportSerializer,
    FilePreviewSerializer,
    IntegrationSerializer,
    SyncRunSerializer,
)
from .services import run_integration_sync, test_integration


class IntegrationTypeView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        return Response(available_adapters())


class IntegrationViewSet(viewsets.ModelViewSet):
    queryset = Integration.objects.all()
    serializer_class = IntegrationSerializer

    def get_permissions(self):
        if self.action in {"list", "retrieve", "adapter_types"}:
            return [IsAuthenticated()]
        return [IsAdminUser()]

    @action(detail=False, methods=["get"], url_path="adapter-types")
    def adapter_types(self, request):
        return Response(available_adapters())

    @action(detail=True, methods=["post"])
    def test(self, request, pk=None):
        integration = self.get_object()
        try:
            result = test_integration(integration)
            return Response(result)
        except Exception as exc:
            return Response({"ok": False, "error": str(exc)}, status=status.HTTP_400_BAD_REQUEST)

    @action(detail=True, methods=["post"])
    def sync(self, request, pk=None):
        integration = self.get_object()
        try:
            run = run_integration_sync(integration)
            return Response(SyncRunSerializer(run).data, status=status.HTTP_201_CREATED)
        except Exception as exc:
            return Response({"error": str(exc)}, status=status.HTTP_400_BAD_REQUEST)


class SyncRunViewSet(viewsets.ReadOnlyModelViewSet):
    queryset = SyncRun.objects.select_related("integration").prefetch_related("record_errors")
    serializer_class = SyncRunSerializer
    permission_classes = [IsAuthenticated]

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
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        queryset = super().get_queryset()
        integration = self.request.query_params.get("integration")
        object_type = self.request.query_params.get("object_type")
        natural_key = self.request.query_params.get("natural_key")
        projection_status = self.request.query_params.get("projection_status")
        include_deleted = self.request.query_params.get("include_deleted") == "true"
        if not include_deleted:
            queryset = queryset.filter(is_deleted=False)
        if integration:
            queryset = queryset.filter(integration__slug=integration)
        if object_type:
            queryset = queryset.filter(object_type=object_type)
        if natural_key:
            queryset = queryset.filter(natural_key=natural_key)
        if projection_status:
            queryset = queryset.filter(projection_status=projection_status)
        return queryset

class FileImportPreviewView(APIView):
    permission_classes = [IsAdminUser]
    parser_classes = [MultiPartParser, FormParser]

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
    permission_classes = [IsAdminUser]
    parser_classes = [MultiPartParser, FormParser]

    def post(self, request):
        serializer = FileImportSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        data = serializer.validated_data
        integration = None
        if data.get("integration_id"):
            integration = Integration.objects.get(pk=data["integration_id"])
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
                default_review_status=data.get("default_review_status", "pending"),
                strict_records=data.get("strict_records", False),
                sync_now=data.get("sync_now", True),
                integration=integration,
            )
        except (ValueError, OSError) as exc:
            return Response({"error": str(exc)}, status=status.HTTP_400_BAD_REQUEST)

        payload = {
            "integration": IntegrationSerializer(result.integration).data,
            "inspection": result.inspection.as_dict(),
            "sync_run": SyncRunSerializer(result.run).data if result.run else None,
        }
        return Response(payload, status=status.HTTP_201_CREATED)
