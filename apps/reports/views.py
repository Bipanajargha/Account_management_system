from rest_framework import mixins, status, viewsets
from rest_framework.decorators import action
from rest_framework.response import Response

from ams.permissions import (
    ROLE_ACCOUNTANT,
    ROLE_ADMIN,
    ROLE_MANAGER,
    RoleBasedPermission,
)
from apps.notifications.utils import log_audit

from .models import Report
from .serializers import ReportCreateSerializer, ReportSerializer
from .services import create_report


class ReportViewSet(
    mixins.ListModelMixin,
    mixins.RetrieveModelMixin,
    viewsets.GenericViewSet,
):
    queryset = Report.objects.select_related("requested_by").all()
    serializer_class = ReportSerializer
    permission_classes = [RoleBasedPermission]
    allowed_read_roles = [ROLE_ADMIN, ROLE_ACCOUNTANT, ROLE_MANAGER]
    allowed_write_roles = [ROLE_ADMIN, ROLE_ACCOUNTANT, ROLE_MANAGER]
    filterset_fields = ["report_type", "export_format"]
    search_fields = ["report_type"]

    def create(self, request, *args, **kwargs):
        serializer = ReportCreateSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        payload = serializer.validated_data
        report = create_report(
            report_type=payload["report_type"],
            start_date=payload["start_date"],
            end_date=payload["end_date"],
            requested_by=request.user,
            export_format=payload["export_format"],
            filters=payload.get("filters"),
        )
        log_audit(
            user=request.user,
            action="create",
            entity_type="report",
            entity_id=str(report.pk),
            metadata={"report_type": report.report_type},
        )
        output = ReportSerializer(report, context={"request": request})
        headers = self.get_success_headers(output.data)
        return Response(output.data, status=status.HTTP_201_CREATED, headers=headers)

    @action(detail=True, methods=["get"])
    def export(self, request, pk=None):
        report = self.get_object()
        response = {
            "format": report.export_format,
            "data": report.data,
            "download_url": f"/api/reports/{report.pk}/export/{report.export_format}",
        }
        return Response(response)
