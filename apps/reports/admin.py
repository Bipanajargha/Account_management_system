from django.contrib import admin

from .models import Report


@admin.register(Report)
class ReportAdmin(admin.ModelAdmin):
    list_display = (
        "id",
        "report_type",
        "start_date",
        "end_date",
        "requested_by",
        "export_format",
        "status",
    )
    list_filter = ("report_type", "export_format", "status")
    search_fields = ("report_type", "requested_by__username")
    date_hierarchy = "start_date"
