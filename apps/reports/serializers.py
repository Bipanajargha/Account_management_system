from django.utils import timezone
from rest_framework import serializers

from .models import Report


class ReportSerializer(serializers.ModelSerializer):
    requested_by_username = serializers.CharField(
        source="requested_by.username",
        read_only=True,
    )

    class Meta:
        model = Report
        fields = [
            "id",
            "report_type",
            "start_date",
            "end_date",
            "requested_by",
            "requested_by_username",
            "generated_at",
            "export_format",
            "data",
            "filters",
            "status",
        ]
        read_only_fields = [
            "id",
            "generated_at",
            "requested_by_username",
            "data",
            "status",
        ]


class ReportCreateSerializer(serializers.Serializer):
    report_type = serializers.ChoiceField(choices=Report.TYPE_CHOICES)
    start_date = serializers.DateField()
    end_date = serializers.DateField()
    export_format = serializers.ChoiceField(
        choices=Report.FORMAT_CHOICES,
        default=Report.FORMAT_PDF,
    )
    filters = serializers.DictField(required=False)

    def validate(self, attrs):
        if attrs["start_date"] > attrs["end_date"]:
            raise serializers.ValidationError("Start date must be before end date.")
        if attrs["end_date"] > timezone.now().date():
            raise serializers.ValidationError("End date cannot be in the future.")
        return attrs


