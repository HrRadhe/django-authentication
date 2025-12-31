from rest_framework import serializers
from .models import Organisation, Membership


class OrganisationCreateSerializer(serializers.Serializer):
    name = serializers.CharField(max_length=255)

    def create(self, validated_data):
        user = self.context["request"].user

        org = Organisation.objects.create(
            name=validated_data["name"],
            owner=user,
        )

        Membership.objects.create(
            user=user,
            organisation=org,
            role="OWNER",
        )

        return org


class OrganisationSerializer(serializers.ModelSerializer):
    class Meta:
        model = Organisation
        fields = ("id", "name", "slug", "created_at")