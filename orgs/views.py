from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework import status


from .models import Organisation, Membership
from .serializers import OrganisationCreateSerializer, OrganisationSerializer


@api_view(["POST"])
@permission_classes([IsAuthenticated])
def create_org_view(request):
    serializer = OrganisationCreateSerializer(
        data=request.data,
        context={"request": request},
    )
    serializer.is_valid(raise_exception=True)
    org = serializer.save()

    return Response(
        OrganisationSerializer(org).data,
        status=status.HTTP_201_CREATED,
    )


@api_view(["GET"])
@permission_classes([IsAuthenticated])
def my_orgs_view(request):
    orgs = Organisation.objects.filter(
        memberships__user=request.user,
        memberships__is_active=True,
    )

    return Response(
        OrganisationSerializer(orgs, many=True).data
    )