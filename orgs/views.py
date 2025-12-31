from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework import status


from django.contrib.auth import get_user_model


from .utils import get_membership, require_role
from .models import Organisation, Membership, OrgRole
from .serializers import OrganisationCreateSerializer, OrganisationSerializer, InviteMemberSerializer, MembershipSerializer
User = get_user_model()

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


@api_view(["GET"])
@permission_classes([IsAuthenticated])
def list_members_view(request, slug):
    org = Organisation.objects.get(slug=slug)
    membership = get_membership(request.user, org)

    members = Membership.objects.filter(
        organisation=org,
        is_active=True,
    ).select_related("user")

    return Response(
        MembershipSerializer(members, many=True).data
    )


@api_view(["POST"])
@permission_classes([IsAuthenticated])
def invite_member_view(request, slug):
    org = Organisation.objects.get(slug=slug)
    membership = get_membership(request.user, org)

    require_role(membership, [OrgRole.OWNER, OrgRole.ADMIN])

    serializer = InviteMemberSerializer(data=request.data)
    serializer.is_valid(raise_exception=True)

    email = serializer.validated_data["email"]
    role = serializer.validated_data["role"]

    user, _ = User.objects.get_or_create(
        email=email,
        defaults={"name": email.split("@")[0]},
    )

    Membership.objects.update_or_create(
        user=user,
        organisation=org,
        defaults={"role": role, "is_active": True},
    )

    return Response(
        {"detail": "Member invited"},
        status=status.HTTP_201_CREATED,
    )


@api_view(["PATCH"])
@permission_classes([IsAuthenticated])
def change_member_role_view(request, slug, member_id):
    org = Organisation.objects.get(slug=slug)
    membership = get_membership(request.user, org)

    require_role(membership, [OrgRole.OWNER])

    member = Membership.objects.get(
        id=member_id,
        organisation=org,
    )

    role = request.data.get("role")
    if role not in OrgRole.values:
        return Response({"detail": "Invalid role"}, status=400)

    member.role = role
    member.save(update_fields=["role"])

    return Response({"detail": "Role updated"})


@api_view(["DELETE"])
@permission_classes([IsAuthenticated])
def remove_member_view(request, slug, member_id):
    org = Organisation.objects.get(slug=slug)
    membership = get_membership(request.user, org)

    require_role(membership, [OrgRole.OWNER])

    member = Membership.objects.get(
        id=member_id,
        organisation=org,
    )

    member.is_active = False
    member.save(update_fields=["is_active"])

    return Response({"detail": "Member removed"})