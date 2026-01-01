from rest_framework.decorators import api_view, permission_classes, throttle_classes
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework import status


from django.contrib.auth import get_user_model
from django.shortcuts import get_object_or_404


from users.audit import log_event
from users.throttles import OrgInviteThrottle
from .utils import get_membership, require_role
from .permission import require_permission
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

    log_event(
        actor=request.user,
        action="org.create",
        resource_type="organisation",
        resource_id=org.id,
        request=request,
    )

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
    org = get_object_or_404(Organisation, slug=slug)
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
@throttle_classes([OrgInviteThrottle])
def invite_member_view(request, slug):
    org = get_object_or_404(Organisation, slug=slug)
    membership = get_membership(request.user, org)

    require_permission(membership, "member.invite")

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

    log_event(
        actor=request.user,
        action="org.member.invite",
        resource_type="membership",
        resource_id=user.id,
        metadata={"org": org.slug, "role": role},
        request=request,
    )

    return Response(
        {"detail": "Member invited"},
        status=status.HTTP_201_CREATED,
    )


@api_view(["PATCH"])
@permission_classes([IsAuthenticated])
def change_member_role_view(request, slug, member_id):
    org = get_object_or_404(Organisation, slug=slug)
    membership = get_membership(request.user, org)

    require_permission(membership, "member.role.change")

    member = get_object_or_404(
        Membership,
        id=member_id,
        organisation=org,
    )

    role = request.data.get("role")
    if role not in OrgRole.values:
        return Response({"error": "Invalid role"}, status=status.HTTP_400_BAD_REQUEST)

    member.role = role
    member.save(update_fields=["role"])

    log_event(
        actor=request.user,
        action="org.member.role_change",
        resource_type="membership",
        resource_id=member.id,
        metadata={"new_role": role},
        request=request,
    )

    return Response({"detail": "Role updated"})


@api_view(["DELETE"])
@permission_classes([IsAuthenticated])
def remove_member_view(request, slug, member_id):
    org = get_object_or_404(Organisation, slug=slug)
    membership = get_membership(request.user, org)

    require_permission(membership, "member.remove")

    member = get_object_or_404(
        Membership,
        id=member_id,
        organisation=org,
    )

    member.is_active = False
    member.save(update_fields=["is_active"])

    log_event(
        actor=request.user,
        action="org.member.remove",
        resource_type="membership",
        resource_id=member.id,
        request=request,
    )

    return Response({"detail": "Member removed"})