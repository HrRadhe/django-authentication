from .models import AuditLog


def log_event(
    *,
    actor=None,
    action,
    resource_type,
    resource_id="",
    request=None,
    metadata=None,
):
    AuditLog.objects.create(
        actor=actor,
        action=action,
        resource_type=resource_type,
        resource_id=str(resource_id),
        metadata=metadata or {},
        ip_address=request.META.get("REMOTE_ADDR") if request else None,
        user_agent=request.META.get("HTTP_USER_AGENT", "") if request else "",
    )