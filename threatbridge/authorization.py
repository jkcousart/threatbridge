from __future__ import annotations

from collections.abc import Callable
from functools import wraps
from typing import Any, TypeVar

from django.contrib.auth.views import redirect_to_login
from django.core.exceptions import PermissionDenied
from django.http import HttpRequest, HttpResponse
from rest_framework.permissions import BasePermission


class Permissions:
    VIEW_INTEGRATIONS = "integrations.view_integration"
    CONFIGURE_INTEGRATIONS = "integrations.configure_integration"
    TEST_INTEGRATIONS = "integrations.test_integration"
    SYNCHRONIZE_INTEGRATIONS = "integrations.synchronize_integration"
    IMPORT_SOURCE_FILES = "integrations.import_source_file"
    RUN_ASSESSMENTS = "catalog.run_assessment"
    REVIEW_ATTACK_MAPPINGS = "catalog.review_attack_mapping"
    VIEW_RESTRICTED_SOURCE_EVIDENCE = "integrations.view_restricted_source_evidence"
    VIEW_DELETED_SOURCE_EVIDENCE = "integrations.view_deleted_source_evidence"
    DELETE_SOURCE_EVIDENCE = "integrations.delete_source_evidence"
    RESTORE_DELETED_SOURCE_EVIDENCE = "integrations.restore_deleted_source_evidence"
    ADMINISTER_SECURITY_CONFIGURATION = "catalog.administer_security_configuration"
    VIEW_SECURITY_AUDIT_EVENTS = "catalog.view_securityauditevent"


def is_allowed(actor: Any, permission: str) -> bool:
    return bool(
        actor
        and getattr(actor, "is_authenticated", False)
        and getattr(actor, "is_active", False)
        and (getattr(actor, "is_superuser", False) or actor.has_perm(permission))
    )


def require_permission(actor: Any, permission: str) -> None:
    if not is_allowed(actor, permission):
        raise PermissionDenied("You do not have permission to perform this operation.")


def require_operation_permission(
    actor: Any,
    permission: str,
    *,
    origin: str,
    system: bool = False,
) -> None:
    """Authorize a human actor or an explicitly identified management execution."""

    if system:
        if actor is not None or not str(origin).startswith("management:"):
            raise PermissionDenied("System execution requires a management-command origin.")
        return
    require_permission(actor, permission)


ViewFunction = TypeVar("ViewFunction", bound=Callable[..., HttpResponse])


def policy_required(permission: str) -> Callable[[ViewFunction], ViewFunction]:
    """Require a named application permission before resolving any target object."""

    def decorator(view: ViewFunction) -> ViewFunction:
        @wraps(view)
        def wrapped(request: HttpRequest, *args: Any, **kwargs: Any) -> HttpResponse:
            if not request.user.is_authenticated:
                return redirect_to_login(request.get_full_path())
            if not is_allowed(request.user, permission) and request.method not in {
                "GET",
                "HEAD",
                "OPTIONS",
            }:
                from catalog.services.audit import record_security_event

                record_security_event(
                    event_type="authorization.denied",
                    origin=f"browser:{view.__name__}",
                    outcome="denied",
                    actor=request.user,
                    target_type="permission",
                    target_identifier=permission,
                    metadata={"method": request.method},
                )
            require_permission(request.user, permission)
            return view(request, *args, **kwargs)

        return wrapped  # type: ignore[return-value]

    return decorator


class HasNamedPermission(BasePermission):
    """DRF permission driven by a view's centralized permission selection."""

    def has_permission(self, request, view) -> bool:
        required = view.get_required_permission()
        permissions = (
            tuple(required)
            if isinstance(required, (list, tuple, set))
            else (required,)
        )
        allowed = bool(
            all(permission and is_allowed(request.user, permission) for permission in permissions)
        )
        if not allowed and request.method not in {"GET", "HEAD", "OPTIONS"}:
            from catalog.services.audit import record_security_event

            record_security_event(
                event_type="authorization.denied",
                origin=f"rest:{view.__class__.__name__}",
                outcome="denied",
                actor=request.user,
                target_type="permission",
                target_identifier=",".join(
                    str(permission or "unspecified") for permission in permissions
                ),
                metadata={"method": request.method},
            )
        return allowed
