"""Create audit entries within the caller's database transaction.

Callers commit the action and its audit record together. Pass metadata only;
credential values and request bodies must never be included in audit details.
"""
from fastapi import Request
from sqlalchemy.orm import Session
from db.models import AuditLog, User


def record(db: Session, user: User, action: str, request: Request, *, project_id=None, incident_id=None, detail=None):
    db.add(AuditLog(organisation_id=user.organisation_id, actor_user_id=user.id,
                    project_id=project_id, incident_id=incident_id, action=action,
                    detail=detail, ip_address=request.client.host if request.client else None))


def public(entry: AuditLog, actor_name: str | None = None):
    return {'id': entry.id, 'actor_user_id': entry.actor_user_id, 'actor_name': actor_name,
            'project_id': entry.project_id, 'incident_id': entry.incident_id,
            'action': entry.action, 'detail': entry.detail, 'ip_address': entry.ip_address,
            'created_at': entry.created_at}
