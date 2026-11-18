"""Project management and membership."""
from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field, SecretStr, field_validator
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from access import assert_project_access
from auth import get_active_user, require_admin, require_admin_or_lead, require_single_organisation
from db.database import get_db
from db.models import BackgroundJob, IncidentRecord, NotificationConfig, Project, ProjectMember, User
from repository_snapshot import repository_name
from audit import record
from routers.org import user_data

router = APIRouter(prefix="/projects", tags=["projects"])

_NOTIFICATION_SEVERITIES = {"low", "medium", "high", "critical"}


class NotificationCreate(BaseModel):
    channel: str = Field(pattern="^(email|slack)$")
    target: str = Field(min_length=1, max_length=500)
    min_severity: str = "low"

    @field_validator("min_severity")
    @classmethod
    def valid_severity(cls, value):
        value = value.lower()
        if value not in _NOTIFICATION_SEVERITIES:
            raise ValueError("Choose low, medium, high, or critical")
        return value


class NotificationUpdate(BaseModel):
    target: str | None = Field(default=None, min_length=1, max_length=500)
    min_severity: str | None = None
    enabled: bool | None = None

    @field_validator("min_severity")
    @classmethod
    def valid_severity(cls, value):
        if value is None:
            return value
        value = value.lower()
        if value not in _NOTIFICATION_SEVERITIES:
            raise ValueError("Choose low, medium, high, or critical")
        return value


def _validate_notification_target(channel: str, target: str) -> str:
    target = target.strip()
    if channel == "email":
        from email.utils import parseaddr
        if "\r" in target or "\n" in target:
            raise HTTPException(422, "Enter a valid email address")
        _, address = parseaddr(target)
        if not address or "@" not in address or address.startswith("@") or address.endswith("@"):
            raise HTTPException(422, "Enter a valid email address")
        return address
    from notifications import validate_slack_webhook
    if not validate_slack_webhook(target):
        raise HTTPException(422, "Use a Slack incoming webhook URL from hooks.slack.com")
    return target


def _notification_data(item: NotificationConfig):
    return {"id": item.id, "channel": item.channel,
            "target": item.target if item.channel == "email" else None,
            "target_display": item.target if item.channel == "email" else "Slack webhook (encrypted)",
            "enabled": item.enabled, "min_severity": item.min_severity,
            "created_at": item.created_at}


class ProjectCreate(BaseModel):
    name: str = Field(min_length=1, max_length=120)
    github_repo_url: str = Field(max_length=300)

    @field_validator("github_repo_url")
    @classmethod
    def validate_repo(cls, value):
        repository_name(value)
        return value


class ProjectUpdate(BaseModel):
    name: str = Field(min_length=1, max_length=120)


class MemberCreate(BaseModel):
    user_id: str = Field(min_length=1, max_length=36)


def project_data(db: Session, project: Project):
    return {"id": project.id, "name": project.name, "github_repo_url": project.github_repo_url,
            "github_repo_full_name": project.github_repo_full_name, "webhook_registered_at": project.webhook_registered_at,
            "webhook_last_verified_at": project.webhook_last_verified_at,
            "created_at": project.created_at,
            "member_count": db.query(ProjectMember).filter_by(project_id=project.id).count(),
            "incident_count": db.query(IncidentRecord).filter_by(project_id=project.id).count()}


@router.get("")
def list_projects(user: User = Depends(get_active_user), db: Session = Depends(get_db)):
    query = db.query(Project).filter_by(organisation_id=user.organisation_id, is_deleted=False)
    if user.role == "developer":
        query = query.join(ProjectMember, ProjectMember.project_id == Project.id).filter(ProjectMember.user_id == user.id)
    elif user.role not in ("org_admin", "security_lead"):
        raise HTTPException(403, "Insufficient role")
    return [project_data(db, project) for project in query.order_by(Project.name).all()]


@router.post("", status_code=201)
def create_project(body: ProjectCreate, request: Request, user: User = Depends(require_admin_or_lead), db: Session = Depends(get_db)):
    name = body.name.strip()
    if not name:
        raise HTTPException(422, "Project name cannot be empty")
    repo_name = repository_name(body.github_repo_url).lower()
    project = Project(organisation_id=user.organisation_id, name=name, github_repo_url=f"https://github.com/{repo_name}",
                      github_repo_full_name=repo_name, created_by=user.id)
    db.add(project)
    try:
        db.flush()
        db.add(ProjectMember(project_id=project.id, user_id=user.id, granted_by=user.id))
        record(db, user, "project.created", request, project_id=project.id, detail={"repository": repo_name})
        db.commit()
    except IntegrityError:
        db.rollback()
        raise HTTPException(409, "A project for this repository already exists")
    return project_data(db, project)


@router.get("/{project_id}")
def get_project(project_id: str, user: User = Depends(get_active_user), db: Session = Depends(get_db)):
    return project_data(db, assert_project_access(project_id, user, db))


class GitHubConnectionInput(BaseModel):
    token: SecretStr = Field(min_length=20, max_length=300)


def github_connection_data(db, project_id):
    from db.models import ProjectGitHubConnection
    row = db.get(ProjectGitHubConnection, project_id)
    return {'configured': row is not None, 'updated_at': row.updated_at if row else None}


@router.get('/{project_id}/github-connection')
def get_github_connection(project_id: str, user: User = Depends(require_admin_or_lead), db: Session = Depends(get_db)):
    assert_project_access(project_id, user, db)
    return github_connection_data(db, project_id)


@router.put('/{project_id}/github-connection')
def save_github_connection(project_id: str, body: GitHubConnectionInput, request: Request,
                           user: User = Depends(require_admin_or_lead), db: Session = Depends(get_db)):
    from datetime import datetime, timezone
    from crypto import encrypt_blob
    from db.models import ProjectGitHubConnection
    assert_project_access(project_id, user, db)
    token = body.token.get_secret_value().strip()
    if len(token) < 20 or any(char.isspace() for char in token):
        raise HTTPException(422, 'Enter a valid GitHub access token without spaces')
    try:
        ciphertext, iv = encrypt_blob({'token': token})
    except Exception:
        raise HTTPException(503, 'Connection encryption is not configured') from None
    row = db.get(ProjectGitHubConnection, project_id)
    if row is None:
        row = ProjectGitHubConnection(project_id=project_id)
        db.add(row)
    row.encrypted_blob, row.iv = ciphertext, iv
    row.updated_by, row.updated_at = user.id, datetime.now(timezone.utc)
    record(db, user, 'project.github_connection_saved', request, project_id=project_id)
    db.commit()
    return github_connection_data(db, project_id)


@router.delete('/{project_id}/github-connection', status_code=204)
def remove_github_connection(project_id: str, request: Request,
                             user: User = Depends(require_admin_or_lead), db: Session = Depends(get_db)):
    from db.models import ProjectGitHubConnection
    assert_project_access(project_id, user, db)
    row = db.get(ProjectGitHubConnection, project_id)
    if row:
        db.delete(row)
        record(db, user, 'project.github_connection_removed', request, project_id=project_id)
        db.commit()


@router.get("/{project_id}/notifications")
def list_notifications(project_id: str, user: User = Depends(require_admin_or_lead), db: Session = Depends(get_db)):
    project = assert_project_access(project_id, user, db)
    from notifications import smtp_configured
    rows = db.query(NotificationConfig).filter_by(project_id=project.id).order_by(NotificationConfig.created_at).all()
    return {"items": [_notification_data(item) for item in rows], "smtp_configured": smtp_configured()}


@router.get('/{project_id}/notification-deliveries')
def notification_deliveries(project_id: str, user: User = Depends(require_admin_or_lead), db: Session = Depends(get_db)):
    assert_project_access(project_id, user, db)
    jobs = (db.query(BackgroundJob).filter_by(project_id=project_id, kind='notification')
            .order_by(BackgroundJob.created_at.desc()).limit(100).all())
    return [{'id': job.id, 'type': job.payload.get('type'), 'channel': job.payload.get('channel'),
             'incident_id': job.payload.get('incident_id'), 'status': job.status, 'attempts': job.attempts,
             'max_attempts': job.max_attempts, 'last_error': job.last_error, 'outcome': (job.result or {}).get('outcome'), 'created_at': job.created_at,
             'updated_at': job.updated_at} for job in jobs]


@router.post('/{project_id}/notification-deliveries/{job_id}/retry', status_code=202)
def retry_notification_delivery(project_id: str, job_id: str, request: Request,
                                user: User = Depends(require_admin_or_lead), db: Session = Depends(get_db)):
    from datetime import datetime, timezone
    assert_project_access(project_id, user, db)
    job = db.query(BackgroundJob).filter_by(id=job_id, project_id=project_id, kind='notification').with_for_update().first()
    if job is None:
        raise HTTPException(404, 'Delivery not found')
    if job.status != 'failed':
        raise HTTPException(409, 'Only failed deliveries can be retried')
    job.status, job.attempts, job.last_error = 'queued', 0, None
    job.available_at = datetime.now(timezone.utc)
    record(db, user, 'notification.retry_requested', request, project_id=project_id, detail={'delivery_id': job.id})
    db.commit()
    return {'status': 'queued'}


@router.post("/{project_id}/notifications", status_code=201)
def create_notification(project_id: str, body: NotificationCreate, request: Request,
                        user: User = Depends(require_admin_or_lead), db: Session = Depends(get_db)):
    project = assert_project_access(project_id, user, db)
    target = _validate_notification_target(body.channel, body.target)
    if body.channel == "slack":
        try:
            from crypto import encrypt_blob
            ciphertext, iv = encrypt_blob({"url": target})
            target = f"{iv}.{ciphertext}"
        except RuntimeError:
            raise HTTPException(503, "Configure wallet encryption before saving a Slack webhook") from None
    item = NotificationConfig(project_id=project.id, channel=body.channel, target=target,
                              enabled=True, min_severity=body.min_severity, created_by=user.id)
    db.add(item)
    db.flush()
    record(db, user, "notification.created", request, project_id=project.id,
           detail={"notification_id": item.id, "channel": item.channel, "min_severity": item.min_severity})
    db.commit()
    db.refresh(item)
    return _notification_data(item)


@router.put("/{project_id}/notifications/{notification_id}")
def update_notification(project_id: str, notification_id: str, body: NotificationUpdate, request: Request,
                        user: User = Depends(require_admin_or_lead), db: Session = Depends(get_db)):
    project = assert_project_access(project_id, user, db)
    item = db.query(NotificationConfig).filter_by(id=notification_id, project_id=project.id).first()
    if item is None:
        raise HTTPException(404, "Notification configuration not found")
    changes = body.model_dump(exclude_unset=True)
    if "target" in changes and changes["target"] is not None:
        target = _validate_notification_target(item.channel, changes["target"])
        if item.channel == "slack":
            from crypto import encrypt_blob
            try:
                ciphertext, iv = encrypt_blob({"url": target})
            except RuntimeError:
                raise HTTPException(503, "Configure wallet encryption before saving a Slack webhook") from None
            target = f"{iv}.{ciphertext}"
        item.target = target
    if "min_severity" in changes and changes["min_severity"] is not None:
        item.min_severity = changes["min_severity"]
    if "enabled" in changes and changes["enabled"] is not None:
        item.enabled = changes["enabled"]
    record(db, user, "notification.updated", request, project_id=project.id,
           detail={"notification_id": item.id, "enabled": item.enabled, "min_severity": item.min_severity})
    db.commit()
    db.refresh(item)
    return _notification_data(item)


@router.delete("/{project_id}/notifications/{notification_id}")
def delete_notification(project_id: str, notification_id: str, request: Request,
                        user: User = Depends(require_admin_or_lead), db: Session = Depends(get_db)):
    project = assert_project_access(project_id, user, db)
    item = db.query(NotificationConfig).filter_by(id=notification_id, project_id=project.id).first()
    if item is None:
        raise HTTPException(404, "Notification configuration not found")
    db.delete(item)
    record(db, user, "notification.deleted", request, project_id=project.id,
           detail={"notification_id": item.id, "channel": item.channel})
    db.commit()
    return {"message": "Notification configuration deleted"}


@router.put("/{project_id}")
def update_project(project_id: str, body: ProjectUpdate, request: Request, user: User = Depends(require_admin_or_lead), db: Session = Depends(get_db)):
    project = assert_project_access(project_id, user, db)
    if not body.name.strip():
        raise HTTPException(422, "Project name cannot be empty")
    project.name = body.name.strip()
    record(db, user, "project.updated", request, project_id=project.id)
    db.commit()
    return project_data(db, project)


@router.post("/{project_id}/adopt-legacy", dependencies=[Depends(require_single_organisation)])
def adopt_legacy_incidents(project_id: str, request: Request, user: User = Depends(require_admin), db: Session = Depends(get_db)):
    """Explicitly associate old, unassigned incidents matching this repository."""
    project = assert_project_access(project_id, user, db)
    count = 0
    for incident in db.query(IncidentRecord).filter(IncidentRecord.project_id.is_(None)).yield_per(200):
        try:
            matches = repository_name(incident.repo_url).lower() == project.github_repo_full_name.lower()
        except (ValueError, TypeError, AttributeError):
            matches = False
        if matches:
            incident.project_id = project.id
            count += 1
    record(db, user, "project.legacy_incidents_adopted", request, project_id=project.id, detail={"count": count})
    db.commit()
    return {"adopted": count}


@router.delete("/{project_id}")
def delete_project(project_id: str, request: Request, user: User = Depends(require_admin), db: Session = Depends(get_db)):
    project = assert_project_access(project_id, user, db)
    project.is_deleted = True
    record(db, user, "project.deleted", request, project_id=project.id)
    db.commit()
    return {"message": "Project deleted"}


@router.get("/{project_id}/members")
def list_members(project_id: str, user: User = Depends(require_admin_or_lead), db: Session = Depends(get_db)):
    project = assert_project_access(project_id, user, db)
    rows = db.query(User).join(ProjectMember, ProjectMember.user_id == User.id).filter(ProjectMember.project_id == project.id).order_by(User.email).all()
    return [user_data(row) for row in rows]


@router.get("/{project_id}/eligible-members")
def eligible_members(project_id: str, user: User = Depends(require_admin_or_lead), db: Session = Depends(get_db)):
    assert_project_access(project_id, user, db)
    rows = db.query(User).filter_by(organisation_id=user.organisation_id, is_active=True).order_by(User.email).all()
    return [{"id": row.id, "email": row.email, "full_name": row.full_name, "role": row.role} for row in rows]


@router.post("/{project_id}/members", status_code=201)
def add_member(project_id: str, body: MemberCreate, request: Request, user: User = Depends(require_admin_or_lead), db: Session = Depends(get_db)):
    project = assert_project_access(project_id, user, db)
    target = db.query(User).filter_by(id=body.user_id, organisation_id=user.organisation_id, is_active=True).first()
    if not target:
        raise HTTPException(404, "Active user not found")
    db.add(ProjectMember(project_id=project.id, user_id=target.id, granted_by=user.id))
    record(db, user, "project.member_added", request, project_id=project.id, detail={"user_id": target.id})
    try:
        db.commit()
    except IntegrityError:
        db.rollback()
        raise HTTPException(409, "User is already a project member")
    return {"message": "Member added"}


@router.delete("/{project_id}/members/{user_id}")
def remove_member(project_id: str, user_id: str, request: Request, user: User = Depends(require_admin_or_lead), db: Session = Depends(get_db)):
    project = assert_project_access(project_id, user, db)
    membership = db.query(ProjectMember).filter_by(project_id=project.id, user_id=user_id).first()
    if not membership:
        raise HTTPException(404, "Membership not found")
    db.delete(membership)
    record(db, user, "project.member_removed", request, project_id=project.id, detail={"user_id": user_id})
    db.commit()
    return {"message": "Member removed"}
