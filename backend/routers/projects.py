"""Project management and membership."""
from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field, field_validator
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from access import assert_project_access
from auth import get_active_user, require_admin, require_admin_or_lead, require_single_organisation
from db.database import get_db
from db.models import IncidentRecord, Project, ProjectMember, User
from repository_snapshot import repository_name
from routers.org import record, user_data

router = APIRouter(prefix="/projects", tags=["projects"])


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
