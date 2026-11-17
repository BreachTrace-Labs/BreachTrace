"""Project authorisation shared by project-scoped endpoints."""
from fastapi import HTTPException
from sqlalchemy.orm import Session

from db.models import Project, ProjectMember, User


def assert_project_access(project_id: str, user: User, db: Session) -> Project:
    project = db.query(Project).filter_by(id=project_id, organisation_id=user.organisation_id, is_deleted=False).first()
    if project is None:
        raise HTTPException(404, "Project not found")
    if user.role in ("org_admin", "security_lead"):
        return project
    if user.role != "developer" or not db.query(ProjectMember.id).filter_by(project_id=project.id, user_id=user.id).first():
        raise HTTPException(403, "No access to this project")
    return project
