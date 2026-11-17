"""Project authorisation shared by project-scoped endpoints."""
from fastapi import Depends, HTTPException
from sqlalchemy.orm import Session

from auth import get_active_user
from db.database import get_db
from db.models import IncidentRecord, Project, ProjectMember, User


def assert_project_access(project_id: str, user: User, db: Session) -> Project:
    project = db.query(Project).filter_by(id=project_id, organisation_id=user.organisation_id, is_deleted=False).first()
    if project is None:
        raise HTTPException(404, "Project not found")
    if user.role in ("org_admin", "security_lead"):
        return project
    if user.role != "developer" or not db.query(ProjectMember.id).filter_by(project_id=project.id, user_id=user.id).first():
        raise HTTPException(403, "No access to this project")
    return project


def accessible_project_ids(user: User, db: Session):
    query = db.query(Project.id).filter_by(organisation_id=user.organisation_id, is_deleted=False)
    if user.role == "developer":
        query = query.join(ProjectMember, ProjectMember.project_id == Project.id).filter(ProjectMember.user_id == user.id)
    elif user.role not in ("org_admin", "security_lead"):
        raise HTTPException(403, "Insufficient role")
    return query


def assert_incident_access(incident_id: str, user: User, db: Session) -> IncidentRecord:
    incident = db.get(IncidentRecord, incident_id)
    if incident is None or incident.project_id is None:
        raise HTTPException(404, "Incident not found")
    assert_project_access(incident.project_id, user, db)
    return incident


def incident_access(incident_id: str, user: User = Depends(get_active_user), db: Session = Depends(get_db)):
    return assert_incident_access(incident_id, user, db)
