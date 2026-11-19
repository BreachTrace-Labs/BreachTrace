"""Schedule existing incident collectors using organisation-scoped settings."""
from datetime import datetime, timezone

from fastapi import BackgroundTasks, HTTPException

from db.database import SessionLocal
from db.models import BackgroundJob, IncidentRecord, Project


def schedule_one_incident(incident_id: str) -> dict:
    from routers.incidents import _queue_incident_refresh
    result = {'last_run_at': datetime.now(timezone.utc).isoformat(), 'queued': 0, 'skipped': 0}
    with SessionLocal() as db:
        schedule = db.query(BackgroundJob).filter_by(dedupe_key=f'incident-auto:{incident_id}').first()
        incident = db.get(IncidentRecord, incident_id)
        if not schedule or not schedule.payload.get('enabled'):
            return result
        project = db.get(Project, incident.project_id) if incident and incident.project_id else None
        if not incident or not incident.is_forensic_tier or not project or project.is_deleted:
            result.update(skipped=1, reason='Incident or project is unavailable for collection.')
            return result
        try:
            _queue_incident_refresh(incident_id, BackgroundTasks(), db)
            result['queued'] = 1
        except HTTPException as exc:
            db.rollback()
            result.update(skipped=1, reason=exc.detail if isinstance(exc.detail, str) else 'Refresh could not be queued.')
        except (KeyError, TypeError, ValueError):
            db.rollback()
            result.update(skipped=1, reason='Check the project provider connection.')
    return result


def migrate_legacy_schedules() -> None:
    """Preserve enabled organisation schedules as independently editable incident schedules."""
    from datetime import timedelta
    with SessionLocal() as db:
        old_jobs = (db.query(BackgroundJob).filter_by(kind='auto_refresh')
                    .with_for_update(skip_locked=True).all())
        for old in old_jobs:
            if not old.payload.get('enabled'):
                continue
            organisation_id = old.payload.get('organisation_id')
            interval = old.payload.get('interval_minutes', 60)
            if not organisation_id or not isinstance(interval, int) or not 15 <= interval <= 10080:
                continue
            rows = (db.query(IncidentRecord).join(Project, IncidentRecord.project_id == Project.id)
                    .filter(Project.organisation_id == organisation_id, Project.is_deleted.is_(False),
                            IncidentRecord.forensic_tier == 1).order_by(IncidentRecord.incident_id)
                    .with_for_update().all())
            for incident in rows:
                key = f'incident-auto:{incident.incident_id}'
                if db.query(BackgroundJob.id).filter_by(dedupe_key=key).first():
                    continue
                db.add(BackgroundJob(kind='incident_auto_refresh', dedupe_key=key, project_id=incident.project_id,
                    status='queued', payload={'incident_id': incident.incident_id, 'enabled': True, 'interval_minutes': interval},
                    available_at=old.available_at or datetime.now(timezone.utc) + timedelta(minutes=interval)))
            old.payload = {**old.payload, 'enabled': False, 'migrated_to_incidents': True}
            if old.status != 'running':
                old.status = 'complete'
        db.commit()


def schedule_incidents(organisation_id: str) -> dict:
    from routers.incidents import _queue_incident_refresh
    supported = {'aws', 'gcp', 'azure', 'stripe', 'twilio'}
    with SessionLocal() as db:
        ids = [row[0] for row in db.query(IncidentRecord.incident_id).join(
            Project, IncidentRecord.project_id == Project.id).filter(
            Project.organisation_id == organisation_id, Project.is_deleted.is_(False)).all()]
    queued = skipped = 0
    for incident_id in ids:
        with SessionLocal() as db:
            schedule = db.query(BackgroundJob).filter_by(dedupe_key=f'auto-refresh:{organisation_id}').first()
            if not schedule or not schedule.payload.get('enabled'):
                break
            incident = db.get(IncidentRecord, incident_id)
            if not incident or not incident.is_forensic_tier or incident.platform not in supported:
                skipped += 1
                continue
            try:
                _queue_incident_refresh(incident_id, BackgroundTasks(), db)
                queued += 1
            except (HTTPException, KeyError, TypeError, ValueError):
                db.rollback()
                skipped += 1
    return {'last_run_at': datetime.now(timezone.utc).isoformat(), 'queued': queued, 'skipped': skipped}
