"""Read-only historical GCP evaluation; no incident or simulated leak is created."""
from collections import Counter
from datetime import datetime
from types import SimpleNamespace

from classifier.rules import classify_events
from collection_credentials import ReaderConfigurationError, project_reader
from collectors.gcp import GCPAuditLogCollector
from db.database import SessionLocal
from db.models import Project
from gcp_correlation import correlate_gcp_records
from gcp_reader import reader_project_id
from redaction import redact

MAX_RECORDS = 2000


def run(payload):
    with SessionLocal() as db:
        project = db.get(Project, payload['project_id'])
        if not project or project.is_deleted:
            raise ReaderConfigurationError('The selected project is no longer available.')
        reader = project_reader(db, SimpleNamespace(project_id=project.id), 'gcp')
        if reader_project_id(reader) != payload['gcp_project_id']:
            raise ReaderConfigurationError('The configured GCP reader belongs to a different project.')
    start = datetime.fromisoformat(payload['start_utc'])
    end = datetime.fromisoformat(payload['end_utc'])
    collector = GCPAuditLogCollector(reader=reader, max_events=MAX_RECORDS)
    try:
        events = collector.collect(payload['principal_email'], start, end)
    finally:
        close = getattr(collector._client, 'close', None)
        if close:
            close()
    return build_result(events, payload, source='live_collection')


def build_result(events, payload, *, source, extra=None):
    start = datetime.fromisoformat(payload['start_utc'])
    end = datetime.fromisoformat(payload['end_utc'])
    classify_events(events)
    categories = Counter(event.impact_category or 'unclassified' for event in events)
    methods = Counter(event.api_action for event in events)
    # The safe collector has already removed request and response bodies. Apply
    # the API redactor before storing research results in the job record.
    return redact({
        'mode': 'research_forensic_evaluation', 'scenario_id': payload['scenario_id'],
        'evidence_source': source,
        'gcp_project_id': payload['gcp_project_id'], 'principal_email': payload['principal_email'],
        'start_utc': start.isoformat(), 'end_utc': end.isoformat(),
        'record_count': len(events), 'successful_count': sum(e.success is True for e in events),
        'failed_count': sum(e.success is False for e in events),
        'categories': dict(sorted(categories.items())), 'methods': dict(sorted(methods.items())),
        'correlation': correlate_gcp_records(events),
        'events': [event.model_dump(mode='json') for event in events],
        'limitations': 'Historical principal-level research evidence; this does not establish a credential leak, key use or complete log coverage.',
        **(extra or {}),
    })
