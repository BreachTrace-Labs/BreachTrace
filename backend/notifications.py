"""Best-effort SMTP and Slack delivery for project notifications.

Webhook delivery and incident processing must not depend on third-party
notification services. All transport errors are deliberately logged without
request URLs, credentials, recipient addresses, or provider response bodies.
"""
from __future__ import annotations

import html
import logging
import os
import re
import smtplib
import ssl
from email.message import EmailMessage
from email.utils import formataddr, parseaddr
from urllib.parse import urlsplit

import httpx
from sqlalchemy.orm import Session

from crypto import decrypt_blob
from db.database import SessionLocal
from db.models import IncidentRecord, NotificationConfig, Project, User

logger = logging.getLogger(__name__)

SMTP_HOST = os.getenv("SMTP_HOST", "")
try:
    SMTP_PORT = int(os.getenv("SMTP_PORT", "587"))
except ValueError:
    SMTP_PORT = 0
SMTP_USER = os.getenv("SMTP_USER", "")
SMTP_PASSWORD = os.getenv("SMTP_PASSWORD", "")
SMTP_FROM = os.getenv("SMTP_FROM", "")
APP_URL = os.getenv("APP_URL", "http://localhost:5173").rstrip("/")

_SEVERITY = {1: "low", 2: "medium", 3: "high", 4: "critical"}
_RANK = {name: rank for rank, name in _SEVERITY.items()}
_COLOR = {"low": "#2e8540", "medium": "#e3a008", "high": "#d97706", "critical": "#c62828", "not assessed": "#64748b"}
_SAFE_SLACK_PATH = re.compile(r"^/(?:services|triggers)/[A-Za-z0-9_-]+(?:/[A-Za-z0-9_-]+){1,2}/?$")


def smtp_configured() -> bool:
    return bool(SMTP_HOST.strip() and SMTP_FROM.strip() and 1 <= SMTP_PORT <= 65535)


def _email_address(value: str) -> str:
    if not isinstance(value, str) or "\r" in value or "\n" in value:
        raise ValueError("Invalid email address")
    _, address = parseaddr(value)
    if not address or "@" not in address or address.startswith("@") or address.endswith("@"):
        raise ValueError("Invalid email address")
    return address


def _sender() -> tuple[str, str]:
    raw = SMTP_FROM
    if "\r" in raw or "\n" in raw:
        raise ValueError("Invalid SMTP sender")
    name, address = parseaddr(raw)
    return name, _email_address(address)


def send_email(to: str, subject: str, body_html: str, body_text: str | None = None) -> bool:
    """Send one HTML email over STARTTLS; return False if unavailable or failed."""
    if not smtp_configured():
        logger.info("Email notification skipped: SMTP is not configured")
        return False
    try:
        recipient = _email_address(to)
        if not subject or "\r" in subject or "\n" in subject:
            raise ValueError("Invalid email subject")
        from_name, from_address = _sender()
        message = EmailMessage()
        message["Subject"] = subject
        message["From"] = formataddr((from_name, from_address))
        message["To"] = recipient
        message.set_content(body_text or "This BreachTrace message contains HTML details.")
        message.add_alternative(body_html, subtype="html")
        with smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=15) as smtp:
            smtp.ehlo()
            smtp.starttls(context=ssl.create_default_context())
            smtp.ehlo()
            if SMTP_USER:
                smtp.login(SMTP_USER, SMTP_PASSWORD)
            smtp.send_message(message)
        return True
    except Exception as exc:
        logger.warning("Email notification delivery failed (%s)", type(exc).__name__)
        return False


def validate_slack_webhook(value: str) -> bool:
    try:
        parsed = urlsplit(value)
        return (
            parsed.scheme == "https"
            and parsed.hostname == "hooks.slack.com"
            and parsed.port in (None, 443)
            and parsed.username is None
            and parsed.password is None
            and parsed.query == ""
            and parsed.fragment == ""
            and bool(_SAFE_SLACK_PATH.fullmatch(parsed.path))
        )
    except (TypeError, ValueError):
        return False


def send_slack(webhook_url: str, message: dict) -> bool:
    """Post a Block Kit payload to a validated Slack incoming webhook."""
    if not validate_slack_webhook(webhook_url):
        logger.warning("Slack notification skipped: webhook URL is invalid")
        return False
    try:
        response = httpx.post(webhook_url, json=message, timeout=10, follow_redirects=False, trust_env=False)
        response.raise_for_status()
        return True
    except Exception as exc:
        logger.warning("Slack notification delivery failed (%s)", type(exc).__name__)
        return False


def _app_url() -> str:
    value = APP_URL
    parsed = urlsplit(value)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc or parsed.username or parsed.password:
        return "http://localhost:5173"
    return value.rstrip("/")


def _severity(incident: IncidentRecord) -> str:
    return _SEVERITY.get(incident.overall_severity, "not assessed")


def _incident_summary(incident: IncidentRecord, project: Project) -> tuple[str, str, str]:
    severity = _severity(incident)
    repo = incident.repo_url or project.github_repo_url
    link = f"{_app_url()}/incidents/{incident.incident_id}"
    return severity, repo, link


def _incident_html(incident: IncidentRecord, project: Project, severity: str, repo: str, link: str) -> str:
    assessment = "" if severity != "not assessed" else "<p>Forensic severity is not assessed yet because no score is available.</p>"
    return (
        "<h2>BreachTrace incident detected</h2>"
        f"<p><strong>Severity:</strong> {html.escape(severity.title())}</p>"
        f"<p><strong>Project:</strong> {html.escape(project.name)}</p>"
        f"<p><strong>Credential family:</strong> {html.escape(incident.credential_type)}</p>"
        f"<p><strong>Masked credential:</strong> {html.escape(incident.credential_hint)}</p>"
        f"<p><strong>Repository:</strong> {html.escape(repo)}</p>"
        f"<p><strong>Commit:</strong> {html.escape(incident.commit_hash or 'Unavailable')}</p>"
        f"{assessment}<p><a href=\"{html.escape(link, quote=True)}\">View incident in BreachTrace</a></p>"
    )


def _slack_payload(incident: IncidentRecord, project: Project, severity: str, repo: str, link: str) -> dict:
    color = _COLOR[severity]
    def safe(value: str) -> str:
        return value.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")[:250]

    text = f"{severity.title()} BreachTrace incident in {safe(project.name)}"
    fields = [
        {"type": "mrkdwn", "text": f"*Credential family:* {safe(incident.credential_type)}"},
        {"type": "mrkdwn", "text": f"*Masked credential:* {safe(incident.credential_hint)}"},
        {"type": "mrkdwn", "text": f"*Repository:* {safe(repo)}"},
        {"type": "mrkdwn", "text": f"*Commit:* {safe(incident.commit_hash or 'Unavailable')}"},
    ]
    if severity == "not assessed":
        fields.append({"type": "mrkdwn", "text": "*Severity:* Not assessed (no score available)"})
    return {
        "text": text,
        "attachments": [{"color": color, "blocks": [
            {"type": "header", "text": {"type": "plain_text", "text": text[:150]}},
            {"type": "section", "fields": fields[:10]},
            {"type": "actions", "elements": [{"type": "button", "text": {"type": "plain_text", "text": "View incident"}, "url": link}]},
        ]}],
    }


def notify_incident_created(incident: IncidentRecord, project: Project, db: Session) -> None:
    """Notify matching project channels after forensic processing completes.

    Severity thresholds use the persisted 1..4 score. If severity is absent,
    only `low` subscriptions receive an explicit "not assessed" notification;
    an unknown score is never represented as low severity.
    """
    severity = _severity(incident)
    rank = _RANK.get(severity)
    repo = incident.repo_url or project.github_repo_url
    link = f"{_app_url()}/incidents/{incident.incident_id}"
    configs = db.query(NotificationConfig).filter_by(project_id=project.id, enabled=True).all()
    for item in configs:
        threshold = _RANK.get(item.min_severity, 1)
        if (rank is not None and rank < threshold) or (rank is None and item.min_severity != "low"):
            continue
        try:
            if item.channel == "email":
                safe_project = re.sub(r"[\r\n]+", " ", project.name)[:120]
                subject = f"[BreachTrace] New {severity} incident in {safe_project}"
                plain = (f"Severity: {severity.title()}\nProject: {project.name}\n"
                         f"Credential family: {incident.credential_type}\nRepository: {repo}\n"
                         f"Commit: {incident.commit_hash or 'Unavailable'}\nIncident: {link}")
                send_email(item.target, subject, _incident_html(incident, project, severity, repo, link), plain)
            elif item.channel == "slack":
                iv, ciphertext = item.target.split(".", 1)
                webhook_url = decrypt_blob(ciphertext, iv)["url"]
                send_slack(webhook_url, _slack_payload(incident, project, severity, repo, link))
        except Exception as exc:
            logger.warning("Project notification failed (%s)", type(exc).__name__)


def notify_incident_created_by_id(incident_id: str) -> None:
    """Reload notification data in its own session for background task use."""
    db = SessionLocal()
    try:
        incident = db.get(IncidentRecord, incident_id)
        if incident is None or incident.project_id is None:
            return
        project = db.get(Project, incident.project_id)
        if project is not None:
            notify_incident_created(incident, project, db)
    except Exception as exc:
        logger.warning("Incident notification processing failed (%s)", type(exc).__name__)
    finally:
        db.close()


def notify_incident_assigned(incident: IncidentRecord, assigned_user: User) -> bool:
    """Send the assignee a summary with a link to the incident."""
    link = f"{_app_url()}/incidents/{incident.incident_id}"
    severity = _severity(incident)
    subject = "[BreachTrace] Incident assigned to you"
    safe_name = html.escape(assigned_user.full_name or assigned_user.email)
    body = (f"<p>Hello {safe_name},</p><p>An incident has been assigned to you.</p>"
            f"<p><strong>Severity:</strong> {html.escape(severity.title())}</p>"
            f"<p><strong>Credential family:</strong> {html.escape(incident.credential_type)}</p>"
            f"<p><strong>Repository:</strong> {html.escape(incident.repo_url)}</p>"
            f"<p><strong>Commit:</strong> {html.escape(incident.commit_hash or 'Unavailable')}</p>"
            f"<p><a href=\"{html.escape(link, quote=True)}\">View incident</a></p>")
    return send_email(assigned_user.email, subject, body)


def notify_incident_assigned_by_id(incident_id: str, assigned_user_id: str) -> None:
    db = SessionLocal()
    try:
        incident = db.get(IncidentRecord, incident_id)
        user = db.get(User, assigned_user_id)
        if incident is not None and user is not None and user.is_active:
            notify_incident_assigned(incident, user)
    except Exception as exc:
        logger.warning("Assignment notification failed (%s)", type(exc).__name__)
    finally:
        db.close()


def send_welcome_email(user: User, temporary_password: str, org_name: str, app_url: str | None = None) -> bool:
    """Deliver the invited user's one-time temporary password over SMTP."""
    app_url = app_url or _app_url()
    parsed = urlsplit(app_url)
    safe_url = app_url.rstrip("/") if parsed.scheme in {"http", "https"} and parsed.netloc and not parsed.username and not parsed.password else _app_url()
    name = html.escape(user.full_name or user.email)
    body = (
        f"<p>Hello {name},</p><p>Your BreachTrace account for {html.escape(org_name)} is ready.</p>"
        f"<p><strong>Email:</strong> {html.escape(user.email)}</p>"
        f"<p><strong>Temporary password:</strong> {html.escape(temporary_password)}</p>"
        f"<p><a href=\"{html.escape(safe_url, quote=True)}\">Open BreachTrace</a></p>"
        "<p>Change your password immediately after signing in. This temporary password is for first sign-in only.</p>"
    )
    plain = (f"Your BreachTrace account for {org_name} is ready.\nEmail: {user.email}\n"
             f"Temporary password: {temporary_password}\nSign in: {safe_url}\n"
             "Change your password immediately after signing in.")
    return send_email(user.email, f"Your BreachTrace account for {org_name}", body, plain)
