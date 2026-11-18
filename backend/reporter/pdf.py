"""Per-incident PDF report (end-to-end key details + forensic analysis)."""
from __future__ import annotations

import io
import re
from xml.sax.saxutils import escape

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle
from reporter.profiles import PLATFORM_PROFILES

_SEV_COLOR = {"low": "#2e7d32", "medium": "#f9a825", "high": "#ef6c00", "critical": "#c62828"}


def _inline(text: str) -> str:
    """Markdown **bold** / `code` -> reportlab markup, escaping everything else."""
    out = escape(text)
    out = re.sub(r"\*\*(.+?)\*\*", r"<b>\1</b>", out)
    return re.sub(r"`(.+?)`", r"<font face='Courier'>\1</font>", out)


def _fmt(dt) -> str:
    return dt.strftime("%Y-%m-%d %H:%M:%S UTC") if dt else "-"


def build_incident_pdf(inc) -> bytes:
    """`inc` is the IncidentDetailOut (or any object with the same attributes)."""
    ss = getSampleStyleSheet()
    h1 = ParagraphStyle("h1", parent=ss["Title"], fontSize=20, textColor=colors.HexColor("#1f3a5f"), alignment=0)
    h2 = ParagraphStyle("h2", parent=ss["Heading2"], textColor=colors.HexColor("#1f3a5f"), spaceBefore=12)
    body = ParagraphStyle("b", parent=ss["BodyText"], leading=14)
    small = ParagraphStyle("s", parent=body, fontSize=7.5, leading=9)

    buf = io.BytesIO()
    doc = SimpleDocTemplate(buf, pagesize=A4, leftMargin=16 * mm, rightMargin=16 * mm,
                            topMargin=16 * mm, bottomMargin=16 * mm,
                            title=f"BreachTrace incident {inc.incident_id}")
    s: list = [Paragraph("BreachTrace - Incident Report", h1)]

    sev = (inc.overall_severity or "n/a")
    col = _SEV_COLOR.get(str(sev).lower(), "#555555")
    s.append(Paragraph(f"Overall severity: <font color='{col}'><b>{escape(str(sev)).upper()}</b></font>", body))

    rows = [
        ["Incident ID", inc.incident_id],
        ["Platform", (inc.platform or "aws").upper()],
        ["Credential", f"{inc.credential_type} ({inc.credential_hint})"],
        ["Principal", inc.principal_id or inc.access_key_id or "-"],
        ["Repository", inc.repo_url],
        ["Commit", inc.commit_hash or "-"],
        ["Estimated start", _fmt(inc.exposure_start)],
        ["Closure recorded", _fmt(inc.exposure_end) if inc.exposure_end else "Not confirmed"],
        ["Status", inc.status],
        ["Framework review", ", ".join({"owasp-nhi2": "OWASP NHI2", "gdpr-32-33": "GDPR", "pci-incident-response": "PCI DSS", "soc2-security": "SOC 2"}.get(f.get("id"), "Review") for f in getattr(inc, "compliance_review_flags", [])) or "Not assessed"],
    ]
    t = Table([[Paragraph(f"<b>{a}</b>", body), Paragraph(escape(str(b)), body)] for a, b in rows],
              colWidths=[38 * mm, 140 * mm])
    t.setStyle(TableStyle([("GRID", (0, 0), (-1, -1), 0.25, colors.lightgrey),
                           ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#f2f5f9")),
                           ("VALIGN", (0, 0), (-1, -1), "TOP")]))
    s += [Spacer(1, 6), t]
    s.append(Paragraph("The start is estimated from the detected commit. A recorded closure time does not independently establish provider-side revocation.", body))
    s.append(Paragraph("Framework review signals suggest areas for human review; they do not determine applicability, a breach, or compliance.", body))
    profile = PLATFORM_PROFILES.get((inc.platform or '').lower())
    if profile and profile.blind_spot:
        s.append(Paragraph(escape(profile.blind_spot), body))

    if inc.report_text:
        s.append(Paragraph("Forensic analysis", h2))
        if (inc.platform or '').lower() == 'gcp':
            s.append(Paragraph("Older reports may contain unsupported GCP cost estimates. Refresh logs to regenerate the report; Cloud Audit Logs do not establish billing charges or loss.", body))
        for line in inc.report_text.splitlines():
            line = line.strip()
            if not line:
                s.append(Spacer(1, 3))
            elif line.startswith("#"):
                s.append(Paragraph(_inline(line.lstrip("# ")), ss["Heading3"]))
            elif line[:2] in ("- ", "* "):
                s.append(Paragraph("&bull; " + _inline(line[2:]), body))
            else:
                s.append(Paragraph(_inline(line), body))

    if inc.remediation_steps:
        s.append(Paragraph("Remediation checklist", h2))
        for i, step in enumerate(inc.remediation_steps, 1):
            s.append(Paragraph(f"{i}. {_inline(step)}", body))

    if inc.financial_impact_lines:
        s.append(Paragraph("Financial impact", h2))
        for ln in inc.financial_impact_lines:
            s.append(Paragraph("&bull; " + _inline(ln.text), body))
    elif inc.estimated_financial_impact:
        s.append(Paragraph("Financial impact", h2))
        s.append(Paragraph(_inline(inc.estimated_financial_impact), body))

    s.append(Paragraph(f"Forensic timeline ({len(inc.events)} events)", h2))
    if inc.events:
        data = [["Time (UTC)", "Action", "Category", "Sev", "Source IP", "OK"]]
        for e in sorted(inc.events, key=lambda e: e.timestamp):
            data.append([Paragraph(e.timestamp.strftime("%m-%d %H:%M:%S"), small),
                         Paragraph(escape(e.api_action), small),
                         Paragraph(escape(e.impact_category or "-"), small),
                         str(e.severity_weight or "-"), Paragraph(escape(e.source_ip or "-"), small),
                         "Y" if e.success else "N"])
        tt = Table(data, repeatRows=1, colWidths=[24 * mm, 82 * mm, 30 * mm, 9 * mm, 26 * mm, 8 * mm])
        tt.setStyle(TableStyle([("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1f3a5f")),
                                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                                ("FONTSIZE", (0, 0), (-1, -1), 7.5),
                                ("GRID", (0, 0), (-1, -1), 0.25, colors.lightgrey),
                                ("VALIGN", (0, 0), (-1, -1), "TOP")]))
        s.append(tt)
    else:
        s.append(Paragraph(escape(getattr(inc, "unavailable_reason", None) or
                                  "No audit-log events were collected for this credential."), body))

    doc.build(s)
    return buf.getvalue()
