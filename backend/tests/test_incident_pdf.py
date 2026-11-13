from datetime import datetime, timezone
from types import SimpleNamespace as NS

from reporter.pdf import build_incident_pdf


def test_pdf_renders_with_markdown_and_events():
    ev = NS(timestamp=datetime(2026, 1, 1, tzinfo=timezone.utc), api_action="A<b>", impact_category="data_access",
            severity_weight=4, source_ip="1.2.3.4", success=True)
    inc = NS(incident_id="abc12345", overall_severity="High", platform="azure", credential_type="azure_client_secret",
             credential_hint="2892****", principal_id=None, access_key_id=None, repo_url="r", commit_hash="c",
             exposure_start=datetime(2026, 1, 1, tzinfo=timezone.utc), exposure_end=None, status="complete",
             gdpr_flag=True, pcidss_flag=False, soc2_flag=False,
             report_text="# Summary\n**Bold** text & <tags>\n- item", remediation_steps=["rotate `secret`"],
             financial_impact_lines=[], estimated_financial_impact="~$1", events=[ev], unavailable_reason=None)
    pdf = build_incident_pdf(inc)
    assert pdf.startswith(b"%PDF") and len(pdf) > 1500
