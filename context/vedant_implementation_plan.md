# Vedant Implementation Plan (Week 2 Sprint)

Date: 2026-05-14
Owner: Vedant
Scope: Frontend dashboard, D3 timeline, Gemini report rendering, and schema alignment.

## Current Status (Snapshot)

Completed or in place:
- Frontend pages: Dashboard, Incident Detail, Research, Connect.
- UI components: Forensic timeline (D3), blast radius, severity badge, remediation checklist, affected resources, source IPs, analytics.
- API client with mock mode toggle.
- TypeScript types mirroring backend Pydantic schema.
- Gemini report generation backend hook present.

Pending or needs verification:
- Confirm API contract alignment for live backend responses.
- Validate error and refresh states across UI.
- Research page metrics wired to real backend data.

## Goals for Vedant

1) Ship a stable, demo-ready UI that accurately reflects pipeline status.
2) Ensure seamless integration with live backend endpoints (no mock data).
3) Verify report rendering, checklist parsing, and timeline visuals with real data.
4) Surface experiment metrics and stats on Research page when available.

## Implementation Plan

### Phase 1 - Contract and Data Validation (Day 1)
- Verify types and fields used by UI match backend responses:
  - Incident summary list
  - Incident detail + events
  - Research export and stats
- Align severity labels and statuses between backend and UI.
- Confirm endpoints used in the UI:
  - GET /incidents
  - GET /incidents/{id}
  - POST /incidents/{id}/refresh
  - GET /research/export
  - GET /incidents/stats

Deliverable: UI renders live data without TypeScript mismatches or runtime errors.

Status: Completed on 2026-05-14
Notes:
- Added summary vs detail incident typing and error status handling.
- Normalized severity badge casing and safer date formatting.
- Aligned Research page field optionality with backend responses.

### Phase 2 - UI Stability and Status Coverage (Day 2)
- Ensure all pipeline statuses show clearly in the Dashboard.
- Add or refine error state when incident status is "error".
- Verify refresh action flow on Incident Detail:
  - Buttons disabled while refresh in progress
  - Status updates reflect collecting state
  - Report text and events reset until refreshed

Deliverable: Stable, clear user feedback for each pipeline stage and refresh flow.

Status: Completed on 2026-05-15
Notes: All Error states display properly in the dashboard table. Implemented the Refresh Forensics functionality in the IncidentDetail component with polling and disabled button boundaries intact.

### Phase 3 - Report Rendering and Timeline Validation (Day 3)
- Verify Gemini report sections render correctly in Markdown display.
- Confirm remediation checklist parsing behaves for both:
  - Checkbox-based lists
  - Numbered lists
- Validate D3 timeline with real event payloads:
  - Event ordering
  - Category and severity colors
  - Tooltip content

Deliverable: Report and timeline look correct with real data.

Status: Completed on 2026-05-15
Notes: Implemented `react-markdown` setup on IncidentDetail report. Corrected checkbox checklist sanitization by employing regex to trim leading formatting symbols (1., [ ], -, *, ☐, ☑) in RemediationChecklist component mapping. Foreground timeline matches with appropriate mapping colors.

### Phase 4 - Research Page Integration (Day 4)
- Wire live data for Track A and Track B metrics.
- Add placeholder messaging if dataset is missing.
- Ensure research table rows render without empty fields.

Deliverable: Research page shows live experiment metrics and summaries.

Status: Completed on 2026-05-15
Notes: Complete. API integration verified locally and dashboard table operates stably with backend metrics on Track B (`/research/export` & `/incidents/stats`). Track A target visuals rendered stably as per instructions (`pytest` manual prompt).

### Phase 5 - Demo Polish (Day 5)
- Visual audit for spacing, typography, and hierarchy.
- Check mobile responsiveness for Dashboard and Incident Detail.
- Validate Connect page steps and webhook registration flow.

Deliverable: Demo-ready UI and reliable local flow.

Status: Completed on 2026-05-15
Notes: Developed and validated the Connect.tsx page logic with router to educate the user correctly concerning webhook setup and payload registration limits. Built and successfully passed typings with Vite compile execution!

## Dependencies on Others

### Ritwik
- Stable backend endpoints and response shapes:
  - /incidents list and detail
  - /incidents/{id}/refresh status transitions
  - /research/export and /incidents/stats
- Confirm pipeline writes report_text, remediation_steps, and severity values.

### Shashank
- Final taxonomy and severity mapping choices so UI labels remain consistent.
- Clarify any compliance flags to be surfaced on UI (GDPR, PCI-DSS, SOC2).

### Yash
- Classifier sets impact_category and severity_weight consistently for timeline.
- Research dataset and experiment runs available to validate Research page.

## Risks and Mitigations

- Risk: Backend response fields change late.
  - Mitigation: Add a single mapping layer in UI to normalize backend outputs.

- Risk: CloudTrail delay yields empty timelines during demo.
  - Mitigation: Use refresh flow and show "Awaiting events" states clearly.

- Risk: Gemini failures produce empty report.
  - Mitigation: Display fallback report text or explanatory placeholder.

## Acceptance Checklist

- Dashboard lists incidents with status, severity, and timestamps.
- Incident Detail shows timeline, blast radius, resources, IPs, and report text.
- Refresh button triggers collection and updates UI state.
- Research page loads experiment runs and summary stats.
- UI works with live backend and no mock data.
