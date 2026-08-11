// Pydantic schema mirror — keep in sync with backend/normalizer/schema.py

export interface ForensicEvent {
  event_id: string
  platform: string
  timestamp: string
  api_action: string
  event_source: string | null
  source_ip: string | null
  user_agent: string | null
  affected_resource: string | null
  resource_type: string | null
  success: boolean
  error_code: string | null
  raw_data: Record<string, unknown>
  impact_category: string | null
  severity_weight: 1 | 2 | 3 | 4 | null
  // GCP / Azure identity and location
  principal_id?: string | null
  location?: string | null
}

export interface IncidentRecord {
  incident_id: string
  credential_type: string
  credential_hint: string
  // Null for GCP/Azure/SaaS incidents — only AWS has an access key ID.
  access_key_id: string | null
  // Unified identity for non-AWS platforms: GCP service account email or Azure
  // client ID. Served by IncidentSummaryOut in backend/routers/incidents.py.
  principal_id: string | null
  gcp_project_id: string | null
  azure_tenant_id: string | null
  azure_subscription_id: string | null
  repo_url: string
  commit_hash: string
  exposure_start: string
  exposure_end: string | null
  status: 'detecting' | 'collecting' | 'classifying' | 'scoring' | 'reporting' | 'complete'
  events: ForensicEvent[]
  overall_severity: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL' | null
  report_text: string | null
  remediation_steps: string[]
  gdpr_flag: boolean
  estimated_financial_impact: string | null
  // Optional rather than required: the API always sends it, but incidents cached
  // from before the multi-platform fields shipped will not have it, and
  // lib/platform.ts falls back to deriving it from credential_type.
  platform?: string
  // Forensic tier. 1 = the platform has a queryable audit log, so the timeline
  // is a real reconstruction. 2 = detection only; there is nothing to query and
  // `unavailable_reason` says why.
  //
  // Optional for the same reason as `platform`: incidents cached from before
  // the field shipped omit it. Read it via `isForensicTier()` in lib/platform,
  // which defaults missing values to Tier 1 — never treat `undefined` as Tier 2,
  // that would hide a real timeline behind the unavailable panel.
  forensic_tier?: 1 | 2
  unavailable_reason?: string | null
  // Computed by the detail endpoint — may be absent on list responses
  pcidss_flag?: boolean
  soc2_flag?: boolean
  compliance_reasons?: string[]
}

// IncidentSummary matches the list endpoint response (no events/report fields)
export type IncidentSummary = Omit<IncidentRecord, 'events' | 'report_text' | 'remediation_steps' | 'estimated_financial_impact'> & {
  events?: ForensicEvent[]
  report_text?: string | null
  remediation_steps?: string[]
  estimated_financial_impact?: string | null
}
