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
  principal_id: string | null
  location: string | null
  impact_category: string | null
  severity_weight: 1 | 2 | 3 | 4 | null
}

export type IncidentStatus =
  | 'detecting'
  | 'collecting'
  | 'classifying'
  | 'scoring'
  | 'reporting'
  | 'complete'
  | 'error'

export type IncidentSeverity = 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL' | null

export interface IncidentSummary {
  incident_id: string
  platform: string
  credential_type: string
  credential_hint: string
  access_key_id: string | null
  // Unified identity for non-AWS platforms: GCP service account email or Azure
  // client ID. Optional until the multi-platform API fields ship — see
  // IncidentSummaryOut in backend/routers/incidents.py.
  principal_id?: string | null
  gcp_project_id: string | null
  azure_tenant_id: string | null
  azure_subscription_id: string | null
  repo_url: string
  commit_hash: string | null
  exposure_start: string
  exposure_end: string | null
  status: IncidentStatus
  overall_severity: IncidentSeverity
  gdpr_flag: boolean
  created_at?: string
}

export interface IncidentRecord extends IncidentSummary {
  events: ForensicEvent[]
  report_text: string | null
  remediation_steps: string[]
  estimated_financial_impact: string | null
  // Computed by the detail endpoint — may be absent on list responses
  pcidss_flag?: boolean
  soc2_flag?: boolean
  compliance_reasons?: string[]
}
