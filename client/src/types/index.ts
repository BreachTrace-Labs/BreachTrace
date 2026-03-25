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
}

export interface IncidentRecord {
  incident_id: string
  credential_type: string
  credential_hint: string
  access_key_id: string
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
}
