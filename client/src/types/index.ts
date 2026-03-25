// BreachTrace — Shared TypeScript types
// Mirrors the backend Pydantic schemas (normalizer/schema.py)

export type IncidentStatus =
  | "detecting"
  | "collecting"
  | "classifying"
  | "scoring"
  | "reporting"
  | "complete";

export type SeverityLevel = "Low" | "Medium" | "High" | "Critical";

export type ImpactCategory =
  | "reconnaissance"
  | "data_access"
  | "exfiltration"
  | "resource_abuse"
  | "privilege_escalation"
  | "financial_abuse"
  | "communication_abuse"
  | "code_compromise";

export interface ForensicEvent {
  event_id: string;
  incident_id: string;
  platform: string;
  timestamp: string;
  api_action: string;
  event_source: string;
  source_ip: string | null;
  user_agent: string | null;
  affected_resource: string | null;
  resource_type: string | null;
  success: boolean;
  error_code: string | null;
  impact_category: ImpactCategory | null;
  severity_weight: number | null;
  raw_data: Record<string, unknown>;
}

export interface IncidentRecord {
  incident_id: string;
  credential_type: string;
  credential_hint: string;
  access_key_id: string;
  repo_url: string;
  commit_hash: string;
  exposure_start: string;
  exposure_end: string | null;
  status: IncidentStatus;
  overall_severity: SeverityLevel | null;
  report_text: string | null;
  remediation_steps: string[];
  gdpr_flag: boolean;
  financial_impact: string | null;
  created_at: string;
  events?: ForensicEvent[];
}

export interface IncidentListItem {
  incident_id: string;
  credential_hint: string;
  credential_type: string;
  exposure_start: string;
  overall_severity: SeverityLevel | null;
  status: IncidentStatus;
  event_count: number;
}

export interface IncidentStats {
  total: number;
  by_severity: Record<SeverityLevel, number>;
  avg_detection_time_s: number;
  avg_report_time_s: number;
  top_categories: string[];
}

export interface CollectionStatus {
  id: string;
  incident_id: string;
  platform: string;
  status: "success" | "no_activity" | "error";
  event_count: number;
  error_message: string | null;
  queried_at: string;
}

export interface ExperimentRun {
  id: string;
  incident_id: string;
  run_number: number;
  experiment_group: "A" | "B" | "C";
  exposure_start: string;
  attacker_sim_start: string;
  detection_time_s: number;
  report_time_s: number;
  api_calls_made: string[];
  impact_categories: string[];
  overall_severity: SeverityLevel;
  external_use_detected: boolean;
  notes: string | null;
  created_at: string;
}

export interface HealthResponse {
  status: string;
  db: string;
  last_incident_at: string | null;
  environment: string;
}
