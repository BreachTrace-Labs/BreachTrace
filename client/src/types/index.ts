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

/**
 * One costed finding on an incident. Mirrors `FinancialImpactLine` in
 * backend/scorer/severity.py.
 *
 * `actual` is the field that carries the weight: it is true only where money
 * demonstrably moved (Stripe transactions). Every other platform is an
 * order-of-magnitude estimate from public list prices, and the panel must not
 * present the two with the same confidence.
 */
export interface FinancialImpactLine {
  platform: string
  kind:
    | 'compute' | 'egress' | 'database' | 'cluster'
    | 'charge' | 'refund' | 'messaging' | 'number'
  /** Short vendor-facing name, e.g. 'EC2', 'Cloud Storage egress', 'Stripe'. */
  label: string
  /** The rendered sentence. Joining these reproduces estimated_financial_impact. */
  text: string
  /** Magnitude in major currency units (already converted from Stripe's cents). */
  amount: number | null
  /** ISO code — set only where the amount is real money. */
  currency: string | null
  /** Rate denominator, or null when the amount is a one-off total. */
  unit: 'hour' | 'day' | 'month' | null
  quantity: number | null
  actual: boolean
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
  // Structured view of estimated_financial_impact, served on the detail
  // endpoint only. Optional: an older backend omits it, and
  // FinancialImpactPanel falls back to rendering the string.
  financial_impact_lines?: FinancialImpactLine[]
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


/* ─── research experiments ─────────────────────────────────────── */

/** One recorded experiment run. Mirrors ExperimentRunOut in backend/routers/research.py. */
export interface ExperimentRun {
  run_id: string
  access_key_id: string | null
  detection_time_s: number | null
  report_time_s: number | null
  api_calls: string[]
  expected_severity: string | null
  actual_severity: string | null
  status: string | null
  created_at: string
  platform: string
  run_number?: number | null
  experiment_group?: string | null
  first_external_use_s?: number | null
  external_use_detected?: boolean
  event_count?: number
}

/**
 * Summary statistics for one metric. Mirrors `_summarize()` in
 * backend/research/analysis.py.
 *
 * Every field except `n` is null when there is no data — deliberately not 0.
 * A platform that recorded no timings must never appear as "0 seconds".
 */
export interface MetricSummary {
  n: number
  mean: number | null
  median: number | null
  p95: number | null
  min: number | null
  max: number | null
}

/** Per-platform breakdown. Mirrors `compare_platforms()`. */
export interface PlatformStats {
  total_runs: number
  completed_runs: number
  completion_rate: number
  detection_time_s: MetricSummary
  report_time_s: MetricSummary
  first_use_time_s: MetricSummary
  events_collected: MetricSummary
  severity_distribution: Record<string, number>
}

/** GET /research/platforms response. */
export interface PlatformComparison {
  total_runs: number
  by_platform: Record<string, PlatformStats>
  /** Platforms with no timing data are omitted entirely, never reported as 0. */
  detection_latency_by_platform: Record<string, number>
}
