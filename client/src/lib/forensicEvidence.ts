import type { DynamicBlastRadius, ForensicEvent, IncidentRecord } from '@/types'

export function inExposureWindow(events: ForensicEvent[], start: string, end: string | null): ForensicEvent[] {
  const from = Date.parse(start), until = end ? Date.parse(end) : Infinity
  if (!Number.isFinite(from) || (end && !Number.isFinite(until))) return []
  return events.filter(event => { const timestamp = Date.parse(event.timestamp); return Number.isFinite(timestamp) && timestamp >= from && timestamp <= until })
}

/** Used only in synthetic preview, where the backend assessment is unavailable. */
export function previewBlastRadius(incident: IncidentRecord): DynamicBlastRadius {
  const events = inExposureWindow(incident.events, incident.exposure_start, incident.exposure_end)
  const successful = events.filter(event => event.success === true)
  const classified = successful.filter(event => event.impact_category && event.severity_weight != null)
  const categories = new Set(classified.map(event => event.impact_category))
  const max = Math.max(0, ...classified.map(event => event.severity_weight ?? 0))
  const severe = ['privilege_escalation', 'exfiltration', 'code_compromise'].some(category => categories.has(category))
  const severity = !classified.length || incident.forensic_tier === 2 ? null : severe || (categories.has('financial_abuse') && max >= 3) || max >= 4 ? 'CRITICAL' : categories.has('financial_abuse') || max === 3 ? 'HIGH' : max === 2 ? 'MEDIUM' : 'LOW'
  const platforms = [...new Set(events.map(event => event.platform || 'unknown'))].sort().map(platform => {
    const group = events.filter(event => (event.platform || 'unknown') === platform)
    const accepted = group.filter(event => event.success === true)
    const counts = (values: string[]) => Object.entries(values.reduce<Record<string, number>>((acc, value) => { acc[value] = (acc[value] ?? 0) + 1; return acc }, {})).sort(([a],[b]) => a.localeCompare(b))
    return { platform, event_count: group.length, successful_count: accepted.length, failed_count: group.filter(event => event.success === false).length, resource_count: new Set(accepted.map(event => event.affected_resource).filter(Boolean)).size, categories: counts(accepted.map(event => event.impact_category ?? 'unclassified')).map(([category,count]) => ({ category,count })), actions: counts(accepted.map(event => event.api_action).filter(Boolean)).map(([action,count]) => ({ action,count })) }
  })
  return { status: incident.forensic_tier === 2 ? 'unavailable' : ['detecting','collecting','classifying','scoring','reporting'].includes(incident.status) ? 'collecting' : incident.status === 'error' ? 'error' : events.length ? 'observed' : 'unavailable', severity, event_count: events.length, successful_count: successful.length, failed_count: events.filter(event => event.success === false).length, resource_count: new Set(successful.filter(event => event.affected_resource).map(event => JSON.stringify([event.platform, event.affected_resource]))).size, last_observed_at: events.length ? events.reduce((latest,event) => Date.parse(event.timestamp) > Date.parse(latest) ? event.timestamp : latest, events[0].timestamp) : null, platforms }
}
