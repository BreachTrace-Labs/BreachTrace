import { AI_LABELS, derivePlatform, FORENSIC_PLATFORMS, isForensicTier, type Platform } from './platform'

type Incident = {
  platform?: string | null; credential_type?: string | null; forensic_tier?: number | null
  repo_url?: string; commit_hash?: string; status?: string
  exposure_start?: string | null; exposure_end?: string | null
  unavailable_reason?: string | null
}
export type IncidentFilter = Platform | 'all' | 'ai' | 'other'

export function isSyntheticIncident(incident: Incident): boolean {
  return !!incident.repo_url?.startsWith('local-test://') || !!incident.commit_hash?.startsWith('synthetic-')
}

export function isAIIncident(incident: Incident): boolean {
  return Object.hasOwn(AI_LABELS, derivePlatform(incident))
}

export function filterIncident(incident: Incident, filter: IncidentFilter): boolean {
  if (filter === 'all') return true
  if (filter === 'ai') return isAIIncident(incident)
  const platform = derivePlatform(incident)
  if (filter === 'other') return !isAIIncident(incident) && !FORENSIC_PLATFORMS.includes(platform)
  return platform === filter
}

export function completeLabel(incident: Incident): string {
  return isForensicTier(incident) ? 'Analysis complete' : 'Detection complete'
}

export function exposureLabel(incident: Incident): string {
  if (isSyntheticIncident(incident)) return 'Demo credential'
  if (incident.unavailable_reason?.startsWith('Snapshot observation:')) return 'Exposure start unknown'
  return incident.exposure_end ? 'Closure recorded' : 'Closure not confirmed'
}

export function exposureDuration(incident: Incident): string {
  if (isSyntheticIncident(incident)) return 'Demo'
  if (!incident.exposure_start || !incident.exposure_end) return 'Not confirmed'
  const start = Date.parse(incident.exposure_start), end = Date.parse(incident.exposure_end)
  if (!Number.isFinite(start) || !Number.isFinite(end) || end < start) return 'Invalid timestamps'
  const seconds = Math.floor((end - start) / 1000)
  const hours = Math.floor(seconds / 3600), minutes = Math.floor((seconds % 3600) / 60)
  return hours ? `${hours}h ${minutes}m ${seconds % 60}s` : minutes ? `${minutes}m ${seconds % 60}s` : `${seconds}s`
}

export function repositoryLink(url: string): string | null {
  try {
    const parsed = new URL(url)
    return ['https:', 'http:'].includes(parsed.protocol) && !parsed.username && !parsed.password ? parsed.href : null
  } catch { return null }
}
