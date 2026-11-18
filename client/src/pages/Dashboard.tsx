import { useCallback, useEffect, useRef, useState } from 'react'
import { Link, useSearchParams } from 'react-router-dom'
import { ChevronRight, Filter, ShieldCheck } from 'lucide-react'
import client, { USE_MOCK } from '@/api/client'
import { useProjects } from '@/context/ProjectContext'
import { useAuth } from '@/context/AuthContext'
import type { IncidentSummary } from '@/types'
import { FORENSIC_PLATFORMS, PLATFORM_META, derivePlatform, isForensicTier } from '@/lib/platform'
import { filterIncident, isSyntheticIncident, type IncidentFilter } from '@/lib/incidentPresentation'
import { Button } from '@/components/ui/button'
import { ProviderIcon } from '@/components/ui/provider-icon'
import SeverityBadge from '@/components/SeverityBadge'
import SyntheticNotice from '@/components/SyntheticNotice'
import './dashboard.css'

const LIMIT = 500
const filters = ['all', ...FORENSIC_PLATFORMS, 'ai', 'other'] as const
const severities = ['all', 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW'] as const
function relativeTime(value: string) {
  const time = Date.parse(value)
  if (!Number.isFinite(time)) return 'Unknown time'
  const seconds = Math.round((time - Date.now()) / 1000)
  const [unit, divisor] = Math.abs(seconds) < 60 ? ['second', 1] : Math.abs(seconds) < 3600 ? ['minute', 60] : Math.abs(seconds) < 86400 ? ['hour', 3600] : ['day', 86400]
  return new Intl.RelativeTimeFormat(undefined, { numeric: 'auto' }).format(Math.round(seconds / divisor), unit as Intl.RelativeTimeFormatUnit)
}
function absoluteTime(value: string) { const date = new Date(value); return Number.isNaN(date.getTime()) ? 'Unknown time' : date.toLocaleString() }
function filterLabel(filter: IncidentFilter) { return filter === 'all' ? 'All' : filter === 'ai' ? 'AI keys' : filter === 'other' ? 'Other' : PLATFORM_META[filter].label }
function Stat({ label, value }: { label: string; value: string | number }) { return <div className="dashboard-stat"><span>{label}</span><strong>{value}</strong></div> }
function Skeletons() { return <div aria-label="Loading incidents" role="status" className="dashboard-list">{Array.from({length: 5}, (_, index) => <div className="dashboard-skeleton" key={index}><span/><span/><span/></div>)}</div> }
export default function Dashboard() {
  const { selected } = useProjects(); const { user } = useAuth(); const projectId = selected?.id
  const [incidents, setIncidents] = useState<IncidentSummary[]>([]); const [loading, setLoading] = useState(true); const [error, setError] = useState(''); const [showDismissed, setShowDismissed] = useState(false); const [severity, setSeverity] = useState<(typeof severities)[number]>('all'); const [params, setParams] = useSearchParams(); const generation = useRef(0)
  const requested = params.get('platform') ?? 'all'; const platform: IncidentFilter = filters.includes(requested as IncidentFilter) ? requested as IncidentFilter : 'all'
  const setPlatform = (value: IncidentFilter) => { const next = new URLSearchParams(params); if (value === 'all') next.delete('platform'); else next.set('platform', value); setParams(next) }
  const load = useCallback(async (initial = false) => {
    const current = ++generation.current
    if (initial) { setLoading(true); setIncidents([]) }
    if (!projectId && !USE_MOCK) { setLoading(false); setIncidents([]); setError(''); return }
    try { const { data } = await client.get<IncidentSummary[]>('/incidents', { params: { limit: LIMIT, ...(projectId ? { project_id: projectId } : {}) } }); if (generation.current === current) { setIncidents(data); setError('') } }
    catch { if (generation.current === current) setError('Could not load incidents. Check the connection and try again.') }
    finally { if (generation.current === current) setLoading(false) }
  }, [projectId])
  useEffect(() => { const requestGeneration = generation; void Promise.resolve().then(() => load(true)); const timer = window.setInterval(() => void load(), 30000); return () => { window.clearInterval(timer); requestGeneration.current++ } }, [load])
  const filtered = incidents.filter(i => (showDismissed || !i.dismissed) && filterIncident(i, platform) && (severity === 'all' || i.overall_severity === severity))
  const open = incidents.filter(i => !i.dismissed); const serious = open.filter(i => i.overall_severity === 'CRITICAL' || i.overall_severity === 'HIGH'); const latest = incidents.reduce<IncidentSummary | null>((a, b) => !a || Date.parse(b.exposure_start) > Date.parse(a.exposure_start) ? b : a, null)
  const clearFilters = () => { setPlatform('all'); setSeverity('all'); setShowDismissed(false) }
  return <div className="dashboard"><header className="dashboard-header"><div><h1>Dashboard</h1><p>Credential detections and available forensic evidence</p></div><Button variant="outline" size="sm" loading={loading} onClick={() => void load(true)}>Refresh</Button></header>
    {error && <div className="dashboard-error" role="alert">{error} <button onClick={() => void load(true)}>Retry</button></div>}
    <div className="dashboard-stats"><Stat label="Loaded incidents" value={loading ? '—' : incidents.length}/><Stat label="Open incidents" value={loading ? '—' : open.length}/><Stat label="Critical / High" value={loading ? '—' : serious.length}/><Stat label="Latest exposure" value={loading ? '—' : latest ? relativeTime(latest.exposure_start) : 'No incidents yet'}/></div>
    {!loading && incidents.length >= LIMIT && <p className="dashboard-note">Showing the latest {LIMIT} incidents. Counts and filters apply to these loaded records.</p>}
    {incidents.some(isSyntheticIncident) && <SyntheticNotice/>}
    <section><div className="dashboard-section-header"><div><h2>Incidents</h2><p>Processing completion does not confirm remediation or revocation.</p></div><label className="dashboard-toggle"><input type="checkbox" checked={showDismissed} onChange={e => setShowDismissed(e.target.checked)}/> Show dismissed</label></div>
      <div className="dashboard-filters"><div role="group" aria-label="Filter by provider">{filters.map(f => <button key={f} type="button" aria-pressed={platform === f} onClick={() => setPlatform(f)}>{filterLabel(f)}</button>)}</div><div role="group" aria-label="Filter by severity">{severities.map(s => <button key={s} type="button" aria-pressed={severity === s} onClick={() => setSeverity(s)}>{s === 'all' ? 'All severities' : s.toLowerCase()}</button>)}</div></div>
      {loading ? <Skeletons/> : error && incidents.length === 0 ? null : incidents.length === 0 ? <div className="dashboard-empty"><ShieldCheck size={28}/><h3>No incidents yet</h3><p>{selected ? `A qualifying credential in a push to ${selected.github_repo_full_name} can create an incident.` : 'Incidents will appear here when a monitored project receives a qualifying push.'}</p>{user?.role !== 'developer' && <Button asChild><Link to={selected ? '/connect' : '/onboarding'}>{selected ? 'Run a snapshot scan →' : 'Set up a project →'}</Link></Button>}</div> : filtered.length === 0 ? <div className="dashboard-empty"><Filter size={28}/><h3>No incidents match your filters</h3><Button variant="ghost" onClick={clearFilters}>Clear filters</Button></div> : <div className="dashboard-list">{filtered.map(incident => <Link className="dashboard-row" to={`/incidents/${incident.incident_id}`} key={incident.incident_id}><div className="dashboard-row-main"><div className="dashboard-row-meta">{incident.overall_severity ? <SeverityBadge severity={incident.overall_severity} showIcon={false}/> : <span className="dashboard-unassessed">Not assessed</span>}<ProviderIcon provider={derivePlatform(incident)}/>{!isForensicTier(incident) && <span className="dashboard-unassessed">Detection only</span>}{incident.dismissed && <span className="dashboard-unassessed">Dismissed</span>}{(incident.azure_repeat_count ?? 0) > 0 && <span className="dashboard-unassessed">⚠ Exposed again · {incident.azure_repeat_count}</span>}</div><strong>{incident.credential_type.replace(/_/g, ' ')}</strong><span className="dashboard-hint">{incident.credential_hint}</span></div><div className="dashboard-row-context"><span>{incident.repo_url.replace('https://github.com/', '')}</span><code>{incident.commit_hash?.slice(0, 8)}</code><time dateTime={incident.exposure_start} title={absoluteTime(incident.exposure_start)}>{relativeTime(incident.exposure_start)}</time>{incident.assigned_to_name && <span>Assigned to {incident.assigned_to_name}</span>}</div><ChevronRight size={17}/></Link>)}</div>}
    </section></div>
}
