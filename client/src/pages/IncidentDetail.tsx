import { useEffect, useState } from 'react'
import { useParams, useNavigate } from 'react-router-dom'
import {
  ArrowLeft,
  AlertTriangle,
  Printer,
  ExternalLink,
  ShieldAlert,
  Scale,
  Building2,
  Activity,
  Clock3,
  GitCommitHorizontal,
  KeyRound,
  Fingerprint,
  Radio,
  RefreshCw,
  Timer,
  Loader2,
  Search as SearchIcon,
} from 'lucide-react'
import client from '@/api/client'
import type { IncidentRecord, ReportSource, SearchResult } from '@/types'
import SearchResults from '@/components/SearchResults'
import { derivePlatform, isForensicTier, PLATFORM_META, platformIdentity } from '@/lib/platform'
import SeverityBadge from '@/components/SeverityBadge'
import ForensicTimeline from '@/components/ForensicTimeline'
import ForensicsUnavailable from '@/components/ForensicsUnavailable'
import FinancialImpactPanel from '@/components/FinancialImpactPanel'
import BlastRadiusSummary from '@/components/BlastRadiusSummary'
import AffectedResources from '@/components/AffectedResources'
import SourceIPs from '@/components/SourceIPs'
import ReactMarkdown from 'react-markdown'
import RemediationChecklist from '@/components/RemediationChecklist'
import EventAnalytics from '@/components/EventAnalytics'
import { Button } from '@/components/ui/button'

/* ─── helpers ─────────────────────────────────────────────────── */

function fmtTime(ts: string) {
  const date = new Date(ts)
  if (Number.isNaN(date.getTime())) return '--'
  return date.toLocaleString('en-US', {
    year: 'numeric',
    month: 'short',
    day: 'numeric',
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
    hour12: false,
    timeZoneName: 'short',
  })
}

function duration(start: string, end: string | null) {
  const startMs = new Date(start).getTime()
  const endMs = end ? new Date(end).getTime() : Date.now()
  if (Number.isNaN(startMs) || Number.isNaN(endMs)) return '--'
  const diff = Math.floor((endMs - startMs) / 1000)
  const h = Math.floor(diff / 3600)
  const m = Math.floor((diff % 3600) / 60)
  const s = diff % 60
  return h > 0 ? `${h}h ${m}m ${s}s` : m > 0 ? `${m}m ${s}s` : `${s}s`
}

/* ─── markdown renderer ────────────────────────────────────────── */

/**
 * Who wrote the report prose. The facts, figures and checklist are computed in
 * code and identical whichever writer ran; only the wording differs.
 */
function ReportSourceBadge({ source }: { source?: ReportSource | null }) {
  if (!source) return null
  const label = {
    deterministic: 'Template',
    local_model: 'On-device model',
    gemini: 'Gemini',
  }[source]
  const title = {
    deterministic: 'Written from verified facts by a fixed template.',
    local_model: 'Written on this computer by the BreachTrace report model, and checked against the facts.',
    gemini: 'Written by Gemini, and checked against the facts.',
  }[source]
  return (
    <span
      title={title}
      className="ml-auto text-[10px] font-semibold uppercase tracking-wider border rounded-full px-2 py-0.5"
      style={{ borderColor: 'var(--color-border)', color: 'var(--color-muted-foreground)' }}
    >
      {label}
    </span>
  )
}

/** Search scoped to one incident: its report passages plus the knowledge base. */
function AskAboutIncident({ incidentId }: { incidentId: string }) {
  const [question, setQuestion] = useState('')
  const [result, setResult] = useState<SearchResult | null>(null)
  const [loading, setLoading] = useState(false)

  async function ask(q: string) {
    if (q.trim().length < 2) return
    setQuestion(q)
    setLoading(true)
    try {
      const { data } = await client.post<SearchResult>('/assistant/search', {
        question: q.trim(),
        incident_id: incidentId,
      })
      setResult(data)
    } catch {
      setResult(null)
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="bg-card border rounded-sm shadow-sm p-6 sm:p-8 space-y-4">
      <h2 className="text-lg font-semibold text-foreground flex items-center gap-2">
        <div className="p-1.5 bg-primary/10 text-primary rounded-sm">
          <SearchIcon size={18} />
        </div>
        Ask about this incident
      </h2>
      <form
        className="flex gap-2"
        onSubmit={(e) => {
          e.preventDefault()
          void ask(question)
        }}
      >
        <input
          value={question}
          onChange={(e) => setQuestion(e.target.value)}
          placeholder="e.g. how do I revoke this key?"
          maxLength={500}
          aria-label="Question about this incident"
          className="flex-1 h-9 px-3 text-sm border rounded-sm bg-transparent outline-none focus:ring-2"
          style={{ borderColor: 'var(--color-border)' }}
        />
        <Button type="submit" size="sm" disabled={loading || question.trim().length < 2}>
          {loading ? <Loader2 size={14} className="animate-spin" /> : 'Ask'}
        </Button>
      </form>
      {result && !loading && (
        <SearchResults result={result} showIncidents={false} onSuggestion={(q) => void ask(q)} />
      )}
    </div>
  )
}

function MarkdownReport({ text }: { text: string }) {
  return (
    <div className="space-y-2">
      <ReactMarkdown>{text}</ReactMarkdown>
    </div>
  )
}

/* ─── incident summary helpers ─────────────────────────────────── */

const STATUS_LABELS: Record<string, string> = {
  detecting:   'Detecting',
  collecting:  'Collecting',
  classifying: 'Classifying',
  scoring:     'Scoring',
  reporting:   'Reporting',
  complete:    'Complete',
  error:        'Needs Attention',
}

const PLATFORM_STYLES: Record<string, { label: string; className: string }> = {
  gcp:   { label: 'GCP',   className: 'bg-blue-500/10 text-blue-700 dark:text-blue-300 border-blue-500/20' },
  azure: { label: 'Azure', className: 'bg-teal-500/10 text-teal-700 dark:text-teal-300 border-teal-500/20' },
  aws:   { label: 'AWS',   className: 'bg-orange-500/10 text-orange-700 dark:text-orange-300 border-orange-500/20' },
}

function PlatformBadge({ platform }: { platform: string | undefined }) {
  if (!platform) return null
  const style = PLATFORM_STYLES[platform.toLowerCase()] ?? PLATFORM_STYLES.aws
  return (
    <span className={`inline-flex items-center px-2.5 py-1 rounded-sm border text-xs font-bold uppercase tracking-wide ${style.className}`}>
      {style.label}
    </span>
  )
}

type RefreshResponse = {
  incident_id: string
  status: IncidentRecord['status'] | string
  message: string
}

function StatusPill({ status }: { status: string }) {
  const complete = status === 'complete'
  const errored = status === 'error'

  return (
    <span
      className={`inline-flex items-center gap-2 rounded-sm border px-3 py-1.5 text-xs font-bold uppercase tracking-wider ${
        complete
          ? 'border-emerald-500/25 bg-emerald-500/10 text-emerald-700 dark:text-emerald-300'
          : errored
          ? 'border-red-500/25 bg-red-500/10 text-red-600 dark:text-red-400'
          : 'border-primary/20 bg-primary/10 text-primary'
      }`}
    >
      <span className={`h-2 w-2 rounded-full ${complete ? 'bg-emerald-500' : errored ? 'bg-red-500' : 'bg-primary animate-pulse'}`} />
      {complete ? 'Investigation Complete' : STATUS_LABELS[status] ?? status}
    </span>
  )
}

function SummaryTile({
  icon: Icon,
  label,
  children,
  accent = false,
}: {
  icon: React.ElementType
  label: string
  children: React.ReactNode
  accent?: boolean
}) {
  return (
    <div className="min-w-0 rounded-sm border bg-background/70 p-4 shadow-sm">
      <div className="flex items-center gap-2 text-xs font-bold uppercase tracking-wider text-muted-foreground">
        <span className={`inline-flex h-6 w-6 items-center justify-center rounded-sm ${accent ? 'bg-red-500/10 text-red-600 dark:text-red-400' : 'bg-muted text-foreground'}`}>
          <Icon size={14} />
        </span>
        {label}
      </div>
      <div className="mt-3 min-w-0 text-sm font-medium text-foreground">
        {children}
      </div>
    </div>
  )
}

/* ─── component ────────────────────────────────────────────────── */

const IncidentDetail: React.FC = () => {
  const { id } = useParams<{ id: string }>()
  const navigate = useNavigate()
  const [incident, setIncident] = useState<IncidentRecord | null>(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [refreshing, setRefreshing] = useState(false)
  const [refreshNotice, setRefreshNotice] = useState<string | null>(null)

  useEffect(() => {
    if (!id) return
    const load = async () => {
      setLoading(true)
      setError(null)
      try {
        const { data } = await client.get<IncidentRecord>(`/incidents/${id}`)
        setIncident(data)
      } catch {
        setError('Incident not found or API unavailable.')
      } finally {
        setLoading(false)
      }
    }
    load()

    const poll = setInterval(() => {
      client
        .get<IncidentRecord>(`/incidents/${id}`)
        .then(({ data }) => setIncident(data))
        .catch(() => {})
    }, 3000)
    return () => clearInterval(poll)
  }, [id])

  const handleRefreshForensics = async () => {
    if (!id || refreshing) return
    setRefreshing(true)
    setRefreshNotice(null)
    try {
      const { data } = await client.post<RefreshResponse>(`/incidents/${id}/refresh`)
      setIncident((current) => current ? { ...current, status: 'collecting', events: [], report_text: null } : current)
      setRefreshNotice(data.message || 'Forensics refresh started.')

      const detail = await client.get<IncidentRecord>(`/incidents/${id}`)
      setIncident(detail.data)
    } catch {
      setRefreshNotice('Unable to start forensic refresh. Check the backend logs and try again.')
    } finally {
      setRefreshing(false)
    }
  }

  if (loading) {
    return (
      <div className="flex items-center justify-center min-h-[60vh]">
        <div className="flex flex-col items-center gap-4">
          <div className="w-8 h-8 border-4 rounded-full border-muted-foreground/20 border-t-primary animate-spin" />
          <p className="text-sm font-medium text-muted-foreground animate-pulse">Loading incident details...</p>
        </div>
      </div>
    )
  }

  if (error || !incident) {
    return (
      <div className="max-w-2xl mx-auto mt-12 space-y-6">
        <Button variant="ghost" size="sm" onClick={() => navigate('/')} className="hover:bg-accent -ml-3">
          <ArrowLeft size={16} className="mr-2" />
          Back to Dashboard
        </Button>
        <div className="p-12 text-center bg-card border rounded-sm shadow-sm">
          <AlertTriangle size={48} className="mx-auto mb-4 text-muted-foreground opacity-50" />
          <h3 className="text-lg font-semibold text-foreground mb-1">Incident Not Found</h3>
          <p className="text-sm text-muted-foreground">{error ?? 'The incident you are looking for does not exist or has been removed.'}</p>
        </div>
      </div>
    )
  }

  const dur = duration(incident.exposure_start, incident.exposure_end)
  const repoDisplay = incident.repo_url.replace('https://github.com/', '')
  const platform = derivePlatform(incident)
  const platformMeta = PLATFORM_META[platform]
  const identity = platformIdentity(incident, incident.events ?? [])

  return (
    <div className="max-w-7xl mx-auto space-y-8 pb-12 animate-in fade-in duration-500">
      {/* Top Header Section */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 border-b pb-6">
        <div className="flex items-center gap-4">
          <Button variant="outline" size="icon" onClick={() => navigate('/')} className="rounded-sm shadow-sm">
             <ArrowLeft size={18} />
          </Button>
          <div>
            <h1 className="text-2xl font-bold tracking-tight text-foreground flex items-center gap-3">
              Incident Detail
              <SeverityBadge severity={incident.overall_severity} />
            </h1>
            <p className="text-sm text-muted-foreground mt-1 flex items-center gap-2">
              <span className="font-mono bg-muted px-2 py-0.5 rounded text-xs">{id}</span>
            </p>
          </div>
        </div>
        
        <div className="flex flex-wrap items-center gap-3">
          <StatusPill status={incident.status} />
          <Button
            variant="outline"
            className="shadow-sm bg-background rounded-sm"
            onClick={handleRefreshForensics}
            disabled={refreshing}
          >
            <RefreshCw size={16} className={`mr-2 ${refreshing ? 'animate-spin' : ''}`} />
            {refreshing ? 'Refreshing...' : 'Refresh Logs'}
          </Button>
          <Button variant="outline" className="shadow-sm bg-background hidden sm:flex rounded-sm" onClick={() => window.print()}>
            <Printer size={16} className="mr-2" /> Export PDF
          </Button>
        </div>
      </div>

      {/* Main Content Grid */}
      <div className="grid grid-cols-1 xl:grid-cols-12 gap-8">
        
        {/* Left Column (Main Info) */}
        <div className="xl:col-span-8 space-y-8">
          
          {/* Overview Card */}
          <div className="bg-card border rounded-sm shadow-sm overflow-hidden">
            {refreshNotice && (
              <div className="border-b bg-primary/5 px-6 py-3 text-sm font-medium text-primary sm:px-8">
                {refreshNotice}
              </div>
            )}
            <div className="grid lg:grid-cols-[minmax(0,1fr)_320px]">
              <div className="p-6 sm:p-8">
                <div className="space-y-6">
                  <div>
                    <h2 className="text-sm font-semibold uppercase tracking-wider text-muted-foreground mb-1">Detected Credential</h2>
                    <p className="text-2xl sm:text-3xl font-mono font-bold tracking-tight text-foreground break-all">
                      {incident.credential_hint}
                    </p>
                  </div>
                  <div className="flex flex-wrap items-center gap-3 text-sm">
                    <span
                      className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-sm font-bold uppercase tracking-wider text-xs"
                      style={{
                        backgroundColor: `color-mix(in srgb, ${platformMeta.color} 14%, transparent)`,
                        color: platformMeta.color,
                      }}
                      title={`Forensic events collected from ${platformMeta.auditLog}`}
                    >
                      <span
                        className="w-1.5 h-1.5 rounded-full shrink-0"
                        style={{ backgroundColor: platformMeta.color }}
                      />
                      {platformMeta.label}
                    </span>
                    <span className="inline-flex items-center px-2.5 py-1 rounded-sm bg-secondary text-secondary-foreground font-medium">
                      {incident.credential_type}
                    </span>
                    <PlatformBadge platform={incident.platform} />
                    <span className="text-muted-foreground">•</span>
                    <a href={incident.repo_url} target="_blank" rel="noopener noreferrer" className="inline-flex items-center gap-1.5 text-primary hover:text-primary/80 hover:underline font-medium transition-colors">
                      {repoDisplay}
                      <ExternalLink size={14} />
                    </a>
                  </div>
                </div>
              </div>

              <div className="border-t bg-muted/30 p-6 sm:p-8 lg:border-l lg:border-t-0">
                <div className="flex items-center justify-between gap-3">
                  <p className="text-xs font-bold uppercase tracking-widest text-muted-foreground">Current State</p>
                  <StatusPill status={incident.status} />
                </div>

                <div className="mt-6 rounded-sm border bg-background p-5 shadow-sm">
                  <div className="flex items-center gap-3">
                    <span className="flex h-10 w-10 items-center justify-center rounded-sm bg-red-500/10 text-red-600 dark:text-red-400">
                      <Radio size={18} />
                    </span>
                    <div>
                      <p className="text-xs font-semibold uppercase tracking-wider text-muted-foreground">Exposure</p>
                      <p className="text-base font-bold text-foreground">
                        {incident.exposure_end ? 'Revoked' : <span className="text-red-500">Still Exposed</span>}
                      </p>
                    </div>
                  </div>
                  <div className="mt-5 border-t pt-4">
                    <p className="text-xs font-semibold uppercase tracking-wider text-muted-foreground">Duration</p>
                    <p className="mt-1 font-mono text-2xl font-bold tracking-tight text-foreground">{dur}</p>
                  </div>
                </div>
              </div>
            </div>

            {/* Stats Grid */}
            <div className="border-t bg-muted/20 p-4 sm:p-6">
              <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 xl:grid-cols-4">
                <SummaryTile icon={Clock3} label="Exposed">
                  {fmtTime(incident.exposure_start)}
                </SummaryTile>
                <SummaryTile icon={Timer} label="Revoked" accent={!incident.exposure_end}>
                  {incident.exposure_end ? fmtTime(incident.exposure_end) : <span className="font-semibold text-red-500 animate-pulse">Still Exposed</span>}
                </SummaryTile>
                <SummaryTile icon={GitCommitHorizontal} label="Commit">
                  <span className="font-mono">{incident.commit_hash ? incident.commit_hash.slice(0, 7) : '—'}</span>
                </SummaryTile>
                <SummaryTile icon={KeyRound} label="Credential Type">
                  <span className="break-words">{incident.credential_type}</span>
                </SummaryTile>
                {incident.principal_id && (
                  <SummaryTile icon={ShieldAlert} label="Identity">
                    <span className="font-mono break-all text-xs">{incident.principal_id}</span>
                  </SummaryTile>
                )}
              </div>

              {/* Leaked principal — named per platform. AWS reports an access key
                  ID, GCP a service account email, Azure a client ID; showing an
                  empty "Access Key ID" on a GCP incident reads as a bug. */}
              {identity && (
                <div className="mt-4">
                  <SummaryTile icon={Fingerprint} label={identity.label}>
                    <span className="font-mono text-xs break-all">{identity.value}</span>
                    {identity.context && (
                      <span className="mt-1 block text-xs font-normal text-muted-foreground">
                        {identity.context}
                      </span>
                    )}
                  </SummaryTile>
                </div>
              )}
            </div>
            
            {(incident.gdpr_flag || incident.pcidss_flag || incident.soc2_flag) && (
              <div className="border-t bg-orange-500/5 dark:bg-orange-500/10 border-orange-500/20 px-6 sm:px-8 py-5">
                <div className="flex items-center gap-2 mb-4">
                  <AlertTriangle className="text-orange-500" size={18} />
                  <h3 className="text-sm font-semibold text-orange-700 dark:text-orange-400">Compliance & Regulatory Impact</h3>
                </div>
                <div className="grid sm:grid-cols-3 gap-4">
                  {incident.gdpr_flag && (
                    <div className="bg-background rounded-sm p-3 border shadow-sm">
                      <div className="flex items-center gap-2 mb-1 text-orange-600 dark:text-orange-400">
                        <ShieldAlert size={14} />
                        <span className="text-xs font-bold uppercase">GDPR — Art. 33</span>
                      </div>
                      <p className="text-xs text-muted-foreground">Notify Data Protection Authority within 72h of confirming breach.</p>
                    </div>
                  )}
                  {incident.pcidss_flag && (
                    <div className="bg-background rounded-sm p-3 border shadow-sm">
                      <div className="flex items-center gap-2 mb-1 text-orange-600 dark:text-orange-400">
                        <Scale size={14} />
                        <span className="text-xs font-bold uppercase">PCI-DSS — Req 12</span>
                      </div>
                      <p className="text-xs text-muted-foreground">Notify acquiring bank and card brands immediately.</p>
                    </div>
                  )}
                  {incident.soc2_flag && (
                    <div className="bg-background rounded-sm p-3 border shadow-sm">
                      <div className="flex items-center gap-2 mb-1 text-orange-600 dark:text-orange-400">
                        <Building2 size={14} />
                        <span className="text-xs font-bold uppercase">SOC 2 — CC6/A1</span>
                      </div>
                      <p className="text-xs text-muted-foreground">Document in SOC 2 evidence records and inform auditor.</p>
                    </div>
                  )}
                </div>
                {incident.compliance_reasons && incident.compliance_reasons.length > 0 && (
                   <div className="mt-4 pt-3 border-t border-orange-500/10">
                    <ul className="list-inside list-disc space-y-1">
                      {incident.compliance_reasons.map((reason, i) => (
                        <li key={i} className="text-xs text-orange-700/80 dark:text-orange-300/80 pl-2">{reason}</li>
                      ))}
                    </ul>
                   </div>
                )}
              </div>
            )}
            
            {/* Financial impact moved to FinancialImpactPanel in the sidebar.
                It renders one figure per currency and separates money that
                actually moved from list-price estimates, which this raw string
                dump could not. Kept in one place so the two cannot disagree. */}
          </div>

          {/* AI Summary Report */}
          {incident.report_text && (
            <div className="bg-card border rounded-sm shadow-sm p-6 sm:p-8">
              <h2 className="text-lg font-semibold text-foreground mb-6 flex items-center gap-2">
                <div className="p-1.5 bg-primary/10 text-primary rounded-sm">
                   <AlertTriangle size={18} />
                </div>
                Incident Report
                <ReportSourceBadge source={incident.report_source} />
              </h2>
              <div className="prose prose-sm xl:prose-base dark:prose-invert max-w-none prose-p:leading-relaxed prose-headings:font-semibold">
                <MarkdownReport text={incident.report_text} />
              </div>
            </div>
          )}

          {incident.status === 'complete' && <AskAboutIncident incidentId={incident.incident_id} />}

          {/* Timeline, or an explanation of why there cannot be one.
              Tier-2 platforms expose no queryable audit log, so rendering an
              empty timeline would read as "nothing happened" when the truth is
              "this is unknowable". */}
          {isForensicTier(incident) ? (
            <div className="bg-card border rounded-sm shadow-sm p-6 sm:p-8">
                <h2 className="text-lg font-semibold text-foreground mb-6 flex items-center gap-2">
                  <div className="p-1.5 bg-primary/10 text-primary rounded-sm">
                     <Activity size={18} />
                  </div>
                  Forensic Timeline
                </h2>
               <ForensicTimeline events={incident.events} />
            </div>
          ) : (
            <ForensicsUnavailable incident={incident} />
          )}

        </div>

        {/* Right Column (Sidebar) */}
        <div className="xl:col-span-4 space-y-6">
          <div className="sticky top-6 space-y-6">
            {/* First in the stack: on a Stripe incident this is real money
                moved, which should not sit below three other cards. Self-hides
                when there is nothing to report. */}
            <FinancialImpactPanel incident={incident} />
            <BlastRadiusSummary incident={incident} />
            <SourceIPs events={incident.events} />
            <AffectedResources events={incident.events} />
            <RemediationChecklist steps={incident.remediation_steps} />
          </div>
        </div>

      </div>
      
      {/* Event Analytics */}
      {incident.events.length > 0 && (
         <div className="mt-8">
             <EventAnalytics events={incident.events} />
         </div>
      )}

    </div>
  )
}

export default IncidentDetail
