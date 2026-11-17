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
import client, { USE_MOCK } from '@/api/client'
import { useAuth } from '@/context/AuthContext'
import IncidentActions from '@/components/IncidentActions'
import type { IncidentRecord, ReportSource, SearchResult } from '@/types'
import SearchResults from '@/components/SearchResults'
import { derivePlatform, isForensicTier, PLATFORM_META, platformIdentity } from '@/lib/platform'
import { completeLabel, exposureDuration, exposureLabel, isSyntheticIncident, repositoryLink } from '@/lib/incidentPresentation'
import SyntheticNotice from '@/components/SyntheticNotice'
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
    openai: 'OpenAI',
    anthropic: 'Anthropic',
    ollama: 'Local Ollama model',
  }[source]
  const title = {
    deterministic: 'Written from verified facts by a fixed template.',
    local_model: 'Written on this computer by the BreachTrace report model, and checked against the facts.',
    gemini: 'Written by Gemini, and checked against the facts.',
    openai: 'Written by your selected OpenAI model, and checked against the facts.',
    anthropic: 'Written by your selected Anthropic model, and checked against the facts.',
    ollama: 'Written by your selected local Ollama model, and checked against the facts.',
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
  const [generateAnswer, setGenerateAnswer] = useState(false)
  const [result, setResult] = useState<SearchResult | null>(null)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState('')

  async function ask(q: string) {
    if (q.trim().length < 2) return
    setQuestion(q)
    setLoading(true)
    setError('')
    setResult(null)
    try {
      const { data } = await client.post<SearchResult>('/assistant/search', {
        question: q.trim(),
        incident_id: incidentId,
        generate_answer: generateAnswer,
      }, { timeout: generateAnswer ? 310_000 : 30_000 })
      setResult(data)
    } catch {
      setResult(null)
      setError('Search is unavailable. Check the backend connection and try again.')
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
      <label className="flex items-start gap-2 text-xs text-muted-foreground">
        <input type="checkbox" checked={generateAnswer} onChange={e => setGenerateAnswer(e.target.checked)} className="mt-0.5" />
        <span>Generate an answer from the retrieved evidence with the model selected in Settings. Cloud models receive the question and matching passages.</span>
      </label>
      {error && <p role="alert" className="text-sm text-destructive">{error}</p>}
      {result && !loading && (
        <SearchResults result={result} showIncidents={false} onSuggestion={(q) => void ask(q)} />
      )}
    </div>
  )
}

function MarkdownReport({ text }: { text: string }) {
  return (
    <div className="space-y-3 break-words [&_h2]:mt-5 [&_h2]:mb-2 [&_h2]:text-base [&_h2]:font-semibold [&_p]:text-sm [&_p]:leading-relaxed [&_ul]:list-disc [&_ul]:pl-5 [&_li]:text-sm [&_code]:break-all [&_code]:text-xs">
      <ReactMarkdown>{text}</ReactMarkdown>
    </div>
  )
}

/* ─── incident summary helpers ─────────────────────────────────── */

const STATUS_LABELS: Record<string, string> = {
  detecting: 'Detecting',
  collecting: 'Collecting',
  classifying: 'Classifying',
  scoring: 'Scoring',
  reporting: 'Reporting',
  complete: 'Complete',
  error: 'Needs Attention',
}

type RefreshResponse = {
  incident_id: string
  status: IncidentRecord['status'] | string
  message: string
}

function StatusPill({ incident }: { incident: IncidentRecord }) {
  const status = incident.status
  const complete = status === 'complete'
  const errored = status === 'error'

  return (
    <span
      className={`inline-flex items-center gap-2 rounded-sm border px-3 py-1.5 text-xs font-bold uppercase tracking-wider ${complete
          ? 'border-emerald-500/25 bg-emerald-500/10 text-emerald-700 dark:text-emerald-300'
          : errored
            ? 'border-red-500/25 bg-red-500/10 text-red-600 dark:text-red-400'
            : 'border-primary/20 bg-primary/10 text-primary'
        }`}
    >
      <span className={`h-2 w-2 rounded-full ${complete ? 'bg-emerald-500' : errored ? 'bg-red-500' : 'bg-primary animate-pulse'}`} />
      {complete ? completeLabel(incident) : STATUS_LABELS[status] ?? status}
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
  const { user } = useAuth()
  const canManage = user?.role !== 'developer'
  const { id } = useParams<{ id: string }>()
  const navigate = useNavigate()
  const [incident, setIncident] = useState<IncidentRecord | null>(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [refreshing, setRefreshing] = useState(false)
  const [refreshNotice, setRefreshNotice] = useState<string | null>(null)
  const [twilioAccount, setTwilioAccount] = useState('')
  const [azureClientId, setAzureClientId] = useState('')
  const [azureOwnershipConfirmed, setAzureOwnershipConfirmed] = useState(false)
  const incidentStatus = incident?.status

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

  }, [id])

  useEffect(() => {
    if (!id || !incidentStatus || ['complete', 'error'].includes(incidentStatus)) return
    const poll = setInterval(() => {
      client
        .get<IncidentRecord>(`/incidents/${id}`)
        .then(({ data }) => setIncident(data))
        .catch(() => { })
    }, 3000)
    return () => clearInterval(poll)
  }, [id, incidentStatus])

  const handleRefreshForensics = async () => {
    if (!id || refreshing) return
    if (incident?.credential_type === 'stripe_secret_key' && !window.confirm('Confirm that the Stripe reader key configured on the backend belongs to the same account as this exposed key. Continue?')) return
    setRefreshing(true)
    setRefreshNotice(null)
    try {
      const { data } = await client.post<RefreshResponse>(`/incidents/${id}/refresh`)
      setIncident((current) => current ? { ...current, status: 'collecting', events: [], report_text: null } : current)
      setRefreshNotice(data.message || 'Forensics refresh started.')

      const detail = await client.get<IncidentRecord>(`/incidents/${id}`)
      setIncident(detail.data)
    } catch (error) {
      const detail = (error as { response?: { data?: { detail?: unknown } } }).response?.data?.detail
      setRefreshNotice(typeof detail === 'string' ? detail : 'Unable to start forensic refresh. Check the backend logs and try again.')
    } finally {
      setRefreshing(false)
    }
  }

  const handleTwilioAccount = async () => {
    if (!id || refreshing) return
    setRefreshing(true)
    setRefreshNotice(null)
    try {
      await client.post(`/incidents/${id}/twilio-account`, { account_sid: twilioAccount.trim() })
      setRefreshNotice('Twilio account associated. Collection started.')
      const detail = await client.get<IncidentRecord>(`/incidents/${id}`)
      setIncident(detail.data)
    } catch {
      setRefreshNotice('Could not start collection. Check that the Account SID matches the configured Twilio reader account.')
    } finally {
      setRefreshing(false)
    }
  }

  const handleAzureApplication = async () => {
    if (!id || refreshing || !azureOwnershipConfirmed) return
    setRefreshing(true)
    setRefreshNotice(null)
    try {
      await client.post(`/incidents/${id}/azure-application`, { client_id: azureClientId.trim() })
      setRefreshNotice('Azure application associated. Activity Log collection started.')
      const detail = await client.get<IncidentRecord>(`/incidents/${id}`)
      setIncident(detail.data)
    } catch (error) {
      const detail = (error as { response?: { data?: { detail?: unknown } } }).response?.data?.detail
      setRefreshNotice(typeof detail === 'string' ? detail : 'Could not start collection. Check the application ID and Azure reader configuration.')
    } finally {
      setRefreshing(false)
    }
  }

  const downloadReport = async () => {
    if (!id) return
    try {
      const { data } = await client.get<Blob>(`/incidents/${id}/report.pdf`, { responseType: 'blob' })
      const url = URL.createObjectURL(data)
      const link = document.createElement('a')
      link.href = url; link.download = `breachtrace-${id}.pdf`; link.click()
      URL.revokeObjectURL(url)
    } catch { setRefreshNotice('Could not download the report. Please try again.') }
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
          <h3 className="text-lg font-semibold text-foreground mb-1">Incident unavailable</h3>
          <p className="text-sm text-muted-foreground">{error ?? 'The incident you are looking for does not exist or has been removed.'}</p>
        </div>
      </div>
    )
  }

  const dur = exposureDuration(incident)
  const synthetic = isSyntheticIncident(incident)
  const forensic = isForensicTier(incident)
  const repoLink = repositoryLink(incident.repo_url)
  const repoDisplay = incident.repo_url.replace('https://github.com/', '')
  const platform = derivePlatform(incident)
  const platformMeta = PLATFORM_META[platform]
  const identity = platformIdentity(incident, incident.events ?? [])
  const exposureTimestamp = new Date(incident.exposure_start).getTime()
  const exposureEvents = incident.events.filter(event => new Date(event.timestamp).getTime() >= exposureTimestamp)

  return (
    <div className="max-w-7xl mx-auto space-y-8 pb-12 animate-in fade-in duration-500">
      {synthetic && <SyntheticNotice />}
      <IncidentActions incident={incident} canManage={canManage} onChange={setIncident} />
      {/* Top Header Section */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 border-b pb-6">
        <div className="flex min-w-0 items-center gap-4">
          <Button variant="outline" size="icon" aria-label="Back to incident monitor" onClick={() => navigate('/')} className="rounded-sm shadow-sm">
            <ArrowLeft size={18} />
          </Button>
          <div className="min-w-0">
            <h1 className="text-2xl font-bold tracking-tight text-foreground flex flex-wrap items-center gap-3">
              Incident Detail
              <SeverityBadge severity={incident.overall_severity} />
              {!incident.overall_severity && <span className="rounded border px-2 py-1 text-xs font-medium text-muted-foreground">Severity not assessed</span>}
            </h1>
            <p className="text-sm text-muted-foreground mt-1 flex items-center gap-2">
              <span className="font-mono bg-muted px-2 py-0.5 rounded text-xs break-all">{id}</span>
            </p>
          </div>
        </div>

        <div className="flex flex-wrap items-center gap-3">
          <StatusPill incident={incident} />
          {canManage && forensic && !synthetic && !USE_MOCK && <Button
            variant="outline"
            className="shadow-sm bg-background rounded-sm"
            onClick={handleRefreshForensics}
            disabled={refreshing}
            title="Refresh available provider logs"
          >
            <RefreshCw size={16} className={`mr-2 ${refreshing ? 'animate-spin' : ''}`} />
            {refreshing ? 'Refreshing…' : 'Refresh logs'}
          </Button>}
          {!USE_MOCK && (
            <Button variant="outline" className="shadow-sm bg-background hidden sm:flex rounded-sm" onClick={() => void downloadReport()}>
              <Printer size={16} className="mr-2" /> Download PDF report
            </Button>
          )}
          <Button variant="outline" className="shadow-sm bg-background hidden sm:flex rounded-sm" onClick={() => window.print()}>
            <Printer size={16} className="mr-2" /> Print / save PDF
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
                      title={`Coverage: ${platformMeta.auditLog}`}
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
                    <span className="text-muted-foreground">•</span>
                    {repoLink ? <a href={repoLink} target="_blank" rel="noopener noreferrer" className="inline-flex items-center gap-1.5 text-primary hover:text-primary/80 hover:underline font-medium transition-colors">
                      {repoDisplay}
                      <ExternalLink size={14} />
                    </a> : <span className="break-all text-muted-foreground">{repoDisplay}</span>}
                  </div>
                </div>
              </div>

              <div className="border-t bg-muted/30 p-6 sm:p-8 lg:border-l lg:border-t-0">
                <div className="flex items-center justify-between gap-3">
                  <p className="text-xs font-bold uppercase tracking-widest text-muted-foreground">Current State</p>
                  <span className="text-xs font-semibold text-muted-foreground">{forensic ? 'Forensic analysis' : 'Detection only'}</span>
                </div>

                <div className="mt-6 rounded-sm border bg-background p-5 shadow-sm">
                  <div className="flex items-center gap-3">
                    <span className={`flex h-10 w-10 items-center justify-center rounded-sm ${synthetic ? 'bg-sky-500/10 text-sky-600 dark:text-sky-300' : 'bg-muted text-muted-foreground'}`}>
                      <Radio size={18} />
                    </span>
                    <div>
                      <p className="text-xs font-semibold uppercase tracking-wider text-muted-foreground">Exposure</p>
                      <p className="text-base font-bold text-foreground">
                        {exposureLabel(incident)}
                      </p>
                    </div>
                  </div>
                  <div className="mt-5 border-t pt-4">
                    <p className="text-xs font-semibold uppercase tracking-wider text-muted-foreground">Confirmed window</p>
                    <p className="mt-1 font-mono text-2xl font-bold tracking-tight text-foreground">{dur}</p>
                  </div>
                </div>
              </div>
            </div>

            {/* Stats Grid */}
            <div className="border-t bg-muted/20 p-4 sm:p-6">
              <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 xl:grid-cols-4">
                <SummaryTile icon={Clock3} label={synthetic ? "Sample exposure start" : "Exposure start"}>
                  {fmtTime(incident.exposure_start)}
                </SummaryTile>
                <SummaryTile icon={Timer} label="Window closure">
                  {synthetic ? 'Demo only' : incident.exposure_end ? fmtTime(incident.exposure_end) : 'Not confirmed'}
                </SummaryTile>
                <SummaryTile icon={GitCommitHorizontal} label="Commit">
                  <span className="font-mono">{synthetic ? 'Demo source' : incident.commit_hash ? incident.commit_hash.slice(0, 7) : '—'}</span>
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
                  <h3 className="text-sm font-semibold text-orange-700 dark:text-orange-400">Potential compliance relevance</h3>
                </div>
                <div className="grid sm:grid-cols-3 gap-4">
                  {incident.gdpr_flag && (
                    <div className="bg-background rounded-sm p-3 border shadow-sm">
                      <div className="flex items-center gap-2 mb-1 text-orange-600 dark:text-orange-400">
                        <ShieldAlert size={14} />
                        <span className="text-xs font-bold uppercase">GDPR — Art. 33</span>
                      </div>
                      <p className="text-xs text-muted-foreground">Review the evidence with your privacy team. This flag does not establish a reportable breach.</p>
                    </div>
                  )}
                  {incident.pcidss_flag && (
                    <div className="bg-background rounded-sm p-3 border shadow-sm">
                      <div className="flex items-center gap-2 mb-1 text-orange-600 dark:text-orange-400">
                        <Scale size={14} />
                        <span className="text-xs font-bold uppercase">PCI-DSS — Req 12</span>
                      </div>
                      <p className="text-xs text-muted-foreground">Review payment-data exposure and your incident response obligations with the responsible team.</p>
                    </div>
                  )}
                  {incident.soc2_flag && (
                    <div className="bg-background rounded-sm p-3 border shadow-sm">
                      <div className="flex items-center gap-2 mb-1 text-orange-600 dark:text-orange-400">
                        <Building2 size={14} />
                        <span className="text-xs font-bold uppercase">SOC 2 — CC6/A1</span>
                      </div>
                      <p className="text-xs text-muted-foreground">Review the relevant security controls and incident evidence with your compliance team.</p>
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

          {canManage && incident.status === 'complete' && <AskAboutIncident incidentId={incident.incident_id} />}

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
              <p className="mb-4 text-sm text-muted-foreground">Shows up to 30 days of available provider history. Events before detected exposure are context and are excluded from incident severity, impact and report calculations. Refresh logs to retrieve recent history.</p>
              {incident.credential_type === 'stripe_secret_key' && <div className="mb-4 space-y-2 text-sm text-muted-foreground">
                <p>BreachTrace queries Stripe Events directly through the backend, using up to the Events API’s 30-day retention window. These records show account-level state changes, not every API request, and do not identify which key caused them. Read-only requests are not included.</p>
              </div>}
              {(incident.credential_type === 'azure_service_principal' || incident.credential_type === 'azure_client_secret') && <p className="mb-4 text-sm text-muted-foreground">Azure Activity Log events are matched to the application identity. They do not identify which client secret was used, and Activity Log does not include every data-plane action.</p>}
              {incident.status === 'error' && <p role="alert" className="mb-4 text-sm text-destructive">{incident.collection_error || 'Forensic collection failed. Check your provider access and refresh the logs.'}</p>}
              <ForensicTimeline events={incident.events} exposureStart={incident.exposure_start} />
            </div>
          ) : (
            <>
              <ForensicsUnavailable incident={incident} />
              {canManage && !USE_MOCK && !synthetic && incident.credential_type === 'azure_client_secret' && <form
                className="border rounded-sm p-5 space-y-3"
                onSubmit={e => { e.preventDefault(); void handleAzureApplication() }}>
                <h3 className="font-semibold">Associate Azure application</h3>
                <p className="text-sm text-muted-foreground">Enter the application (client) ID that owns this secret. The backend reader needs Activity Log access to the correct subscription. Activity is associated with the application, not a specific secret.</p>
                <label className="block text-sm">Application (client) ID
                  <input className="block mt-1 w-full border rounded p-2 bg-transparent font-mono" value={azureClientId}
                    onChange={e => setAzureClientId(e.target.value)} pattern="[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}" required placeholder="xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx" />
                </label>
                <label className="flex items-start gap-2 text-sm"><input type="checkbox" checked={azureOwnershipConfirmed} onChange={e => setAzureOwnershipConfirmed(e.target.checked)} required /> I confirmed this secret belongs to this application.</label>
                <Button disabled={refreshing || !azureOwnershipConfirmed} type="submit">{refreshing ? 'Starting…' : 'Collect Azure activity'}</Button>
              </form>}
              {canManage && !USE_MOCK && incident.credential_type === 'twilio_api_key' && <form
                className="border rounded-sm p-5 space-y-3"
                onSubmit={e => { e.preventDefault(); void handleTwilioAccount() }}>
                <p className="text-sm">Confirm the owning Twilio Account SID to collect account activity. It must match the reader account configured on the backend.</p>
                <label className="block text-sm">Twilio Account SID
                  <input className="block mt-1 w-full border rounded p-2 bg-transparent font-mono" value={twilioAccount}
                    onChange={e => setTwilioAccount(e.target.value)} pattern="AC[0-9a-fA-F]{32}" required placeholder="AC…" />
                </label>
                <Button disabled={refreshing} type="submit">{refreshing ? 'Starting…' : 'Collect Twilio activity'}</Button>
              </form>}
            </>
          )}

        </div>

        {/* Right Column (Sidebar) */}
        <div className="xl:col-span-4 space-y-6">
          <div className="xl:sticky xl:top-24 space-y-6">
            {/* First in the stack: on a Stripe incident this is real money
                moved, which should not sit below three other cards. Self-hides
                when there is nothing to report. */}
            {forensic ? <>
              <FinancialImpactPanel incident={incident} />
              <BlastRadiusSummary incident={{...incident, events: exposureEvents}} />
              <SourceIPs events={exposureEvents} />
              <AffectedResources events={exposureEvents} />
            </> : <div className="rounded-sm border bg-card p-5 space-y-3 text-sm">
              <h2 className="font-semibold">Detection evidence</h2>
              <p>Credential candidate found · validity not verified</p>
              <p className="text-muted-foreground">Usage, billing impact and severity have not been assessed by BreachTrace. Review available records in the provider console.</p>
              {synthetic && <p className="text-muted-foreground">This example uses a fabricated key. No provider request was made.</p>}
            </div>}
            <RemediationChecklist steps={incident.remediation_steps} />
          </div>
        </div>

      </div>

      {/* Event Analytics */}
      {exposureEvents.length > 0 && (
        <div className="mt-8">
          <EventAnalytics events={exposureEvents} />
        </div>
      )}

    </div>
  )
}

export default IncidentDetail
