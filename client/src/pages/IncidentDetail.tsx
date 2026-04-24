import { useEffect, useState } from 'react'
import { useParams, useNavigate } from 'react-router-dom'
import { ArrowLeft, AlertTriangle, Printer, ExternalLink, ShieldAlert, Scale, Building2, Activity, Check, CircleDot, Circle } from 'lucide-react'
import client from '@/api/client'
import type { IncidentRecord } from '@/types'
import SeverityBadge from '@/components/SeverityBadge'
import ForensicTimeline from '@/components/ForensicTimeline'
import BlastRadiusSummary from '@/components/BlastRadiusSummary'
import AffectedResources from '@/components/AffectedResources'
import SourceIPs from '@/components/SourceIPs'
import RemediationChecklist from '@/components/RemediationChecklist'
import EventAnalytics from '@/components/EventAnalytics'
import { Button } from '@/components/ui/button'

/* ─── helpers ─────────────────────────────────────────────────── */

function fmtTime(ts: string) {
  return new Date(ts).toLocaleString('en-US', {
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
  const diff = Math.floor(((end ? new Date(end).getTime() : Date.now()) - new Date(start).getTime()) / 1000)
  const h = Math.floor(diff / 3600)
  const m = Math.floor((diff % 3600) / 60)
  const s = diff % 60
  return h > 0 ? `${h}h ${m}m ${s}s` : m > 0 ? `${m}m ${s}s` : `${s}s`
}

/* ─── markdown renderer ────────────────────────────────────────── */

function renderInline(text: string): React.ReactNode {
  // Split on **bold** then *em* patterns
  const parts = text.split(/(\*\*[^*]+\*\*|\*[^*\n]+\*)/g)
  return (
    <>
      {parts.map((part, i) => {
        if (part.startsWith('**') && part.endsWith('**') && part.length > 4) {
          return <strong key={i} className="font-semibold">{part.slice(2, -2)}</strong>
        }
        if (part.startsWith('*') && part.endsWith('*') && part.length > 2 && !part.startsWith('**')) {
          // Gemini uses single * for emphasis, treat as bold
          return <strong key={i} className="font-semibold">{part.slice(1, -1)}</strong>
        }
        return part || null
      })}
    </>
  )
}

function MarkdownReport({ text }: { text: string }) {
  const lines = text.split('\n')
  const nodes: React.ReactNode[] = []
  let para: string[] = []
  let key = 0

  const flushPara = () => {
    if (para.length === 0) return
    nodes.push(
      <p key={key++} className="text-sm leading-relaxed" style={{ color: 'var(--color-foreground)' }}>
        {renderInline(para.join(' '))}
      </p>
    )
    para = []
  }

  for (const raw of lines) {
    const line = raw.trim()

    if (!line) {
      flushPara()
      continue
    }

    // Headings
    if (/^#{1,2} /.test(line)) {
      flushPara()
      const text = line.replace(/^#{1,2} /, '')
      nodes.push(
        <p
          key={key++}
          className="text-[11px] font-bold uppercase tracking-widest mt-5 mb-1.5"
          style={{ color: 'var(--color-muted-foreground)' }}
        >
          {text}
        </p>
      )
      continue
    }

    if (/^### /.test(line)) {
      flushPara()
      nodes.push(
        <p key={key++} className="text-sm font-semibold mt-3 mb-1" style={{ color: 'var(--color-foreground)' }}>
          {renderInline(line.slice(4))}
        </p>
      )
      continue
    }

    // Checklist items (☐ or ☑)
    if (/^[☐☑] /.test(line)) {
      flushPara()
      const checked = line.startsWith('☑')
      nodes.push(
        <div key={key++} className="flex items-start gap-2 text-sm my-0.5">
          <span
            className="shrink-0 mt-0.5 text-base leading-tight"
            style={{ color: checked ? 'var(--color-sev-low)' : 'var(--color-muted-foreground)' }}
          >
            {checked ? '☑' : '☐'}
          </span>
          <span style={{ color: 'var(--color-foreground)' }}>{renderInline(line.slice(2))}</span>
        </div>
      )
      continue
    }

    // Bullet list items
    if (/^[-•] /.test(line) || /^\* [^*]/.test(line)) {
      flushPara()
      const content = line.replace(/^[-•*] /, '')
      nodes.push(
        <div key={key++} className="flex items-start gap-2.5 text-sm my-0.5">
          <span
            className="shrink-0 mt-2 w-1 h-1 rounded-full"
            style={{ backgroundColor: 'var(--color-muted-foreground)', opacity: 0.6 }}
          />
          <span style={{ color: 'var(--color-foreground)' }}>{renderInline(content)}</span>
        </div>
      )
      continue
    }

    // Numbered list items
    if (/^\d+[.)]\s/.test(line)) {
      flushPara()
      const match = line.match(/^(\d+[.)]\s*)(.*)$/)
      const num = match?.[1] ?? ''
      const content = match?.[2] ?? line
      nodes.push(
        <div key={key++} className="flex items-start gap-2 text-sm my-0.5">
          <span
            className="shrink-0 font-mono text-[11px] mt-0.5 w-5 text-right"
            style={{ color: 'var(--color-muted-foreground)' }}
          >
            {num.trim()}
          </span>
          <span style={{ color: 'var(--color-foreground)' }}>{renderInline(content)}</span>
        </div>
      )
      continue
    }

    // Regular paragraph text
    para.push(line)
  }

  flushPara()

  return <div className="space-y-2">{nodes}</div>
}

/* ─── status stepper ───────────────────────────────────────────── */

const PIPELINE_STEPS: IncidentRecord['status'][] = [
  'detecting', 'collecting', 'classifying', 'scoring', 'reporting', 'complete',
]

const STATUS_LABELS: Record<string, string> = {
  detecting:   'Detecting',
  collecting:  'Collecting',
  classifying: 'Classifying',
  scoring:     'Scoring',
  reporting:   'Reporting',
  complete:    'Complete',
}

function PipelineStepper({ status }: { status: IncidentRecord['status'] }) {
  const current = PIPELINE_STEPS.indexOf(status)
  return (
    <div className="flex flex-wrap items-center justify-center gap-1.5 sm:gap-2">
      {PIPELINE_STEPS.map((step, i) => {
        const done = i < current
        const active = i === current
        const inactive = i > current
        return (
          <div key={step} className="flex items-center gap-1.5 sm:gap-2">
            <div
              className={`flex items-center justify-center px-2.5 py-1.5 border rounded-sm text-[11px] sm:text-xs font-semibold uppercase tracking-wider transition-all duration-300 ${
                active
                  ? 'bg-primary/10 border-primary/30 text-primary shadow-sm'
                  : done
                  ? 'bg-muted/50 border-muted-foreground/20 text-muted-foreground/80'
                  : 'bg-transparent border-dashed border-border text-muted-foreground/40'
              }`}
            >
              {done && <Check size={13} className="mr-1.5 text-primary/70" />}
              {active && <CircleDot size={13} className="mr-1.5 animate-pulse text-primary" />}
              {inactive && <Circle size={13} className="mr-1.5 opacity-40 text-muted-foreground" />}
              {STATUS_LABELS[step]}
            </div>
            {i < PIPELINE_STEPS.length - 1 && (
              <div
                className={`w-3 sm:w-6 h-px transition-all duration-300 ${
                  done ? 'bg-primary/50' : 'bg-border border-dashed'
                }`}
              />
            )}
          </div>
        )
      })}
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
        
        <div className="flex items-center gap-3">
          <Button variant="outline" className="shadow-sm bg-background hidden sm:flex rounded-sm" onClick={() => window.print()}>
            <Printer size={16} className="mr-2" /> Export PDF
          </Button>
          {incident.status !== 'complete' && (
            <div className="px-4 py-2 bg-primary/10 text-primary text-sm font-medium rounded-sm flex items-center gap-2 border border-primary/20">
              <div className="w-2 h-2 rounded-full bg-primary animate-pulse" />
              Investigation Active
            </div>
          )}
        </div>
      </div>

      {/* Main Content Grid */}
      <div className="grid grid-cols-1 xl:grid-cols-12 gap-8">
        
        {/* Left Column (Main Info) */}
        <div className="xl:col-span-8 space-y-8">
          
          {/* Overview Card */}
          <div className="bg-card border rounded-sm shadow-sm overflow-hidden">
            <div className="p-6 sm:p-8">
              <div className="flex flex-col lg:flex-row lg:items-start justify-between gap-8 mb-8">
                <div className="space-y-4 flex-1">
                  <div>
                    <h2 className="text-sm font-semibold uppercase tracking-wider text-muted-foreground mb-1">Detected Credential</h2>
                    <p className="text-xl sm:text-2xl font-mono font-bold text-foreground break-all">
                      {incident.credential_hint}
                    </p>
                  </div>
                  <div className="flex flex-wrap items-center gap-3 text-sm">
                    <span className="inline-flex items-center px-2.5 py-1 rounded-sm bg-secondary text-secondary-foreground font-medium">
                      {incident.credential_type}
                    </span>
                    <span className="text-muted-foreground">•</span>
                    <a href={incident.repo_url} target="_blank" rel="noopener noreferrer" className="inline-flex items-center gap-1.5 text-primary hover:text-primary/80 hover:underline font-medium transition-colors">
                      {repoDisplay}
                      <ExternalLink size={14} />
                    </a>
                  </div>
                </div>

                <div className="lg:w-auto w-full bg-muted/30 p-5 rounded-sm border border-muted flex shrink-0 justify-center">
                  <PipelineStepper status={incident.status} />
                </div>
              </div>

              {/* Stats Grid */}
              <div className="grid grid-cols-2 md:grid-cols-4 gap-4 p-4 rounded-sm bg-muted/40 border border-muted/50">
                <div className="space-y-1">
                  <p className="text-xs font-semibold text-muted-foreground uppercase tracking-wider">Exposed</p>
                  <p className="text-sm font-medium text-foreground">{fmtTime(incident.exposure_start)}</p>
                </div>
                <div className="space-y-1">
                  <p className="text-xs font-semibold text-muted-foreground uppercase tracking-wider">Revoked</p>
                  <p className="text-sm font-medium text-foreground">
                    {incident.exposure_end ? fmtTime(incident.exposure_end) : <span className="text-red-500 font-semibold animate-pulse">Still Exposed</span>}
                  </p>
                </div>
                <div className="space-y-1">
                  <p className="text-xs font-semibold text-muted-foreground uppercase tracking-wider">Duration</p>
                  <p className="text-sm font-mono font-medium text-foreground">{dur}</p>
                </div>
                <div className="space-y-1">
                  <p className="text-xs font-semibold text-muted-foreground uppercase tracking-wider">Commit</p>
                  <p className="text-sm font-mono font-medium text-foreground">{incident.commit_hash.slice(0, 7)}</p>
                </div>
              </div>
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
            
            {incident.estimated_financial_impact && (
              <div className="border-t px-6 sm:px-8 py-4 bg-muted/20 flex flex-col sm:flex-row sm:items-center justify-between gap-4">
                 <span className="text-sm font-medium text-muted-foreground uppercase tracking-wider">Estimated Financial Impact</span>
                 <span className="text-lg font-bold text-destructive flex items-center gap-2">
                    {incident.estimated_financial_impact}
                 </span>
              </div>
            )}
          </div>

          {/* AI Summary Report */}
          {incident.report_text && (
            <div className="bg-card border rounded-sm shadow-sm p-6 sm:p-8">
              <h2 className="text-lg font-semibold text-foreground mb-6 flex items-center gap-2">
                <div className="p-1.5 bg-primary/10 text-primary rounded-sm">
                   <AlertTriangle size={18} />
                </div>
                Executive Summary
              </h2>
              <div className="prose prose-sm xl:prose-base dark:prose-invert max-w-none prose-p:leading-relaxed prose-headings:font-semibold">
                <MarkdownReport text={incident.report_text} />
              </div>
            </div>
          )}

          {/* Forensic Timeline */}
          <div className="bg-card border rounded-sm shadow-sm p-6 sm:p-8">
              <h2 className="text-lg font-semibold text-foreground mb-6 flex items-center gap-2">
                <div className="p-1.5 bg-primary/10 text-primary rounded-sm">
                   <Activity size={18} />
                </div>
                Forensic Timeline
              </h2>
             <ForensicTimeline events={incident.events} />
          </div>

        </div>

        {/* Right Column (Sidebar) */}
        <div className="xl:col-span-4 space-y-6">
          <div className="sticky top-6 space-y-6">
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
