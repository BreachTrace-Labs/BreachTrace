import { useEffect, useState } from 'react'
import { useParams, useNavigate } from 'react-router-dom'
import { ArrowLeft, AlertTriangle, Printer, ExternalLink } from 'lucide-react'
import client from '@/api/client'
import type { IncidentRecord } from '@/types'
import SeverityBadge from '@/components/SeverityBadge'
import ForensicTimeline from '@/components/ForensicTimeline'
import BlastRadiusSummary from '@/components/BlastRadiusSummary'
import AffectedResources from '@/components/AffectedResources'
import SourceIPs from '@/components/SourceIPs'
import RemediationChecklist from '@/components/RemediationChecklist'
import { Button } from '@/components/ui/button'
import { Separator } from '@/components/ui/separator'

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

/* ─── status stepper ───────────────────────────────────────────── */

const PIPELINE_STEPS: IncidentRecord['status'][] = [
  'detecting',
  'collecting',
  'classifying',
  'scoring',
  'reporting',
  'complete',
]

const STATUS_LABELS: Record<string, string> = {
  detecting: 'Detecting',
  collecting: 'Collecting',
  classifying: 'Classifying',
  scoring: 'Scoring',
  reporting: 'Reporting',
  complete: 'Complete',
}

const STATUS_COLORS: Record<string, string> = {
  detecting: 'var(--color-status-detecting)',
  collecting: 'var(--color-status-collecting)',
  classifying: 'var(--color-status-classifying)',
  scoring: 'var(--color-status-scoring)',
  reporting: 'var(--color-status-reporting)',
  complete: 'var(--color-status-complete)',
}

function PipelineStepper({ status }: { status: IncidentRecord['status'] }) {
  const current = PIPELINE_STEPS.indexOf(status)
  return (
    <div className="flex items-center gap-0">
      {PIPELINE_STEPS.map((step, i) => {
        const done = i < current
        const active = i === current
        const inactive = i > current
        return (
          <div key={step} className="flex items-center">
            {/* Step */}
            <div className="flex flex-col items-center gap-1">
              <div
                className="w-2 h-2 rounded-full transition-all"
                style={{
                  backgroundColor: done || active
                    ? STATUS_COLORS[step]
                    : 'var(--color-border)',
                  opacity: inactive ? 0.4 : 1,
                }}
              />
              <span
                className="text-[10px] font-medium uppercase tracking-wider hidden sm:block"
                style={{
                  color: active
                    ? STATUS_COLORS[step]
                    : done
                    ? 'var(--color-muted-foreground)'
                    : 'var(--color-border)',
                }}
              >
                {STATUS_LABELS[step]}
              </span>
            </div>
            {/* Connector */}
            {i < PIPELINE_STEPS.length - 1 && (
              <div
                className="h-px w-8 sm:w-12 mx-1 mb-3 sm:mb-4 transition-all"
                style={{
                  backgroundColor: done
                    ? STATUS_COLORS[PIPELINE_STEPS[i + 1]]
                    : 'var(--color-border)',
                  opacity: done ? 0.6 : 0.4,
                }}
              />
            )}
          </div>
        )
      })}
    </div>
  )
}

/* ─── meta row ─────────────────────────────────────────────────── */

function MetaRow({ label, value, mono = false }: { label: string; value: string | null | undefined; mono?: boolean }) {
  return (
    <div className="flex flex-col gap-0.5">
      <span
        className="text-[11px] uppercase tracking-wider font-semibold"
        style={{ color: 'var(--color-muted-foreground)' }}
      >
        {label}
      </span>
      <span
        className={`text-sm ${mono ? 'font-mono' : 'font-medium'}`}
        style={{ color: 'var(--color-foreground)' }}
      >
        {value ?? '—'}
      </span>
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

    // Auto-poll every 3 seconds to show live pipeline progression
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
      <div className="flex items-center justify-center py-32">
        <div
          className="w-5 h-5 border-2 border-t-transparent rounded-full animate-spin"
          style={{ borderColor: 'var(--color-foreground)', borderTopColor: 'transparent' }}
        />
      </div>
    )
  }

  if (error || !incident) {
    return (
      <div className="space-y-4">
        <Button variant="ghost" size="sm" onClick={() => navigate('/')} className="gap-2">
          <ArrowLeft size={14} />
          Back
        </Button>
        <div
          className="border py-16 text-center"
          style={{ borderColor: 'var(--color-border)' }}
        >
          <AlertTriangle
            size={32}
            strokeWidth={1.5}
            className="mx-auto mb-3"
            style={{ color: 'var(--color-muted-foreground)' }}
          />
          <p className="text-sm">{error ?? 'Incident not found'}</p>
        </div>
      </div>
    )
  }

  const dur = duration(incident.exposure_start, incident.exposure_end)
  const repoDisplay = incident.repo_url.replace('https://github.com/', '')

  return (
    <div className="space-y-8">
      {/* Nav bar */}
      <div className="flex items-center justify-between">
        <Button variant="ghost" size="sm" onClick={() => navigate('/')} className="gap-2 -ml-3">
          <ArrowLeft size={14} />
          All Incidents
        </Button>
        <Button
          variant="outline"
          size="sm"
          onClick={() => window.print()}
          className="gap-2"
        >
          <Printer size={13} />
          Export
        </Button>
      </div>

      {/* Incident header */}
      <div
        className="border p-6"
        style={{ borderColor: 'var(--color-border)', backgroundColor: 'var(--color-card)' }}
      >
        <div className="flex items-start justify-between gap-4 flex-wrap">
          <div className="space-y-1">
            <div className="flex items-center gap-3">
              <h1 className="font-mono text-lg font-bold tracking-tight">
                {incident.credential_hint}
              </h1>
              <SeverityBadge severity={incident.overall_severity} />
            </div>
            <div className="flex items-center gap-2">
              <span
                className="text-xs uppercase tracking-wider font-semibold"
                style={{ color: 'var(--color-muted-foreground)' }}
              >
                {incident.credential_type}
              </span>
              <span style={{ color: 'var(--color-border)' }}>·</span>
              <a
                href={incident.repo_url}
                target="_blank"
                rel="noopener noreferrer"
                className="text-xs font-mono flex items-center gap-1 hover:underline"
                style={{ color: 'var(--color-muted-foreground)' }}
              >
                {repoDisplay}
                <ExternalLink size={11} strokeWidth={2} />
              </a>
            </div>
          </div>

          {/* Pipeline status */}
          <PipelineStepper status={incident.status} />
        </div>

        <Separator className="my-5" />

        {/* Meta grid */}
        <div className="grid grid-cols-2 sm:grid-cols-4 gap-5">
          <MetaRow label="Exposed" value={fmtTime(incident.exposure_start)} />
          <MetaRow
            label="Revoked"
            value={incident.exposure_end ? fmtTime(incident.exposure_end) : 'Still Exposed'}
          />
          <MetaRow label="Duration" value={dur} mono />
          <MetaRow label="Commit" value={incident.commit_hash.slice(0, 12)} mono />
        </div>

        {/* GDPR banner */}
        {incident.gdpr_flag && (
          <div
            className="mt-5 flex items-start gap-3 border-l-2 pl-4 py-2"
            style={{ borderColor: 'var(--color-sev-critical)' }}
          >
            <AlertTriangle
              size={14}
              strokeWidth={2}
              className="mt-0.5 shrink-0"
              style={{ color: 'var(--color-sev-critical)' }}
            />
            <p className="text-sm font-medium" style={{ color: 'var(--color-sev-critical)' }}>
              GDPR notification may be required — potential PII access detected
            </p>
          </div>
        )}

        {/* Financial impact */}
        {incident.estimated_financial_impact && (
          <div
            className="mt-4 flex items-start gap-3 border-l-2 pl-4 py-2"
            style={{ borderColor: 'var(--color-sev-high)' }}
          >
            <p className="text-sm">
              <span
                className="font-semibold uppercase text-[11px] tracking-wider block"
                style={{ color: 'var(--color-sev-high)' }}
              >
                Estimated Financial Impact
              </span>
              {incident.estimated_financial_impact}
            </p>
          </div>
        )}
      </div>

      {/* Gemini report */}
      {incident.report_text && (
        <div>
          <h2 className="text-sm font-semibold mb-3">Incident Summary</h2>
          <div
            className="border p-6 text-sm leading-relaxed"
            style={{
              borderColor: 'var(--color-border)',
              backgroundColor: 'var(--color-card)',
              color: 'var(--color-foreground)',
              whiteSpace: 'pre-wrap',
            }}
          >
            {incident.report_text}
          </div>
        </div>
      )}

      {/* Two-column grid: timeline left, details right */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Timeline — full width or 2/3 */}
        <div className="lg:col-span-2 space-y-6">
          <ForensicTimeline events={incident.events} />
        </div>

        {/* Right column */}
        <div className="space-y-6">
          <BlastRadiusSummary incident={incident} />
          <SourceIPs events={incident.events} />
          <AffectedResources events={incident.events} />
          <RemediationChecklist steps={incident.remediation_steps} />
        </div>
      </div>
    </div>
  )
}

export default IncidentDetail
