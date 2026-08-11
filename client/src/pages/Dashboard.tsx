import { useEffect, useState, useRef } from 'react'
import { useNavigate } from 'react-router-dom'
import {
  AlertTriangle,
  Clock,
  Activity,
  ShieldOff,
  RefreshCw,
  Scale,
} from 'lucide-react'
import client from '@/api/client'
import type { IncidentSummary } from '@/types'
import {
  derivePlatform,
  FORENSIC_PLATFORMS,
  isForensicTier,
  PLATFORM_META,
  type Platform,
} from '@/lib/platform'
import SeverityBadge from '@/components/SeverityBadge'
import {
  Table,
  TableHeader,
  TableBody,
  TableRow,
  TableHead,
  TableCell,
} from '@/components/ui/table'
import { Button } from '@/components/ui/button'

/* ─── helpers ─────────────────────────────────────────────────── */

function fmtTime(ts: string) {
  const date = new Date(ts)
  if (Number.isNaN(date.getTime())) return '--'
  return date.toLocaleString('en-US', {
    month: 'short',
    day: 'numeric',
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
    hour12: false,
  })
}

function duration(start: string, end: string | null, now: number) {
  const s = new Date(start).getTime()
  const e = end ? new Date(end).getTime() : now
  if (Number.isNaN(s) || Number.isNaN(e)) return '--'
  const diff = Math.floor((e - s) / 1000)
  const m = Math.floor(diff / 60)
  const sec = diff % 60
  return m > 0 ? `${m}m ${sec}s` : `${sec}s`
}

const STATUS_DOT: Record<string, string> = {
  detecting:   'var(--color-status-detecting)',
  collecting:  'var(--color-status-collecting)',
  classifying: 'var(--color-status-classifying)',
  scoring:     'var(--color-status-scoring)',
  reporting:   'var(--color-status-reporting)',
  complete:    'var(--color-status-complete)',
}

const SEV_COLORS: Record<string, string> = {
  CRITICAL: 'var(--color-sev-critical)',
  HIGH:     'var(--color-sev-high)',
  MEDIUM:   'var(--color-sev-medium)',
  LOW:      'var(--color-sev-low)',
}

const SEV_ROW_BORDER: Record<string, string> = {
  CRITICAL: 'var(--color-sev-critical)',
  HIGH:     'var(--color-sev-high)',
  MEDIUM:   'var(--color-sev-medium)',
  LOW:      'var(--color-sev-low)',
}

const STATUS_LABELS: Record<string, string> = {
  detecting:   'Detecting',
  collecting:  'Collecting',
  classifying: 'Classifying',
  scoring:     'Scoring',
  reporting:   'Reporting',
  complete:    'Complete',
  error:        'Needs Attention',
}

/* ─── platform tag ─────────────────────────────────────────────── */

function PlatformTag({ platform }: { platform: Platform }) {
  const meta = PLATFORM_META[platform]
  return (
    <span
      className="inline-flex items-center gap-1.5 text-[11px] font-bold uppercase tracking-wider"
      title={`Forensic source: ${meta.auditLog}`}
    >
      <span
        className="w-1.5 h-1.5 rounded-full shrink-0"
        style={{ backgroundColor: meta.color }}
      />
      {meta.label}
    </span>
  )
}

function StatusPill({ status }: { status: IncidentSummary['status'] }) {
  return (
    <span className="inline-flex items-center gap-1.5 text-xs font-medium capitalize">
      <span
        className="w-1.5 h-1.5 rounded-full inline-block"
        style={{ backgroundColor: STATUS_DOT[status] ?? 'var(--color-muted-foreground)' }}
      />
      {STATUS_LABELS[status] ?? status}
    </span>
  )
}

/* ─── stat card ────────────────────────────────────────────────── */

function StatCard({
  label,
  value,
  icon,
  accent,
  sub,
}: {
  label: string
  value: string | number
  icon: React.ReactNode
  accent?: boolean
  sub?: string
}) {
  return (
    <div
      className="flex flex-col gap-3 p-5 border"
      style={{
        backgroundColor: 'var(--color-card)',
        borderColor: accent ? 'var(--color-sev-critical)' : 'var(--color-border)',
      }}
    >
      <div
        className="flex items-center justify-between"
        style={{ color: 'var(--color-muted-foreground)' }}
      >
        <span className="text-xs font-semibold uppercase tracking-wider">{label}</span>
        <span>{icon}</span>
      </div>
      <div className="flex items-end justify-between gap-2">
        <span
          className="text-2xl font-bold tracking-tight font-mono"
          style={{ color: accent ? 'var(--color-sev-critical)' : 'var(--color-foreground)' }}
        >
          {value}
        </span>
        {sub && (
          <span
            className="text-xs font-mono pb-0.5"
            style={{ color: 'var(--color-muted-foreground)' }}
          >
            {sub}
          </span>
        )}
      </div>
    </div>
  )
}

/* ─── severity distribution chart ─────────────────────────────── */

function SeverityChart({ incidents }: { incidents: IncidentSummary[] }) {
  const sevs = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'] as const
  const counts = sevs.map(s => ({
    sev: s,
    n: incidents.filter(i => i.overall_severity === s).length,
  }))
  const max = Math.max(...counts.map(c => c.n), 1)

  return (
    <div className="space-y-2.5">
      {counts.map(({ sev, n }) => (
        <div key={sev} className="flex items-center gap-3">
          <span
            className="text-[11px] font-mono font-semibold shrink-0"
            style={{ color: SEV_COLORS[sev], width: 56 }}
          >
            {sev}
          </span>
          <div
            className="flex-1 h-1.5 rounded-full overflow-hidden"
            style={{ backgroundColor: 'var(--color-muted)' }}
          >
            <div
              className="h-full rounded-full transition-all duration-500"
              style={{
                width: `${(n / max) * 100}%`,
                backgroundColor: SEV_COLORS[sev],
                opacity: n === 0 ? 0.2 : 1,
              }}
            />
          </div>
          <span
            className="text-xs font-mono tabular-nums"
            style={{ color: 'var(--color-muted-foreground)', width: 16, textAlign: 'right' }}
          >
            {n}
          </span>
        </div>
      ))}
    </div>
  )
}

/* ─── credential type chart ────────────────────────────────────── */

function CredentialChart({ incidents }: { incidents: IncidentSummary[] }) {
  const counts = incidents.reduce<Record<string, number>>((acc, i) => {
    const t = i.credential_type || 'Unknown'
    acc[t] = (acc[t] ?? 0) + 1
    return acc
  }, {})
  const entries = Object.entries(counts).sort((a, b) => b[1] - a[1]).slice(0, 5)
  const max = Math.max(...entries.map(e => e[1]), 1)

  if (entries.length === 0) {
    return <p className="text-xs" style={{ color: 'var(--color-muted-foreground)' }}>No data</p>
  }

  return (
    <div className="space-y-2.5">
      {entries.map(([type, count]) => (
        <div key={type} className="flex items-center gap-3">
          <span
            className="text-[11px] font-mono shrink-0 truncate"
            style={{ color: 'var(--color-foreground)', width: 120 }}
            title={type}
          >
            {type}
          </span>
          <div
            className="flex-1 h-1.5 rounded-full overflow-hidden"
            style={{ backgroundColor: 'var(--color-muted)' }}
          >
            <div
              className="h-full rounded-full transition-all duration-500"
              style={{
                width: `${(count / max) * 100}%`,
                backgroundColor: 'var(--color-muted-foreground)',
                opacity: 0.6,
              }}
            />
          </div>
          <span
            className="text-xs font-mono tabular-nums"
            style={{ color: 'var(--color-muted-foreground)', width: 16, textAlign: 'right' }}
          >
            {count}
          </span>
        </div>
      ))}
    </div>
  )
}

/* ─── pipeline status distribution ─────────────────────────────── */

function StatusBreakdown({ incidents }: { incidents: IncidentSummary[] }) {
  const statuses = ['detecting', 'collecting', 'classifying', 'scoring', 'reporting', 'complete'] as const
  const counts = statuses.map(s => ({
    status: s,
    n: incidents.filter(i => i.status === s).length,
  }))
  const total = incidents.length
  const active = statuses.slice(0, 5).reduce((sum, s) => sum + incidents.filter(i => i.status === s).length, 0)
  const complete = incidents.filter(i => i.status === 'complete').length

  return (
    <div className="space-y-3">
      {/* Stacked progress bar */}
      <div className="flex h-2 rounded-full overflow-hidden gap-px">
        {counts.map(({ status, n }) =>
          n > 0 ? (
            <div
              key={status}
              className="h-full transition-all duration-500"
              style={{
                width: `${(n / total) * 100}%`,
                backgroundColor: STATUS_DOT[status],
              }}
              title={`${status}: ${n}`}
            />
          ) : null
        )}
      </div>

      {/* Legend */}
      <div className="grid grid-cols-2 gap-x-4 gap-y-1.5">
        {counts.filter(c => c.n > 0).map(({ status, n }) => (
          <div key={status} className="flex items-center gap-2">
            <span
              className="w-1.5 h-1.5 rounded-full shrink-0"
              style={{ backgroundColor: STATUS_DOT[status] }}
            />
            <span
              className="text-[11px] capitalize flex-1"
              style={{ color: 'var(--color-muted-foreground)' }}
            >
              {status}
            </span>
            <span className="text-[11px] font-mono tabular-nums" style={{ color: 'var(--color-foreground)' }}>
              {n}
            </span>
          </div>
        ))}
      </div>

      {/* Summary line */}
      <p className="text-[11px]" style={{ color: 'var(--color-muted-foreground)' }}>
        <span className="font-semibold" style={{ color: 'var(--color-foreground)' }}>{complete}</span> resolved ·{' '}
        <span className="font-semibold" style={{ color: 'var(--color-sev-high)' }}>{active}</span> in pipeline
      </p>
    </div>
  )
}

/* ─── component ────────────────────────────────────────────────── */

const Dashboard: React.FC = () => {
  const [incidents, setIncidents] = useState<IncidentSummary[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  // Filter options are the five Tier-1 platforms plus 'other'. Rendering a chip
  // per platform would mean eleven chips, most of them empty most of the time.
  const [filterPlatform, setFilterPlatform] = useState<Platform | 'all' | 'other'>('all')
  const [now, setNow] = useState(Date.now())
  const tickerRef = useRef<ReturnType<typeof setInterval> | null>(null)
  const navigate = useNavigate()

  useEffect(() => {
    tickerRef.current = setInterval(() => setNow(Date.now()), 1000)
    return () => {
      if (tickerRef.current !== null) clearInterval(tickerRef.current)
    }
  }, [])

  const fetchIncidents = async () => {
    setLoading(true)
    setError(null)
    try {
      const { data } = await client.get<IncidentSummary[]>('/incidents')
      setIncidents(data)
    } catch {
      setError('Could not reach the backend. Make sure the API is running.')
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => { fetchIncidents() }, [])

  useEffect(() => {
    const poll = setInterval(() => {
      client
        .get<IncidentSummary[]>('/incidents')
        .then(({ data }) => setIncidents(data))
        .catch(() => {})
    }, 3000)
    return () => clearInterval(poll)
  }, [])

  const critical        = incidents.filter(i => i.overall_severity === 'CRITICAL').length
  const active          = incidents.filter(i => i.status !== 'complete').length
  const credTypes       = [...new Set(incidents.map(i => i.credential_type))].length
  const complianceFlags = incidents.filter(i => i.gdpr_flag).length

  // Platform is derived rather than read straight off the payload — see
  // lib/platform.ts. Reading `i.platform` directly matched nothing against a
  // backend that does not yet return the field.
  const platformOf = (i: IncidentSummary) => derivePlatform(i)

  const filteredIncidents =
    filterPlatform === 'all'
      ? incidents
      : filterPlatform === 'other'
        ? incidents.filter(i => !FORENSIC_PLATFORMS.includes(platformOf(i)))
        : incidents.filter(i => platformOf(i) === filterPlatform)

  const platformCounts = incidents.reduce<Record<string, number>>((acc, i) => {
    const p = platformOf(i)
    acc[p] = (acc[p] ?? 0) + 1
    return acc
  }, {})

  return (
    <div className="space-y-8">
      {/* Page header */}
      <div className="flex items-end justify-between">
        <div>
          <h1 className="text-xl font-bold tracking-tight">Incident Monitor</h1>
          <p className="mt-1 text-sm" style={{ color: 'var(--color-muted-foreground)' }}>
            Credential exposure forensics across detected GitHub leaks
          </p>
        </div>
        <Button
          variant="outline"
          size="sm"
          onClick={fetchIncidents}
          disabled={loading}
          className="gap-2"
        >
          <RefreshCw size={13} strokeWidth={2} className={loading ? 'animate-spin' : ''} />
          Refresh
        </Button>
      </div>

      {/* Stats row */}
      <div
        className="grid grid-cols-2 sm:grid-cols-5 gap-px border"
        style={{ backgroundColor: 'var(--color-border)', borderColor: 'var(--color-border)' }}
      >
        <StatCard
          label="Total Incidents"
          value={loading ? '—' : filteredIncidents.length}
          icon={<Activity size={14} strokeWidth={2} />}
          sub={loading ? undefined : `${active} active`}
        />
        <StatCard
          label="Critical"
          value={loading ? '—' : critical}
          icon={<AlertTriangle size={14} strokeWidth={2} />}
          accent={critical > 0}
        />
        <StatCard
          label="Active"
          value={loading ? '—' : active}
          icon={<Clock size={14} strokeWidth={2} />}
        />
        <StatCard
          label="Credential Types"
          value={loading ? '—' : credTypes || 0}
          icon={<ShieldOff size={14} strokeWidth={2} />}
        />
        <StatCard
          label="Compliance Flags"
          value={loading ? '—' : complianceFlags}
          icon={<Scale size={14} strokeWidth={2} />}
          accent={complianceFlags > 0}
        />
      </div>

      {/* Visualization section — only when data is loaded */}
      {!loading && incidents.length > 0 && (
        <div
          className="grid grid-cols-1 sm:grid-cols-3 gap-px border"
          style={{ backgroundColor: 'var(--color-border)', borderColor: 'var(--color-border)' }}
        >
          {/* Severity distribution */}
          <div className="p-5" style={{ backgroundColor: 'var(--color-card)' }}>
            <p
              className="text-[11px] font-semibold uppercase tracking-widest mb-4"
              style={{ color: 'var(--color-muted-foreground)' }}
            >
              Severity Distribution
            </p>
            <SeverityChart incidents={incidents} />
          </div>

          {/* Credential types */}
          <div className="p-5" style={{ backgroundColor: 'var(--color-card)' }}>
            <p
              className="text-[11px] font-semibold uppercase tracking-widest mb-4"
              style={{ color: 'var(--color-muted-foreground)' }}
            >
              Credential Types
            </p>
            <CredentialChart incidents={incidents} />
          </div>

          {/* Pipeline status */}
          <div className="p-5" style={{ backgroundColor: 'var(--color-card)' }}>
            <p
              className="text-[11px] font-semibold uppercase tracking-widest mb-4"
              style={{ color: 'var(--color-muted-foreground)' }}
            >
              Pipeline Status
            </p>
            <StatusBreakdown incidents={incidents} />
          </div>
        </div>
      )}

      {/* Incidents table */}
      <div>
        <div className="flex items-center justify-between mb-4">
          <h2 className="text-sm font-semibold">
            Incidents
            {!loading && (
              <span
                className="ml-2 text-xs font-mono px-1.5 py-0.5 rounded"
                style={{ backgroundColor: 'var(--color-muted)', color: 'var(--color-muted-foreground)' }}
              >
                {filteredIncidents.length}
              </span>
            )}
          </h2>
          <div className="flex bg-[var(--color-muted)] p-1 rounded-md">
            {(['all', ...FORENSIC_PLATFORMS, 'other'] as const).map(platform => {
              const isActive = filterPlatform === platform
              const label =
                platform === 'all'
                  ? 'All'
                  : platform === 'other'
                    ? 'Other'
                    : PLATFORM_META[platform].label
              const count =
                platform === 'all'
                  ? incidents.length
                  : platform === 'other'
                    ? incidents.filter(i => !FORENSIC_PLATFORMS.includes(platformOf(i))).length
                    : (platformCounts[platform] ?? 0)
              return (
                <button
                  key={platform}
                  onClick={() => setFilterPlatform(platform)}
                  aria-pressed={isActive}
                  className={`flex items-center gap-1.5 px-3 py-1 text-xs font-medium rounded-sm transition-colors ${
                    isActive
                      ? 'bg-[var(--color-background)] shadow-sm'
                      : 'text-[var(--color-muted-foreground)] hover:text-[var(--color-foreground)]'
                  }`}
                >
                  {platform !== 'all' && (
                    <span
                      className="w-1.5 h-1.5 rounded-full shrink-0"
                      style={{
                        backgroundColor:
                          platform === 'other'
                            ? 'var(--color-platform-tier2)'
                            : PLATFORM_META[platform].color,
                        opacity: count === 0 ? 0.3 : 1,
                      }}
                    />
                  )}
                  {label}
                  <span className="font-mono tabular-nums opacity-60">{count}</span>
                </button>
              )
            })}
          </div>
        </div>

        {error ? (
          <div
            className="border py-10 text-center"
            style={{ borderColor: 'var(--color-border)' }}
          >
            <p className="text-sm" style={{ color: 'var(--color-muted-foreground)' }}>{error}</p>
          </div>
        ) : loading ? (
          <div
            className="border py-16 text-center"
            style={{ borderColor: 'var(--color-border)' }}
          >
            <div
              className="w-5 h-5 border-2 border-t-transparent rounded-full animate-spin mx-auto"
              style={{ borderColor: 'var(--color-foreground)', borderTopColor: 'transparent' }}
            />
            <p className="mt-3 text-sm" style={{ color: 'var(--color-muted-foreground)' }}>
              Loading incidents…
            </p>
          </div>
        ) : incidents.length === 0 ? (
          <div
            className="border py-16 text-center"
            style={{ borderColor: 'var(--color-border)' }}
          >
            <ShieldOff
              size={32}
              strokeWidth={1.5}
              className="mx-auto mb-3"
              style={{ color: 'var(--color-muted-foreground)' }}
            />
            <p className="text-sm font-medium">No incidents detected yet</p>
            <p className="mt-1 text-sm" style={{ color: 'var(--color-muted-foreground)' }}>
              Connect your GitHub repository to begin monitoring.
            </p>
            <Button
              variant="outline"
              size="sm"
              className="mt-4"
              onClick={() => navigate('/connect')}
            >
              Connect Repository
            </Button>
          </div>
        ) : filteredIncidents.length === 0 ? (
          <div
            className="border py-16 text-center"
            style={{ borderColor: 'var(--color-border)' }}
          >
            <p className="text-sm font-medium">
              No {filterPlatform === 'all' ? '' : PLATFORM_META[filterPlatform as Platform].label}{' '}
              incidents
            </p>
            <p className="mt-1 text-sm" style={{ color: 'var(--color-muted-foreground)' }}>
              {incidents.length} incident{incidents.length !== 1 ? 's' : ''} on other platforms.
            </p>
            <Button
              variant="outline"
              size="sm"
              className="mt-4"
              onClick={() => setFilterPlatform('all')}
            >
              Show all platforms
            </Button>
          </div>
        ) : (
          <div className="border" style={{ borderColor: 'var(--color-border)' }}>
            <Table>
              <TableHeader>
                <TableRow className="hover:bg-transparent">
                  <TableHead className="w-4 p-0" />
                  <TableHead>Platform</TableHead>
                  <TableHead>Credential</TableHead>
                  <TableHead>Repository</TableHead>
                  <TableHead>Exposed</TableHead>
                  <TableHead>Duration</TableHead>
                  <TableHead>Status</TableHead>
                  <TableHead>Severity</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {filteredIncidents.map((inc) => {
                  const sevBorder = inc.overall_severity
                    ? SEV_ROW_BORDER[inc.overall_severity]
                    : 'transparent'
                  return (
                    <TableRow
                      key={inc.incident_id}
                      onClick={() => navigate(`/incident/${inc.incident_id}`)}
                      className="cursor-pointer"
                    >
                      {/* Severity accent bar */}
                      <TableCell className="p-0 w-1">
                        <div
                          className="w-0.5 h-full min-h-12"
                          style={{ backgroundColor: sevBorder }}
                        />
                      </TableCell>

                      {/* Platform */}
                      <TableCell>
                        <PlatformTag platform={platformOf(inc)} />
                      </TableCell>

                      {/* Credential */}
                      <TableCell>
                        <div>
                          <div className="flex items-center gap-2">
                            <span
                              className="font-mono text-xs font-semibold"
                              style={{ color: 'var(--color-foreground)' }}
                            >
                              {inc.credential_hint}
                            </span>
                            {inc.gdpr_flag && (
                              <span
                                className="inline-flex items-center gap-1 text-[10px] font-bold px-1.5 py-0.5 rounded uppercase tracking-wider"
                                style={{
                                  backgroundColor: 'color-mix(in srgb, var(--color-sev-critical) 15%, transparent)',
                                  color: 'var(--color-sev-critical)',
                                }}
                                title="Compliance notification required (GDPR / PCI-DSS)"
                              >
                                <Scale size={9} strokeWidth={2.5} />
                                Legal
                              </span>
                            )}
                          </div>
                          <p
                            className="text-[11px] mt-0.5 uppercase tracking-wider font-semibold"
                            style={{ color: 'var(--color-muted-foreground)' }}
                          >
                            {inc.credential_type}
                          </p>
                          {/* Tier-2 rows would otherwise look like Tier-1 rows
                              whose investigation found nothing. The badge makes
                              "we could not look" distinct from "we looked and
                              found nothing" at a glance. */}
                          {!isForensicTier(inc) && (
                            <span
                              className="inline-block mt-1 text-[10px] font-bold px-1.5 py-0.5 rounded uppercase tracking-wider"
                              style={{
                                backgroundColor:
                                  'color-mix(in srgb, var(--color-platform-tier2) 18%, transparent)',
                                color: 'var(--color-platform-tier2)',
                              }}
                              title="This platform exposes no queryable audit log, so activity cannot be reconstructed"
                            >
                              Detection only
                            </span>
                          )}
                        </div>
                      </TableCell>

                      {/* Repository */}
                      <TableCell>
                        <span
                          className="text-xs font-mono block"
                          style={{
                            color: 'var(--color-muted-foreground)',
                            maxWidth: 180,
                            overflow: 'hidden',
                            textOverflow: 'ellipsis',
                            whiteSpace: 'nowrap',
                          }}
                          title={inc.repo_url}
                        >
                          {inc.repo_url.replace('https://github.com/', '')}
                        </span>
                      </TableCell>

                      {/* Exposed */}
                      <TableCell>
                        <span className="text-xs font-mono" style={{ color: 'var(--color-muted-foreground)' }}>
                          {fmtTime(inc.exposure_start)}
                        </span>
                      </TableCell>

                      {/* Duration */}
                      <TableCell>
                        <span className="text-xs font-mono">
                          {duration(inc.exposure_start, inc.exposure_end, now)}
                        </span>
                      </TableCell>

                      {/* Status */}
                      <TableCell>
                        <StatusPill status={inc.status} />
                      </TableCell>

                      {/* Severity */}
                      <TableCell>
                        {inc.overall_severity ? (
                          <SeverityBadge severity={inc.overall_severity} />
                        ) : (
                          <span className="text-xs" style={{ color: 'var(--color-muted-foreground)' }}>—</span>
                        )}
                      </TableCell>
                    </TableRow>
                  )
                })}
              </TableBody>
            </Table>
          </div>
        )}
      </div>
    </div>
  )
}

export default Dashboard
