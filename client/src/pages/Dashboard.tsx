import { useEffect, useState, useRef } from 'react'
import { useNavigate } from 'react-router-dom'
import {
  AlertTriangle,
  Clock,
  Activity,
  ShieldOff,
  RefreshCw,
} from 'lucide-react'
import client from '@/api/client'
import type { IncidentRecord } from '@/types'
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
  return new Date(ts).toLocaleString('en-US', {
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
  const diff = Math.floor((e - s) / 1000)
  const m = Math.floor(diff / 60)
  const sec = diff % 60
  return m > 0 ? `${m}m ${sec}s` : `${sec}s`
}

const STATUS_DOT: Record<string, string> = {
  detecting:    'var(--color-status-detecting)',
  collecting:   'var(--color-status-collecting)',
  classifying:  'var(--color-status-classifying)',
  scoring:      'var(--color-status-scoring)',
  reporting:    'var(--color-status-reporting)',
  complete:     'var(--color-status-complete)',
}

function StatusPill({ status }: { status: IncidentRecord['status'] }) {
  return (
    <span className="inline-flex items-center gap-1.5 text-xs font-medium capitalize">
      <span
        className="w-1.5 h-1.5 rounded-full inline-block"
        style={{ backgroundColor: STATUS_DOT[status] ?? 'var(--color-muted-foreground)' }}
      />
      {status}
    </span>
  )
}

/* ─── stat card ────────────────────────────────────────────────── */

function StatCard({
  label,
  value,
  icon,
  accent,
}: {
  label: string
  value: string | number
  icon: React.ReactNode
  accent?: boolean
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
      <span
        className="text-2xl font-bold tracking-tight font-mono"
        style={{ color: accent ? 'var(--color-sev-critical)' : 'var(--color-foreground)' }}
      >
        {value}
      </span>
    </div>
  )
}

/* ─── component ────────────────────────────────────────────────── */

const Dashboard: React.FC = () => {
  const [incidents, setIncidents] = useState<IncidentRecord[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [now, setNow] = useState(Date.now())
  const tickerRef = useRef<ReturnType<typeof setInterval> | null>(null)
  const navigate = useNavigate()

  // Tick every second so active-incident durations update live
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
      const { data } = await client.get<IncidentRecord[]>('/incidents')
      setIncidents(data)
    } catch {
      setError('Could not reach the backend. Make sure the API is running.')
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => { fetchIncidents() }, [])

  // Auto-poll every 3 seconds so live pipeline progress is visible
  useEffect(() => {
    const poll = setInterval(() => {
      client
        .get<IncidentRecord[]>('/incidents')
        .then(({ data }) => setIncidents(data))
        .catch(() => {})
    }, 3000)
    return () => clearInterval(poll)
  }, [])

  /* derive stats */
  const critical = incidents.filter((i) => i.overall_severity === 'CRITICAL').length
  const active = incidents.filter((i) => i.status !== 'complete').length
  const credTypes = [...new Set(incidents.map((i) => i.credential_type))].length

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
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-px border border-[var(--color-border)]"
           style={{ backgroundColor: 'var(--color-border)' }}>
        <StatCard
          label="Total Incidents"
          value={loading ? '—' : incidents.length}
          icon={<Activity size={14} strokeWidth={2} />}
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
      </div>

      {/* Incidents table */}
      <div>
        <div
          className="flex items-center justify-between mb-4"
        >
          <h2 className="text-sm font-semibold">
            Incidents
            {!loading && (
              <span
                className="ml-2 text-xs font-mono px-1.5 py-0.5 rounded"
                style={{ backgroundColor: 'var(--color-muted)', color: 'var(--color-muted-foreground)' }}
              >
                {incidents.length}
              </span>
            )}
          </h2>
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
          </div>
        ) : (
          <div className="border" style={{ borderColor: 'var(--color-border)' }}>
            <Table>
              <TableHeader>
                <TableRow className="hover:bg-transparent">
                  <TableHead>Credential</TableHead>
                  <TableHead>Repository</TableHead>
                  <TableHead>Exposed</TableHead>
                  <TableHead>Duration</TableHead>
                  <TableHead>Status</TableHead>
                  <TableHead>Severity</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {incidents.map((inc) => (
                  <TableRow
                    key={inc.incident_id}
                    onClick={() => navigate(`/incident/${inc.incident_id}`)}
                  >
                    <TableCell>
                      <div>
                        <span
                          className="font-mono text-xs font-semibold"
                          style={{ color: 'var(--color-foreground)' }}
                        >
                          {inc.credential_hint}
                        </span>
                        <p
                          className="text-[11px] mt-0.5 uppercase tracking-wider font-semibold"
                          style={{ color: 'var(--color-muted-foreground)' }}
                        >
                          {inc.credential_type}
                        </p>
                      </div>
                    </TableCell>
                    <TableCell>
                      <span
                        className="text-xs font-mono truncate max-w-[180px] block"
                        style={{ color: 'var(--color-muted-foreground)' }}
                        title={inc.repo_url}
                      >
                        {inc.repo_url.replace('https://github.com/', '')}
                      </span>
                    </TableCell>
                    <TableCell>
                      <span className="text-xs font-mono" style={{ color: 'var(--color-muted-foreground)' }}>
                        {fmtTime(inc.exposure_start)}
                      </span>
                    </TableCell>
                    <TableCell>
                      <span className="text-xs font-mono">
                        {duration(inc.exposure_start, inc.exposure_end, now)}
                      </span>
                    </TableCell>
                    <TableCell>
                      <StatusPill status={inc.status} />
                    </TableCell>
                    <TableCell>
                      {inc.overall_severity ? (
                        <SeverityBadge severity={inc.overall_severity} />
                      ) : (
                        <span className="text-xs" style={{ color: 'var(--color-muted-foreground)' }}>
                          —
                        </span>
                      )}
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </div>
        )}
      </div>
    </div>
  )
}

export default Dashboard