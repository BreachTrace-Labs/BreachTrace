import { useEffect, useState } from 'react'
import { FlaskConical, BarChart3, CheckCircle, Clock, AlertCircle } from 'lucide-react'
import client from '@/api/client'
import { Card, CardHeader, CardTitle, CardContent } from '@/components/ui/card'
import { Separator } from '@/components/ui/separator'
import PlatformLatencyChart from '@/components/PlatformLatencyChart'
import ModelBenchmark from '@/components/ModelBenchmark'
import GCPHistoricalResearch from '@/components/GCPHistoricalResearch'
import type { ExperimentRun, PlatformComparison } from '@/types'

/* ─── types for research endpoint ─────────────────────────────── */

interface ResearchStats {
  total_runs: number
  avg_detection_time_s: number | null
  avg_report_time_s: number | null
  severity_distribution: Record<string, number>
  detection_target_s: number
  report_target_s: number
  precision?: number
  recall?: number
  f1?: number
  public_dataset_runs?: number
  public_dataset_avg_detection_time_s?: number
  public_dataset_avg_report_time_s?: number
}

/* ─── track badge ──────────────────────────────────────────────── */

function TrackBadge({ track, label }: { track: 'A' | 'B'; label: string }) {
  return (
    <div className="flex items-center gap-2">
      <div
        className="w-6 h-6 flex items-center justify-center text-[11px] font-bold"
        style={{
          backgroundColor: 'var(--color-foreground)',
          color: 'var(--color-background)',
          borderRadius: '3px',
        }}
      >
        {track}
      </div>
      <span className="text-sm font-semibold">{label}</span>
    </div>
  )
}

/* ─── metric card ──────────────────────────────────────────────── */

function MetricCard({
  label,
  value,
  unit,
  target,
  icon,
}: {
  label: string
  value: string | number | null
  unit?: string
  target?: string
  icon: React.ReactNode
}) {
  return (
    <div
      className="border p-5 flex flex-col gap-3"
      style={{
        backgroundColor: 'var(--color-card)',
        borderColor: 'var(--color-border)',
      }}
    >
      <div className="flex items-center justify-between">
        <span
          className="text-xs font-semibold uppercase tracking-wider"
          style={{ color: 'var(--color-muted-foreground)' }}
        >
          {label}
        </span>
        <span style={{ color: 'var(--color-muted-foreground)' }}>{icon}</span>
      </div>
      <div className="flex items-baseline gap-1">
        <span className="text-2xl font-bold font-mono tracking-tight">
          {value !== null && value !== undefined ? value : '—'}
        </span>
        {unit && (
          <span className="text-sm" style={{ color: 'var(--color-muted-foreground)' }}>
            {unit}
          </span>
        )}
      </div>
      {target && (
        <span className="text-xs" style={{ color: 'var(--color-muted-foreground)' }}>
          Target: {target}
        </span>
      )}
    </div>
  )
}

/* ─── component ────────────────────────────────────────────────── */

const Research: React.FC = () => {
  const [runs, setRuns] = useState<ExperimentRun[]>([])
  const [stats, setStats] = useState<ResearchStats | null>(null)
  const [comparison, setComparison] = useState<PlatformComparison | null>(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    const load = async () => {
      setLoading(true)
      setError(null)
      try {
        const [runsRes, statsRes, platformsRes] = await Promise.allSettled([
          client.get<ExperimentRun[]>('/research/export'),
          client.get<ResearchStats>('/incidents/stats'),
          client.get<PlatformComparison>('/research/platforms'),
        ])
        if (runsRes.status === 'fulfilled') setRuns(runsRes.value.data)
        if (statsRes.status === 'fulfilled') setStats(statsRes.value.data)
        if (platformsRes.status === 'fulfilled') setComparison(platformsRes.value.data)

        // Distinguish "the harness has not run yet" from "the API is down".
        // Now that runs are actually recorded, an empty table is a meaningful
        // state and must not be shown when the real problem is connectivity.
        if (
          runsRes.status === 'rejected' &&
          statsRes.status === 'rejected' &&
          platformsRes.status === 'rejected'
        ) {
          setError('Could not reach the backend. Make sure the API is running.')
        }
      } finally {
        setLoading(false)
      }
    }
    load()
  }, [])

  // runs.length is the source of truth once anything is recorded; stats is the
  // fallback for a backend that has stats but no exportable rows.
  const totalRuns = runs.length > 0 ? runs.length : (stats?.total_runs ?? 0)

  const fmt = (n: number | null, digits = 1) =>
    n !== null && n !== undefined ? n.toFixed(digits) : '—'

  /* severity distribution for mini bar */
  const sevOrder = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']
  const sevColors: Record<string, string> = {
    CRITICAL: 'var(--color-sev-critical)',
    HIGH: 'var(--color-sev-high)',
    MEDIUM: 'var(--color-sev-medium)',
    LOW: 'var(--color-sev-low)',
  }
  const totalSev = stats
    ? Object.values(stats.severity_distribution).reduce((s, v) => s + v, 0)
    : 0

  return (
    <div className="space-y-10">
      {/* Header */}
      <div className="flex items-end justify-between">
        <div>
          <h1 className="text-xl font-bold tracking-tight">Research</h1>
          <p className="mt-1 text-sm" style={{ color: 'var(--color-muted-foreground)' }}>
            Recorded experiment metrics and dataset evaluation status
          </p>
        </div>
        <div className="flex items-center gap-2">
          <FlaskConical size={16} strokeWidth={1.5} style={{ color: 'var(--color-muted-foreground)' }} />
          <span className="text-xs font-mono" style={{ color: 'var(--color-muted-foreground)' }}>
            Group 03 · KJSCE IT
          </span>
        </div>
      </div>

      <ModelBenchmark />
      <GCPHistoricalResearch />

      {/* Track A */}
      <section className="space-y-5">
        <TrackBadge track="A" label="Dataset evaluation — independent labels required" />

        <div
          className="border p-6"
          style={{ borderColor: 'var(--color-border)', backgroundColor: 'var(--color-card)' }}
        >
          <p className="text-sm leading-relaxed" style={{ color: 'var(--color-muted-foreground)' }}>
            SecretBench’s labelled dataset is not included in this workspace. Synthetic
            format tests and demo incidents do not measure real-world precision or recall.
            Accuracy metrics require an independently labelled evaluation set; targets below
            are study goals, not achieved results.
          </p>

          <Separator className="my-5" />

          <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-px border" style={{ backgroundColor: 'var(--color-border)' }}>
            {[
              { label: 'Total Runs', key: 'public_dataset_runs', target: '200', unit: '' },
              { label: 'Avg Detection', key: 'public_dataset_avg_detection_time_s', target: '< 30s', unit: 's' },
              { label: 'Avg Report', key: 'public_dataset_avg_report_time_s', target: '< 60s', unit: 's' },
              { label: 'Precision', key: 'precision', target: '> 95%', unit: '%' },
              { label: 'Recall', key: 'recall', target: '> 90%', unit: '%' },
              { label: 'F1 Score', key: 'f1', target: '> 92%', unit: '%' },
            ].map(({ label, target, key, unit }) => (
              <div
                key={label}
                className="p-5"
                style={{ backgroundColor: 'var(--color-card)' }}
              >
                <span
                  className="text-[11px] uppercase tracking-wider font-semibold block mb-2"
                  style={{ color: 'var(--color-muted-foreground)' }}
                >
                  {label}
                </span>
                <span className="text-2xl font-bold font-mono">
                  {stats && typeof stats[key as keyof ResearchStats] === 'number'
                    ? `${stats[key as keyof ResearchStats]}${unit}`
                    : loading ? '—' : 'Not measured'}
                </span>
                <span
                  className="text-xs block mt-1"
                  style={{ color: 'var(--color-muted-foreground)' }}
                >
                  Target: {target}
                </span>
              </div>
            ))}
          </div>

          <div
            className="mt-4 flex items-center gap-2 text-xs"
            style={{ color: 'var(--color-muted-foreground)' }}
          >
            <AlertCircle size={12} strokeWidth={2} />
            Run <span className="font-mono">pytest tests/test_secretbench.py</span> to populate metrics
          </div>
        </div>
      </section>

      {/* Track B */}
      <section className="space-y-5">
        {/* Count derived, not hardcoded: it said "35" while the data had 45,
            and would be wrong again the moment the harness runs. */}
        <TrackBadge
          track="B"
          label={`Self-Created Pipeline Experiments — ${
            loading ? '…' : totalRuns
          } Full Run${totalRuns === 1 ? '' : 's'}`}
        />

        {/* Metrics */}
        <div className="grid grid-cols-2 sm:grid-cols-4 gap-px border" style={{ backgroundColor: 'var(--color-border)' }}>
          <MetricCard
            label="Total Runs"
            value={loading ? null : totalRuns}
            target="≥ 35"
            icon={<BarChart3 size={14} strokeWidth={2} />}
          />
          <MetricCard
            label="Avg Detection"
            value={loading ? null : fmt(stats?.avg_detection_time_s ?? null)}
            unit="s"
            target="< 30s"
            icon={<Clock size={14} strokeWidth={2} />}
          />
          <MetricCard
            label="Avg Report"
            value={loading ? null : fmt(stats?.avg_report_time_s ?? null)}
            unit="s"
            target="< 60s"
            icon={<Clock size={14} strokeWidth={2} />}
          />
          <MetricCard
            label="Complete"
            // `||` here previously turned a real 0 into stats.total_runs,
            // reporting runs as complete when none were.
            value={loading ? null : runs.filter((r) => r.status === 'complete').length}
            target="35 runs"
            icon={<CheckCircle size={14} strokeWidth={2} />}
          />
        </div>

        {/* The paper's headline figure — first thing under the metrics. */}
        {!loading && <PlatformLatencyChart data={comparison} />}

        {/* Severity distribution */}
        {totalSev > 0 && (
          <Card>
            <CardHeader className="pb-3">
              <CardTitle className="text-sm">Severity Distribution</CardTitle>
            </CardHeader>
            <CardContent className="space-y-3">
              {sevOrder.map((sev) => {
                const count = stats?.severity_distribution?.[sev] ?? 0
                const pct = totalSev > 0 ? (count / totalSev) * 100 : 0
                return (
                  <div key={sev}>
                    <div className="flex items-center justify-between mb-1">
                      <span className="text-xs font-semibold uppercase tracking-wider" style={{ color: sevColors[sev] }}>
                        {sev}
                      </span>
                      <span className="text-xs font-mono" style={{ color: 'var(--color-muted-foreground)' }}>
                        {count} · {pct.toFixed(0)}%
                      </span>
                    </div>
                    <div className="h-1 rounded-full" style={{ backgroundColor: 'var(--color-muted)' }}>
                      <div
                        className="h-full rounded-full"
                        style={{ width: `${pct}%`, backgroundColor: sevColors[sev] }}
                      />
                    </div>
                  </div>
                )
              })}
            </CardContent>
          </Card>
        )}

        {/* Experiment runs table */}
        <div>
          <h3 className="text-sm font-semibold mb-3">
            Experiment Log
            {runs.length > 0 && (
              <span
                className="ml-2 text-xs font-mono px-1.5 py-0.5 rounded"
                style={{ backgroundColor: 'var(--color-muted)', color: 'var(--color-muted-foreground)' }}
              >
                {runs.length}
              </span>
            )}
          </h3>

          {loading ? (
            <div
              className="border py-12 text-center"
              style={{ borderColor: 'var(--color-border)' }}
            >
              <div
                className="w-5 h-5 border-2 border-t-transparent rounded-full animate-spin mx-auto"
                style={{ borderColor: 'var(--color-foreground)', borderTopColor: 'transparent' }}
              />
              <p className="mt-3 text-sm" style={{ color: 'var(--color-muted-foreground)' }}>
                Loading experiment data…
              </p>
            </div>
          ) : runs.length === 0 ? (
            <div
              className="border py-12 text-center"
              style={{ borderColor: 'var(--color-border)' }}
            >
              {/* "Nothing recorded" and "backend unreachable" look identical
                  otherwise, and now that runs are genuinely recorded an empty
                  table is a real state worth trusting. */}
              {error ? (
                <>
                  <AlertCircle
                    size={28}
                    strokeWidth={1.5}
                    className="mx-auto mb-3"
                    style={{ color: 'var(--color-sev-high)' }}
                  />
                  <p className="text-sm font-medium">Could not load experiment data</p>
                  <p className="mt-1 text-sm" style={{ color: 'var(--color-muted-foreground)' }}>
                    {error}
                  </p>
                </>
              ) : (
                <>
                  <FlaskConical
                    size={28}
                    strokeWidth={1.5}
                    className="mx-auto mb-3"
                    style={{ color: 'var(--color-muted-foreground)' }}
                  />
                  <p className="text-sm font-medium">No experiments recorded yet</p>
                  <p className="mt-1 text-sm" style={{ color: 'var(--color-muted-foreground)' }}>
                    Run the research harness to populate this table.
                  </p>
                  <p
                    className="mt-3 text-xs font-mono px-3 py-1.5 inline-block border"
                    style={{
                      borderColor: 'var(--color-border)',
                      color: 'var(--color-muted-foreground)',
                    }}
                  >
                    python -m research.harness --platform aws --runs 3
                  </p>
                </>
              )}
            </div>
          ) : (
            <div className="border overflow-hidden" style={{ borderColor: 'var(--color-border)' }}>
              <div className="overflow-x-auto">
                <table className="w-full text-sm">
                  <thead>
                    <tr style={{ borderBottom: `1px solid var(--color-border)` }}>
                      {['Run', 'Key', 'Detection', 'Report', 'Expected', 'Actual', 'Status'].map(
                        (h) => (
                          <th
                            key={h}
                            className="text-left px-4 py-2.5 text-[11px] font-semibold uppercase tracking-wider"
                            style={{ color: 'var(--color-muted-foreground)' }}
                          >
                            {h}
                          </th>
                        )
                      )}
                    </tr>
                  </thead>
                  <tbody>
                    {runs.map((run, i) => (
                      <tr
                        key={run.run_id}
                        style={{ borderBottom: i < runs.length - 1 ? `1px solid var(--color-border)` : 'none' }}
                      >
                        <td className="px-4 py-2.5 font-mono text-xs">{i + 1}</td>
                        <td className="px-4 py-2.5 font-mono text-xs">
                          {run.access_key_id ? `${run.access_key_id.slice(0, 16)}…` : '—'}
                        </td>
                        <td className="px-4 py-2.5 font-mono text-xs">
                          {run.detection_time_s !== null ? `${run.detection_time_s.toFixed(1)}s` : '—'}
                        </td>
                        <td className="px-4 py-2.5 font-mono text-xs">
                          {run.report_time_s !== null ? `${run.report_time_s.toFixed(1)}s` : '—'}
                        </td>
                        <td className="px-4 py-2.5 text-xs">{run.expected_severity ?? '—'}</td>
                        <td className="px-4 py-2.5 text-xs">{run.actual_severity ?? '—'}</td>
                        <td className="px-4 py-2.5 text-xs capitalize">{run.status ?? '—'}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          )}
        </div>
      </section>
    </div>
  )
}

export default Research
