import type { ForensicEvent } from '../types'

interface Props {
  events: ForensicEvent[]
}

const SEV_LABELS: Record<number, string> = {
  4: 'Critical',
  3: 'High',
  2: 'Medium',
  1: 'Low',
}

const SEV_COLORS: Record<number, string> = {
  4: 'var(--color-sev-critical)',
  3: 'var(--color-sev-high)',
  2: 'var(--color-sev-medium)',
  1: 'var(--color-sev-low)',
}

/* ── shared horizontal bar ── */
function HBar({
  label,
  count,
  max,
  color,
  labelWidth = 88,
}: {
  label: string
  count: number
  max: number
  color: string
  labelWidth?: number
}) {
  return (
    <div className="flex items-center gap-3">
      <span
        className="text-[11px] font-mono shrink-0 truncate"
        style={{ color: 'var(--color-foreground)', width: labelWidth }}
        title={label}
      >
        {label}
      </span>
      <div
        className="flex-1 h-1.5 rounded-full overflow-hidden"
        style={{ backgroundColor: 'var(--color-muted)' }}
      >
        <div
          className="h-full rounded-full transition-all duration-500"
          style={{
            width: `${max > 0 ? (count / max) * 100 : 0}%`,
            backgroundColor: color,
            opacity: count === 0 ? 0.2 : 1,
          }}
        />
      </div>
      <span
        className="text-xs font-mono tabular-nums shrink-0"
        style={{ color: 'var(--color-muted-foreground)', width: 24, textAlign: 'right' }}
      >
        {count}
      </span>
    </div>
  )
}

/* ── mini stat tile ── */
function StatTile({
  label,
  value,
  accent = false,
}: {
  label: string
  value: string | number
  accent?: boolean
}) {
  return (
    <div>
      <p
        className="text-[10px] uppercase tracking-wider font-semibold"
        style={{ color: 'var(--color-muted-foreground)' }}
      >
        {label}
      </p>
      <p
        className="text-xl font-bold font-mono mt-0.5 tabular-nums"
        style={{ color: accent ? 'var(--color-sev-critical)' : 'var(--color-foreground)' }}
      >
        {value}
      </p>
    </div>
  )
}

/* ── mini donut via SVG stroke-dasharray ── */
function MiniDonut({
  segments,
}: {
  segments: { color: string; pct: number }[]
}) {
  const r = 28
  const cx = 36
  const cy = 36
  const circ = 2 * Math.PI * r
  const gap = 1.5  // gap between segments in px

  const visibleSegments = segments.filter(s => s.pct > 0)

  return (
    <svg width={72} height={72} className="shrink-0">
      {/* Track */}
      <circle cx={cx} cy={cy} r={r} fill="none" stroke="var(--color-muted)" strokeWidth={10} />
      {visibleSegments
        .map((s, i) => {
          const offset = circ * (0.25 - visibleSegments.slice(0, i).reduce((sum, segment) => sum + segment.pct, 0))
          const dash   = Math.max(0, s.pct * circ - gap)
          const space  = circ - dash
          const circle = (
            <circle
              key={i}
              cx={cx}
              cy={cy}
              r={r}
              fill="none"
              stroke={s.color}
              strokeWidth={10}
              strokeDasharray={`${dash} ${space}`}
              strokeDashoffset={offset}
              strokeLinecap="butt"
            />
          )
          return circle
        })}
    </svg>
  )
}

const EventAnalytics: React.FC<Props> = ({ events }) => {
  if (events.length === 0) return null

  /* ── severity breakdown ── */
  const sevCounts = ([4, 3, 2, 1] as const).map(sev => ({
    sev,
    count: events.filter(e => e.severity_weight === sev).length,
  }))
  const maxSev = Math.max(...sevCounts.map(s => s.count), 1)

  /* ── donut segments ── */
  const total = events.length
  const donutSegments = sevCounts.map(s => ({
    color: SEV_COLORS[s.sev],
    pct:   s.count / total,
  }))

  /* ── top API actions ── */
  const actionCounts = events.reduce<Record<string, number>>((acc, e) => {
    acc[e.api_action] = (acc[e.api_action] ?? 0) + 1
    return acc
  }, {})
  const topActions = Object.entries(actionCounts)
    .sort((a, b) => b[1] - a[1])
    .slice(0, 6)
  const maxAction = Math.max(...topActions.map(a => a[1]), 1)

  /* ── key metrics ── */
  const uniqueIPs       = new Set(events.filter(e => e.source_ip).map(e => e.source_ip!)).size
  const uniqueResources = new Set(events.filter(e => e.affected_resource).map(e => e.affected_resource!)).size
  const failed          = events.filter(e => !e.success).length
  const successRate     = Math.round((events.filter(e => e.success).length / total) * 100)

  return (
    <div>
      <h2 className="text-sm font-semibold mb-3">Event Analytics</h2>

      <div
        className="grid grid-cols-1 sm:grid-cols-3 gap-px border"
        style={{ backgroundColor: 'var(--color-border)', borderColor: 'var(--color-border)' }}
      >
        {/* ── Panel 1: Severity breakdown ── */}
        <div className="p-5" style={{ backgroundColor: 'var(--color-card)' }}>
          <p
            className="text-[11px] font-semibold uppercase tracking-widest mb-4"
            style={{ color: 'var(--color-muted-foreground)' }}
          >
            Event Severity
          </p>

          <div className="flex items-start gap-4">
            {/* Donut */}
            <div className="relative shrink-0">
              <MiniDonut segments={donutSegments} />
              <div
                className="absolute inset-0 flex flex-col items-center justify-center"
                style={{ pointerEvents: 'none' }}
              >
                <span className="text-sm font-bold font-mono">{total}</span>
                <span
                  className="text-[9px] uppercase tracking-wider"
                  style={{ color: 'var(--color-muted-foreground)' }}
                >
                  events
                </span>
              </div>
            </div>

            {/* Bars */}
            <div className="flex-1 space-y-2.5 pt-1">
              {sevCounts.map(({ sev, count }) => (
                <HBar
                  key={sev}
                  label={SEV_LABELS[sev]}
                  count={count}
                  max={maxSev}
                  color={SEV_COLORS[sev]}
                  labelWidth={52}
                />
              ))}
            </div>
          </div>
        </div>

        {/* ── Panel 2: Top API calls ── */}
        <div className="p-5" style={{ backgroundColor: 'var(--color-card)' }}>
          <p
            className="text-[11px] font-semibold uppercase tracking-widest mb-4"
            style={{ color: 'var(--color-muted-foreground)' }}
          >
            Top API Calls
          </p>
          <div className="space-y-2.5">
            {topActions.map(([action, count]) => (
              <HBar
                key={action}
                label={action}
                count={count}
                max={maxAction}
                color="var(--color-muted-foreground)"
                labelWidth={100}
              />
            ))}
          </div>
        </div>

        {/* ── Panel 3: Key metrics ── */}
        <div className="p-5" style={{ backgroundColor: 'var(--color-card)' }}>
          <p
            className="text-[11px] font-semibold uppercase tracking-widest mb-4"
            style={{ color: 'var(--color-muted-foreground)' }}
          >
            Key Metrics
          </p>

          <div className="grid grid-cols-2 gap-x-6 gap-y-4">
            <StatTile label="Total Events"  value={total} />
            <StatTile label="Unique IPs"    value={uniqueIPs} />
            <StatTile label="Resources"     value={uniqueResources} />
            <StatTile label="Failed"        value={failed}       accent={failed > 0} />
            <StatTile label="Success Rate"  value={`${successRate}%`} accent={successRate < 50} />
            <StatTile
              label="Unclassified"
              value={events.filter(e => !e.impact_category).length}
            />
          </div>

          {/* Failure rate */}
          {failed > 0 && (
            <div className="mt-4 pt-3 border-t" style={{ borderColor: 'var(--color-border)' }}>
              <p
                className="text-[10px] uppercase tracking-wider font-semibold mb-2"
                style={{ color: 'var(--color-muted-foreground)' }}
              >
                Allowed vs Denied
              </p>
              <div
                className="flex h-2 rounded-full overflow-hidden"
              >
                <div
                  className="h-full transition-all"
                  style={{
                    width: `${successRate}%`,
                    backgroundColor: 'var(--color-sev-low)',
                  }}
                />
                <div
                  className="h-full transition-all"
                  style={{
                    width: `${100 - successRate}%`,
                    backgroundColor: 'var(--color-sev-critical)',
                  }}
                />
              </div>
              <div className="flex justify-between mt-1">
                <span className="text-[10px] font-mono" style={{ color: 'var(--color-sev-low)' }}>
                  {successRate}% allowed
                </span>
                <span className="text-[10px] font-mono" style={{ color: 'var(--color-sev-critical)' }}>
                  {100 - successRate}% failed
                </span>
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  )
}

export default EventAnalytics
