import { useRef } from 'react'
import { Download } from 'lucide-react'
import { Card, CardHeader, CardTitle, CardContent } from '@/components/ui/card'
import { FORENSIC_PLATFORMS, PLATFORM_META, type Platform } from '@/lib/platform'
import type { PlatformComparison } from '@/types'

/**
 * Detection and report latency per platform — the paper's headline figure.
 *
 * Built as inline SVG rather than the CSS-div bar idiom used elsewhere: this
 * one needs a value axis, and it needs to serialise to a file for the paper.
 *
 * Encoding follows the rule ForensicTimeline already states — independent
 * channels, so nothing depends on colour alone:
 *   colour     = platform identity (never severity)
 *   fill style = metric (detection solid, report hatched)
 * Both tone and hatch survive greyscale conversion; hue does not.
 *
 * Direct labels rather than a legend: the value sits at each bar's end and the
 * metric names are written on the first group only.
 */

interface Props {
  data: PlatformComparison | null
}

const VIEW_W = 720
const LABEL_W = 96          // platform name gutter
const VALUE_W = 62          // room for '123.4s' past the bar end
const ROW_H = 52            // one platform: two bars + gap
const BAR_H = 15
const BAR_GAP = 5
const TOP_PAD = 26
const AXIS_H = 34
const PLOT_W = VIEW_W - LABEL_W - VALUE_W

const TICK_COUNT = 5

function niceMax(value: number): number {
  if (value <= 0) return 1
  const raw = value * 1.08
  const magnitude = 10 ** Math.floor(Math.log10(raw))
  return Math.ceil(raw / magnitude) * magnitude
}

/** Platforms in a stable order, unknown keys appended rather than dropped. */
function orderedPlatforms(data: PlatformComparison): string[] {
  const known = FORENSIC_PLATFORMS.filter(p => p in data.by_platform) as string[]
  const extra = Object.keys(data.by_platform).filter(p => !known.includes(p))
  return [...known, ...extra]
}

function platformColor(platform: string): string {
  return PLATFORM_META[platform as Platform]?.color ?? 'var(--color-muted-foreground)'
}

function platformLabel(platform: string): string {
  return PLATFORM_META[platform as Platform]?.label ?? platform.toUpperCase()
}

/**
 * Resolve `var(--x)` to a literal colour.
 *
 * A detached .svg has no stylesheet, so custom properties resolve to nothing
 * and the exported figure comes out blank. Theme here is driven by a
 * prefers-color-scheme media query, so this has to happen at export time.
 */
function resolveCssVars(markup: string): string {
  const root = getComputedStyle(document.documentElement)
  return markup.replace(/var\((--[^)]+)\)/g, (_match, name: string) => {
    return root.getPropertyValue(name).trim() || '#888888'
  })
}

const PlatformLatencyChart: React.FC<Props> = ({ data }) => {
  const svgRef = useRef<SVGSVGElement | null>(null)

  const platforms = data ? orderedPlatforms(data) : []

  if (!data || platforms.length === 0) {
    return (
      <Card>
        <CardHeader className="pb-3">
          <CardTitle className="text-sm">Pipeline Latency by Platform</CardTitle>
        </CardHeader>
        <CardContent>
          <p className="text-sm" style={{ color: 'var(--color-muted-foreground)' }}>
            No experiment runs recorded yet. Run the harness to populate this figure.
          </p>
        </CardContent>
      </Card>
    )
  }

  const rows = platforms.map(platform => {
    const stats = data.by_platform[platform]
    return {
      platform,
      detection: stats.detection_time_s.mean,
      report: stats.report_time_s.mean,
      n: stats.detection_time_s.n,
    }
  })

  const values = rows.flatMap(r => [r.detection, r.report]).filter((v): v is number => v !== null)
  const max = niceMax(values.length > 0 ? Math.max(...values) : 0)
  const height = TOP_PAD + rows.length * ROW_H + AXIS_H
  const scale = (v: number) => (v / max) * PLOT_W

  const handleExport = () => {
    if (!svgRef.current) return
    const clone = svgRef.current.cloneNode(true) as SVGSVGElement
    clone.setAttribute('xmlns', 'http://www.w3.org/2000/svg')
    const blob = new Blob([resolveCssVars(new XMLSerializer().serializeToString(clone))], {
      type: 'image/svg+xml;charset=utf-8',
    })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = 'breachtrace-latency-by-platform.svg'
    a.click()
    URL.revokeObjectURL(url)
  }

  return (
    <Card>
      <CardHeader className="pb-3">
        <CardTitle className="flex items-center gap-2 text-sm">
          Pipeline Latency by Platform
          <span
            className="text-[11px] font-mono px-1.5 py-0.5 rounded"
            style={{ backgroundColor: 'var(--color-muted)', color: 'var(--color-muted-foreground)' }}
          >
            {data.total_runs} runs
          </span>
          <button
            onClick={handleExport}
            className="ml-auto inline-flex items-center gap-1 text-[11px] hover:underline"
            style={{ color: 'var(--color-muted-foreground)' }}
            title="Download as SVG for the paper"
          >
            <Download size={11} strokeWidth={2} />
            SVG
          </button>
        </CardTitle>
      </CardHeader>

      <CardContent className="p-0 pb-4">
        <div className="overflow-x-auto px-5">
          <svg
            ref={svgRef}
            viewBox={`0 0 ${VIEW_W} ${height}`}
            style={{ width: '100%', height: 'auto', minWidth: 480 }}
            role="img"
            aria-label="Mean detection and report latency per platform"
          >
            <defs>
              {/* Hatch distinguishes report from detection without relying on
                  colour, so the figure survives greyscale printing. */}
              <pattern
                id="latency-hatch"
                patternUnits="userSpaceOnUse"
                width="5"
                height="5"
                patternTransform="rotate(45)"
              >
                <line
                  x1="0" y1="0" x2="0" y2="5"
                  stroke="var(--color-foreground)"
                  strokeWidth="1.6"
                  opacity="0.45"
                />
              </pattern>
            </defs>

            {/* Gridlines behind the bars */}
            {Array.from({ length: TICK_COUNT + 1 }, (_, i) => {
              const value = (max / TICK_COUNT) * i
              const x = LABEL_W + scale(value)
              return (
                <g key={i}>
                  <line
                    x1={x} y1={TOP_PAD - 8} x2={x} y2={TOP_PAD + rows.length * ROW_H}
                    stroke="var(--color-border)"
                    strokeWidth={1}
                  />
                  <text
                    x={x}
                    y={TOP_PAD + rows.length * ROW_H + 16}
                    textAnchor="middle"
                    fontSize="10"
                    fontFamily="var(--font-mono)"
                    fill="var(--color-muted-foreground)"
                  >
                    {value.toFixed(0)}s
                  </text>
                </g>
              )
            })}

            {rows.map((row, index) => {
              const top = TOP_PAD + index * ROW_H
              const detectionY = top + 4
              const reportY = detectionY + BAR_H + BAR_GAP
              const color = platformColor(row.platform)
              const hasData = row.detection !== null || row.report !== null

              return (
                <g key={row.platform}>
                  <text
                    x={0} y={detectionY + BAR_H - 2}
                    fontSize="12" fontWeight="600"
                    fill="var(--color-foreground)"
                  >
                    {platformLabel(row.platform)}
                  </text>
                  {/* Sample size — a figure without n is not publication quality. */}
                  <text
                    x={0} y={reportY + BAR_H - 2}
                    fontSize="10"
                    fontFamily="var(--font-mono)"
                    fill="var(--color-muted-foreground)"
                  >
                    n={row.n}
                  </text>

                  {/* A platform with no timings gets no bar and says so.
                      Rendering `?? 0` here would undo analysis.py's decision to
                      return null rather than 0.0, and put a fabricated
                      "0 seconds" in the paper. */}
                  {!hasData && (
                    <text
                      x={LABEL_W + 4} y={detectionY + BAR_H + 4}
                      fontSize="11" fontStyle="italic"
                      fill="var(--color-muted-foreground)"
                    >
                      no timing data
                    </text>
                  )}

                  {row.detection !== null && (
                    <>
                      <rect
                        x={LABEL_W} y={detectionY}
                        width={Math.max(scale(row.detection), 1)} height={BAR_H}
                        fill={color}
                      />
                      <text
                        x={LABEL_W + scale(row.detection) + 6} y={detectionY + BAR_H - 3}
                        fontSize="11" fontFamily="var(--font-mono)"
                        fill="var(--color-foreground)"
                      >
                        {row.detection.toFixed(1)}s
                      </text>
                    </>
                  )}

                  {row.report !== null && (
                    <>
                      <rect
                        x={LABEL_W} y={reportY}
                        width={Math.max(scale(row.report), 1)} height={BAR_H}
                        fill={color} opacity={0.35}
                      />
                      <rect
                        x={LABEL_W} y={reportY}
                        width={Math.max(scale(row.report), 1)} height={BAR_H}
                        fill="url(#latency-hatch)"
                      />
                      <text
                        x={LABEL_W + scale(row.report) + 6} y={reportY + BAR_H - 3}
                        fontSize="11" fontFamily="var(--font-mono)"
                        fill="var(--color-foreground)"
                      >
                        {row.report.toFixed(1)}s
                      </text>
                    </>
                  )}

                  {/* Direct labels on the first group only — no legend needed. */}
                  {index === 0 && (
                    <>
                      <text
                        x={LABEL_W + 6} y={detectionY + BAR_H - 3}
                        fontSize="10" fontWeight="600"
                        fill="var(--color-background)"
                      >
                        detection
                      </text>
                      <text
                        x={LABEL_W + 6} y={reportY + BAR_H - 3}
                        fontSize="10" fontWeight="600"
                        fill="var(--color-foreground)"
                      >
                        report
                      </text>
                    </>
                  )}
                </g>
              )
            })}
          </svg>
        </div>

        <p className="px-5 pt-2 text-[11px]" style={{ color: 'var(--color-muted-foreground)' }}>
          Mean seconds from credential exposure to detection, and to a completed
          forensic report. Lower is better.
        </p>
      </CardContent>
    </Card>
  )
}

export default PlatformLatencyChart
