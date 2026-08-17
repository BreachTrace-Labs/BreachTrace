import { useEffect, useMemo, useRef, useState } from 'react'
import * as d3 from 'd3'
import type { ForensicEvent } from '../types'
import { derivePlatform, PLATFORM_META, type Platform } from '@/lib/platform'
import { Card, CardHeader, CardTitle, CardContent } from '@/components/ui/card'
import { Clock } from 'lucide-react'

interface Props {
  events: ForensicEvent[]
}

const SEV_COLOR: Record<number, string> = {
  1: 'var(--color-sev-low)',
  2: 'var(--color-sev-medium)',
  3: 'var(--color-sev-high)',
  4: 'var(--color-sev-critical)',
}

const CAT_LABEL: Record<string, string> = {
  reconnaissance:       'Recon',
  data_access:          'Data Access',
  exfiltration:         'Exfiltration',
  resource_abuse:       'Resource Abuse',
  privilege_escalation: 'Priv Esc',
  financial_abuse:      'Financial',
  communication_abuse:  'Comms',
  code_compromise:      'Code',
}

const CAT_COLOR: Record<string, string> = {
  reconnaissance:       'var(--color-sev-low)',
  data_access:          'var(--color-sev-medium)',
  exfiltration:         'var(--color-sev-critical)',
  resource_abuse:       'var(--color-sev-high)',
  privilege_escalation: 'var(--color-sev-critical)',
  financial_abuse:      'var(--color-sev-high)',
  communication_abuse:  'var(--color-sev-medium)',
  code_compromise:      'var(--color-sev-critical)',
}

function fmtDate(d: Date) {
  return d.toLocaleDateString('en-US', {
    weekday: 'short', year: 'numeric', month: 'short', day: 'numeric',
  })
}

function fmtTime(d: Date) {
  return d.toLocaleTimeString('en-US', {
    hour12: false, hour: '2-digit', minute: '2-digit', second: '2-digit',
  })
}

/**
 * Glyph per platform, so a greyscale print still distinguishes the streams.
 *
 * Only Tier-1 platforms ever plot here — Tier-2 incidents render the
 * ForensicsUnavailable panel instead of a timeline — but the map is total so
 * that adding a platform cannot produce an undefined symbol at runtime.
 */
const PLATFORM_SYMBOL: Record<Platform, d3.SymbolType> = {
  aws: d3.symbolCircle,
  gcp: d3.symbolSquare,
  azure: d3.symbolDiamond,
  stripe: d3.symbolTriangle,
  twilio: d3.symbolStar,
  // Tier 2: unreachable in practice, kept for exhaustiveness.
  github: d3.symbolCross,
  slack: d3.symbolCross,
  npm: d3.symbolCross,
  sendgrid: d3.symbolCross,
  huggingface: d3.symbolCross,
  db: d3.symbolCross,
}

/**
 * Y-axis row key. A single exposure can leak credentials for more than one
 * platform, and two platforms can expose services with colliding names, so the
 * row identity has to be (platform, service) rather than service alone.
 */
/** Separator kept as an explicit escape: it can never occur in a service name,
    and writing it literally would put a raw NUL byte in this file. */
const ROW_SEP = '\u0000'
const rowKey = (platform: Platform, source: string) => `${platform}${ROW_SEP}${source}`
const rowSource = (key: string) => key.split(ROW_SEP)[1]
const rowPlatform = (key: string) => key.split(ROW_SEP)[0] as Platform

type EnrichedEvent = ForensicEvent & {
  ts: Date
  source: string
  plat: Platform
  row: string
}

const ForensicTimeline: React.FC<Props> = ({ events }) => {
  const svgRef      = useRef<SVGSVGElement | null>(null)
  const wrapperRef  = useRef<HTMLDivElement | null>(null)
  const tooltipRef  = useRef<HTMLDivElement | null>(null)

  const data = useMemo<EnrichedEvent[]>(() => {
    return events
      .filter(e => !!e.timestamp)
      .map(e => {
        const plat = derivePlatform(e)
        const source = e.event_source || 'unknown-service'
        return { ...e, ts: new Date(e.timestamp), source, plat, row: rowKey(plat, source) }
      })
      .sort((a, b) => a.ts.getTime() - b.ts.getTime())
  }, [events])

  /* Platforms present, in a stable order, for the legend and axis grouping */
  const platformsPresent = useMemo<Platform[]>(() => {
    const seen = new Set(data.map(d => d.plat))
    return (['aws', 'gcp', 'azure'] as Platform[]).filter(p => seen.has(p))
  }, [data])

  const isMultiPlatform = platformsPresent.length > 1

  /* Grouped by calendar date for the list view */
  const grouped = useMemo(() => {
    const groups: { date: string; events: EnrichedEvent[] }[] = []
    for (const e of data) {
      const dateKey = e.ts.toDateString()
      const last = groups[groups.length - 1]
      if (!last || last.events[0].ts.toDateString() !== dateKey) {
        groups.push({ date: fmtDate(e.ts), events: [e] })
      } else {
        last.events.push(e)
      }
    }
    return groups
  }, [data])

  /* Track the container width.
     The first chart render happens before layout, so clientWidth reads 0 and the
     chart fell back to a hard-coded 760px — wider than its container, so the
     right edge of the time axis was clipped. Observing the element keeps the
     chart correct on first paint and on window resize. */
  const [chartWidth, setChartWidth] = useState(0)

  useEffect(() => {
    const el = wrapperRef.current
    if (!el) return

    const observer = new ResizeObserver(([entry]) => {
      setChartWidth(entry.contentRect.width)
    })
    observer.observe(el)
    setChartWidth(el.clientWidth)
    return () => observer.disconnect()
  }, [])

  /* Create tooltip div once on mount */
  useEffect(() => {
    if (!wrapperRef.current) return
    const div = document.createElement('div')
    Object.assign(div.style, {
      position:     'absolute',
      pointerEvents: 'none',
      padding:      '8px 10px',
      background:   'var(--color-card)',
      border:       '1px solid var(--color-border)',
      borderRadius: '6px',
      boxShadow:    '0 10px 30px rgba(0,0,0,0.18)',
      fontSize:     '11px',
      color:        'var(--color-foreground)',
      opacity:      '0',
      maxWidth:     '260px',
      lineHeight:   '1.5',
      zIndex:       '20',
    })
    wrapperRef.current.appendChild(div)
    tooltipRef.current = div
    return () => { div.remove(); tooltipRef.current = null }
  }, [])

  /* D3 scatter chart */
  useEffect(() => {
    const svg = d3.select(svgRef.current)
    svg.selectAll('*').remove()
    if (data.length === 0 || chartWidth === 0) return

    const width = chartWidth

    // Rows are (platform, service) pairs. Grow the chart with the row count so a
    // multi-platform incident does not crush its bands into unreadable slivers.
    const rows = Array.from(new Set(data.map(d => d.row))).sort((a, b) => {
      const pa = platformsPresent.indexOf(rowPlatform(a))
      const pb = platformsPresent.indexOf(rowPlatform(b))
      return pa !== pb ? pa - pb : rowSource(a).localeCompare(rowSource(b))
    })

    const height = Math.max(230, 72 + rows.length * 34)

    // Derive the left gutter from the longest service label rather than fixing
    // it: a hard-coded margin let long names (storage.googleapis.com) run into
    // the platform bracket. Labels are capped so one outlier cannot eat the plot.
    const MAX_LABEL_CHARS = 24
    const CHAR_PX = 6.2               // ~11px sans-serif average advance
    const BRACKET_PX = isMultiPlatform ? 46 : 0
    const truncate = (s: string) =>
      s.length > MAX_LABEL_CHARS ? s.slice(0, MAX_LABEL_CHARS - 1) + '…' : s

    const longestLabel = rows.reduce(
      (max, r) => Math.max(max, truncate(rowSource(r)).length),
      0,
    )
    const labelPx = Math.ceil(longestLabel * CHAR_PX) + 12
    const margin = {
      top: 20,
      right: 20,
      bottom: 52,
      left: Math.min(260, Math.max(110, BRACKET_PX + labelPx)),
    }
    const iW = width  - margin.left - margin.right
    const iH = height - margin.top  - margin.bottom

    svg.attr('width', width).attr('height', height)

    const g = svg.append('g').attr('transform', `translate(${margin.left},${margin.top})`)

    const minTime = data[0].ts
    const maxTime = data[data.length - 1].ts
    const pad     = 1000 * 30

    const x = d3.scaleTime()
      .domain([new Date(minTime.getTime() - pad), new Date(maxTime.getTime() + pad)])
      .range([0, iW])

    const y = d3.scaleBand()
      .domain(rows)
      .range([0, iH])
      .padding(0.3)

    /* X-axis — always includes date so the axis is unambiguous */
    const spanMs = maxTime.getTime() - minTime.getTime()
    const fmt    = spanMs > 23 * 3600 * 1000
      ? d3.timeFormat('%b %d')       // multi-day: just the date
      : d3.timeFormat('%b %d %H:%M') // same-day: date + time

    const xAxis = d3.axisBottom<Date>(x)
      .ticks(Math.min(6, Math.max(3, Math.floor(iW / 120))))
      .tickSizeOuter(0)
      .tickFormat(fmt)

    g.append('g')
      .attr('transform', `translate(0,${iH})`)
      .call(xAxis)
      .selectAll('text')
      .style('fill', 'var(--color-muted-foreground)')
      .style('font-size', '10px')
      .attr('text-anchor', 'end')
      .attr('dx', '-0.4em')
      .attr('dy', '0.2em')
      .attr('transform', 'rotate(-30)')

    // Y labels show the service; the platform is carried by the bracket and the
    // glyph, so repeating it on every row would just be noise.
    const yAxis = d3.axisLeft<string>(y).tickSize(0).tickFormat(k => truncate(rowSource(k)))
    g.append('g')
      .call(yAxis)
      .selectAll('text')
      .style('fill', 'var(--color-muted-foreground)')
      .style('font-size', '11px')

    g.selectAll('.domain, .tick line').style('stroke', 'var(--color-border)')

    /* Platform brackets — a labelled colour bar spanning each platform's rows */
    if (isMultiPlatform) {
      const bracket = g.append('g').attr('class', 'platform-brackets')

      for (const platform of platformsPresent) {
        const platformRows = rows.filter(r => rowPlatform(r) === platform)
        if (platformRows.length === 0) continue

        const top    = y(platformRows[0]) ?? 0
        const lastRow = platformRows[platformRows.length - 1]
        const bottom = (y(lastRow) ?? 0) + y.bandwidth()
        const meta   = PLATFORM_META[platform]

        bracket.append('rect')
          .attr('x', -margin.left + 8)
          .attr('y', top)
          .attr('width', 3)
          .attr('height', Math.max(0, bottom - top))
          .attr('rx', 1.5)
          .attr('fill', meta.color)

        bracket.append('text')
          .attr('x', -margin.left + 17)
          .attr('y', top + (bottom - top) / 2)
          .attr('dy', '0.32em')
          .style('fill', meta.color)
          .style('font-size', '10px')
          .style('font-weight', '700')
          .style('letter-spacing', '0.05em')
          .text(meta.label)
      }
    }

    /* Grid lines.
       The axis generator also emits a `path.domain` outlining the plot area.
       It inherits `currentColor` — a solid white bracket around the chart in
       dark mode — so it is dropped off the grid selection directly. */
    const grid = g.append('g')
      .attr('class', 'grid')
      .call(
        d3.axisLeft<string>(y)
          .tickSize(-iW)
          .tickFormat(() => '')
      )

    grid.select('.domain').remove()
    grid.selectAll('line')
      .style('stroke', 'var(--color-border)')
      .style('stroke-opacity', '0.4')
      .style('stroke-dasharray', '2,4')

    const tooltip = d3.select(tooltipRef.current)

    g.selectAll('path.event-node')
      .data(data)
      .enter()
      .append('path')
      .attr('class', 'event-node')
      // Glyph encodes platform, fill encodes severity — the two channels stay
      // independent so severity is still readable within a single platform.
      .attr('d', (d) => d3.symbol().type(PLATFORM_SYMBOL[d.plat]).size(120)())
      .attr('transform', (d) => `translate(${x(d.ts)}, ${(y(d.row) ?? 0) + y.bandwidth() / 2})`)
      .attr('fill', (d) => SEV_COLOR[d.severity_weight || 1] || 'var(--color-muted-foreground)')
      .attr('stroke', 'var(--color-background)')
      .attr('stroke-width', 1.5)
      .style('cursor', 'pointer')
      .on('mouseenter', function(event, d) {
        const time = d.ts.toLocaleString('en-US', {
          month: 'short', day: 'numeric',
          hour: '2-digit', minute: '2-digit', second: '2-digit',
          hour12: false,
        })
        const node = tooltipRef.current!
        node.textContent = ''

        const b = document.createElement('div')
        b.style.fontWeight = '700'
        b.style.marginBottom = '3px'
        b.textContent = d.api_action

        const plat = document.createElement('div')
        plat.style.color = PLATFORM_META[d.plat].color
        plat.style.fontSize = '10px'
        plat.style.fontWeight = '700'
        plat.style.textTransform = 'uppercase'
        plat.style.letterSpacing = '0.05em'
        plat.style.marginBottom = '3px'
        plat.textContent = `${PLATFORM_META[d.plat].label} · ${PLATFORM_META[d.plat].auditLog}`

        const l2 = document.createElement('div')
        l2.textContent = `${time} · ${d.source_ip ?? 'unknown IP'}`

        const l3 = document.createElement('div')
        l3.textContent = d.affected_resource ?? 'no resource recorded'
        l3.style.color = 'var(--color-foreground)'
        l3.style.fontFamily = 'monospace'
        l3.style.fontSize = '10px'
        l3.style.marginTop = '2px'

        const l4 = document.createElement('div')
        l4.style.color = 'var(--color-muted-foreground)'
        l4.style.marginTop = '4px'
        l4.style.fontSize = '10px'
        l4.textContent = `Mapped to ${d.impact_category ?? 'unclassified'} because action = ${d.api_action}`

        node.append(plat, b, l2, l3, l4)
        const [mx, my] = d3.pointer(event, wrapperRef.current)
        tooltip
          .style('opacity', 1)
          .style('left', `${mx + 12}px`)
          .style('top', `${my - 10}px`)
      })
      .on('mousemove', function(event) {
        const [mx, my] = d3.pointer(event, wrapperRef.current)
        const node = tooltipRef.current!
        const boxW = node.offsetWidth  || 200
        const boxH = node.offsetHeight || 80
        const left = mx + 14 + boxW > (wrapperRef.current?.clientWidth ?? 999) ? mx - boxW - 8 : mx + 14
        tooltip.style('left', `${left}px`).style('top', `${Math.max(0, my - boxH / 2)}px`)
      })
      .on('mouseleave', function() {
        tooltip.style('opacity', 0)
        d3.select(this).attr('r', 6).attr('stroke-width', 1.5)
      })

    return () => { svg.selectAll('*').remove() }
  }, [data, platformsPresent, isMultiPlatform, chartWidth])

  return (
    <Card>
      <CardHeader className="pb-3">
        <CardTitle className="flex items-center gap-2 text-sm">
          <Clock size={13} strokeWidth={2} />
          Forensic Timeline
          {isMultiPlatform && (
            <span
              className="text-[11px] font-bold px-1.5 py-0.5 rounded uppercase tracking-wider"
              style={{
                backgroundColor: 'color-mix(in srgb, var(--color-sev-critical) 14%, transparent)',
                color: 'var(--color-sev-critical)',
              }}
              title="This exposure affected more than one cloud platform"
            >
              {platformsPresent.length} platforms
            </span>
          )}
          {grouped.length > 1 && (
            <span
              className="text-[11px] font-mono px-1.5 py-0.5 rounded"
              style={{ backgroundColor: 'var(--color-muted)', color: 'var(--color-muted-foreground)' }}
            >
              {grouped.length} days
            </span>
          )}
          <span
            className="ml-auto text-xs font-mono px-1.5 py-0.5 rounded"
            style={{ backgroundColor: 'var(--color-muted)', color: 'var(--color-muted-foreground)' }}
          >
            {events.length} events
          </span>
        </CardTitle>
      </CardHeader>

      <CardContent className="p-0">
        {data.length === 0 ? (
          <p className="text-sm px-5 pb-5" style={{ color: 'var(--color-muted-foreground)' }}>
            No events collected yet
          </p>
        ) : (
          <>
            {/* ── D3 scatter chart ── */}
            <div
              ref={wrapperRef}
              className={`relative overflow-hidden${isMultiPlatform ? '' : ' border-b'}`}
              style={{ borderColor: 'var(--color-border)', minHeight: 230 }}
            >
              <svg ref={svgRef} />
            </div>

            {/* Legend — only earns its space when the glyphs actually differ */}
            {isMultiPlatform && (
              <div
                className="flex flex-wrap items-center gap-4 px-5 py-2.5 border-b"
                style={{ borderColor: 'var(--color-border)' }}
              >
                {platformsPresent.map(p => {
                  const meta = PLATFORM_META[p]
                  const count = data.filter(d => d.plat === p).length
                  return (
                    <span key={p} className="flex items-center gap-1.5">
                      <svg width="11" height="11" viewBox="-6 -6 12 12" aria-hidden="true">
                        <path
                          d={d3.symbol().type(PLATFORM_SYMBOL[p]).size(60)() ?? undefined}
                          fill={meta.color}
                        />
                      </svg>
                      <span
                        className="text-[11px] font-semibold"
                        style={{ color: 'var(--color-foreground)' }}
                      >
                        {meta.label}
                      </span>
                      <span
                        className="text-[11px] font-mono tabular-nums"
                        style={{ color: 'var(--color-muted-foreground)' }}
                      >
                        {count}
                      </span>
                    </span>
                  )
                })}
                <span
                  className="ml-auto text-[11px]"
                  style={{ color: 'var(--color-muted-foreground)' }}
                >
                  Shape = platform · Colour = severity
                </span>
              </div>
            )}

            {/* ── Vertical event list grouped by date ── */}
            <div className="max-h-140 overflow-y-auto">
              {grouped.map((group, gi) => (
                <div key={group.date}>
                  {/* Sticky date header */}
                  <div
                    className="sticky top-0 z-10 flex items-center gap-2.5 px-5 py-2"
                    style={{
                      backgroundColor: 'var(--color-muted)',
                      borderTop: gi > 0 ? '1px solid var(--color-border)' : undefined,
                      borderBottom: '1px solid var(--color-border)',
                    }}
                  >
                    <span
                      className="w-1.5 h-1.5 rounded-full shrink-0"
                      style={{ backgroundColor: 'var(--color-muted-foreground)' }}
                    />
                    <span
                      className="text-[11px] font-semibold uppercase tracking-widest"
                      style={{ color: 'var(--color-muted-foreground)' }}
                    >
                      {group.date}
                    </span>
                    <span
                      className="ml-auto text-[11px] font-mono"
                      style={{ color: 'var(--color-muted-foreground)', opacity: 0.7 }}
                    >
                      {group.events.length} event{group.events.length !== 1 ? 's' : ''}
                    </span>
                  </div>

                  {/* Event rows */}
                  {group.events.map((e, ei) => {
                    const sevColor = SEV_COLOR[e.severity_weight || 1] ?? 'var(--color-muted-foreground)'
                    const catColor = CAT_COLOR[e.impact_category ?? ''] ?? 'var(--color-muted-foreground)'
                    const catLabel = e.impact_category ? (CAT_LABEL[e.impact_category] ?? e.impact_category) : null
                    const isLast   = ei === group.events.length - 1

                    return (
                      <div
                        key={e.event_id}
                        className="flex items-start gap-3 px-5 py-3"
                        style={{ borderBottom: !isLast ? '1px solid var(--color-border)' : undefined }}
                      >
                        {/* Time */}
                        <span
                          className="text-[11px] font-mono shrink-0 tabular-nums"
                          style={{ color: 'var(--color-muted-foreground)', width: 58, paddingTop: 3 }}
                        >
                          {fmtTime(e.ts)}
                        </span>

                        {/* Severity dot */}
                        <span
                          className="w-2 h-2 rounded-full shrink-0 mt-1"
                          style={{ backgroundColor: sevColor, boxShadow: `0 0 4px ${sevColor}60` }}
                        />

                        {/* Content */}
                        <div className="flex-1 min-w-0">
                          <div className="flex items-center gap-2 flex-wrap">
                            {isMultiPlatform && (
                              <span
                                className="shrink-0 text-[10px] font-bold px-1.5 py-0.5 rounded uppercase tracking-wider"
                                style={{
                                  backgroundColor: `color-mix(in srgb, ${PLATFORM_META[e.plat].color} 14%, transparent)`,
                                  color: PLATFORM_META[e.plat].color,
                                }}
                              >
                                {PLATFORM_META[e.plat].label}
                              </span>
                            )}
                            <span
                              className="text-sm font-semibold font-mono"
                              style={{ color: 'var(--color-foreground)' }}
                            >
                              {e.api_action}
                            </span>
                            {catLabel && (
                              <span
                                className="shrink-0 text-[10px] font-bold px-1.5 py-0.5 rounded uppercase tracking-wider"
                                style={{
                                  backgroundColor: `color-mix(in srgb, ${catColor} 15%, transparent)`,
                                  color: catColor,
                                }}
                              >
                                {catLabel}
                              </span>
                            )}
                            {!e.success && (
                              <span
                                className="shrink-0 text-[10px] font-bold px-1.5 py-0.5 rounded uppercase tracking-wider"
                                style={{
                                  backgroundColor: 'color-mix(in srgb, var(--color-muted-foreground) 12%, transparent)',
                                  color: 'var(--color-muted-foreground)',
                                }}
                              >
                                Denied
                              </span>
                            )}
                          </div>
                          <div className="flex items-center gap-1.5 mt-0.5 flex-wrap">
                            {e.event_source && (
                              <span className="text-[11px] font-mono" style={{ color: 'var(--color-muted-foreground)' }}>
                                {e.event_source}
                              </span>
                            )}
                            {e.source_ip && e.source_ip !== 'unknown' && (
                              <>
                                <span style={{ color: 'var(--color-border)' }}>·</span>
                                <span className="text-[11px] font-mono" style={{ color: 'var(--color-muted-foreground)' }}>
                                  {e.source_ip}
                                </span>
                              </>
                            )}
                            {e.affected_resource && (
                              <>
                                <span style={{ color: 'var(--color-border)' }}>·</span>
                                <span
                                  className="text-[11px] font-mono"
                                  style={{
                                    color: 'var(--color-muted-foreground)',
                                    maxWidth: 240,
                                    overflow: 'hidden',
                                    textOverflow: 'ellipsis',
                                    whiteSpace: 'nowrap',
                                    display: 'inline-block',
                                    verticalAlign: 'bottom',
                                  }}
                                  title={e.affected_resource}
                                >
                                  {e.affected_resource}
                                </span>
                              </>
                            )}
                          </div>
                        </div>
                      </div>
                    )
                  })}
                </div>
              ))}
            </div>
          </>
        )}
      </CardContent>
    </Card>
  )
}

export default ForensicTimeline
