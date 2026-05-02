import { useEffect, useMemo, useRef } from 'react'
import * as d3 from 'd3'
import type { ForensicEvent } from '../types'
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

type EnrichedEvent = ForensicEvent & { ts: Date; source: string }

const ForensicTimeline: React.FC<Props> = ({ events }) => {
  const svgRef      = useRef<SVGSVGElement | null>(null)
  const wrapperRef  = useRef<HTMLDivElement | null>(null)
  const tooltipRef  = useRef<HTMLDivElement | null>(null)

  const data = useMemo<EnrichedEvent[]>(() => {
    return events
      .filter(e => !!e.timestamp)
      .map(e => ({ ...e, ts: new Date(e.timestamp), source: e.event_source || 'unknown-service' }))
      .sort((a, b) => a.ts.getTime() - b.ts.getTime())
  }, [events])

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
    if (data.length === 0) return

    const container = d3.select(wrapperRef.current)
    const width   = container.node()?.clientWidth || 760
    const height  = 230
    const margin  = { top: 20, right: 20, bottom: 52, left: 130 }
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

    const services = Array.from(new Set(data.map(d => d.source)))
    const y = d3.scaleBand()
      .domain(services)
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

    const yAxis = d3.axisLeft<string>(y).tickSize(0)
    g.append('g')
      .call(yAxis)
      .selectAll('text')
      .style('fill', 'var(--color-muted-foreground)')
      .style('font-size', '11px')

    g.selectAll('.domain, .tick line').style('stroke', 'var(--color-border)')

    /* Grid lines */
    g.append('g')
      .attr('class', 'grid')
      .call(
        d3.axisLeft<string>(y)
          .tickSize(-iW)
          .tickFormat(() => '')
      )
      .selectAll('line')
      .style('stroke', 'var(--color-border)')
      .style('stroke-opacity', '0.4')
      .style('stroke-dasharray', '2,4')
    g.select('.grid .domain').remove()

    const tooltip = d3.select(tooltipRef.current)

    /* Event circles */
    g.selectAll('circle')
      .data(data)
      .enter()
      .append('circle')
      .attr('cx', d => x(d.ts))
      .attr('cy', d => (y(d.source) ?? 0) + y.bandwidth() / 2)
      .attr('r', 6)
      .attr('fill', d => SEV_COLOR[d.severity_weight || 1] ?? 'var(--color-muted-foreground)')
      .attr('stroke', 'var(--color-background)')
      .attr('stroke-width', 1.5)
      .style('cursor', 'pointer')
      .on('mouseenter', function(_event, d) {
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

        node.append(b, l2, l3, l4)
        tooltip.style('opacity', 1)

        d3.select(this)
          .attr('r', 8)
          .attr('stroke-width', 2)
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
  }, [data])

  return (
    <Card>
      <CardHeader className="pb-3">
        <CardTitle className="flex items-center gap-2 text-sm">
          <Clock size={13} strokeWidth={2} />
          Forensic Timeline
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
              className="relative overflow-hidden border-b"
              style={{ borderColor: 'var(--color-border)', minHeight: 230 }}
            >
              <svg ref={svgRef} />
            </div>

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
