import { useEffect, useMemo, useRef } from 'react'
import * as d3 from 'd3'
import type { ForensicEvent } from '../types'
import { Card, CardHeader, CardTitle, CardContent } from '@/components/ui/card'

interface Props {
  events: ForensicEvent[]
}

const SEV_COLOR: Record<number, string> = {
  1: 'var(--color-sev-low)',
  2: 'var(--color-sev-medium)',
  3: 'var(--color-sev-high)',
  4: 'var(--color-sev-critical)',
}

const ForensicTimeline: React.FC<Props> = ({ events }) => {
  const svgRef = useRef<SVGSVGElement | null>(null)
  const wrapperRef = useRef<HTMLDivElement | null>(null)
  // Stable ref for the tooltip div — created once on mount, avoids accumulation on re-render
  const tooltipRef = useRef<HTMLDivElement | null>(null)

  const data = useMemo(() => {
    return events
      .filter((e) => !!e.timestamp)
      .map((e) => ({
        ...e,
        ts: new Date(e.timestamp),
        source: e.event_source || 'unknown-service',
      }))
      .sort((a, b) => a.ts.getTime() - b.ts.getTime())
  }, [events])

  // Create the tooltip div once on mount; clean it up on unmount.
  useEffect(() => {
    if (!wrapperRef.current) return
    const div = document.createElement('div')
    Object.assign(div.style, {
      position: 'absolute',
      pointerEvents: 'none',
      padding: '8px 10px',
      background: 'var(--color-card)',
      border: '1px solid var(--color-border)',
      borderRadius: '6px',
      boxShadow: '0 10px 30px rgba(0,0,0,0.15)',
      fontSize: '11px',
      color: 'var(--color-foreground)',
      opacity: '0',
    })
    wrapperRef.current.appendChild(div)
    tooltipRef.current = div
    return () => {
      div.remove()
      tooltipRef.current = null
    }
  }, [])

  useEffect(() => {
    const svg = d3.select(svgRef.current)
    svg.selectAll('*').remove()
    if (data.length === 0) return

    const container = d3.select(wrapperRef.current)
    const width = container.node()?.clientWidth || 760
    const height = 260
    const margin = { top: 24, right: 20, bottom: 32, left: 120 }
    const innerWidth = width - margin.left - margin.right
    const innerHeight = height - margin.top - margin.bottom

    svg.attr('width', width).attr('height', height)

    const g = svg
      .append('g')
      .attr('transform', `translate(${margin.left},${margin.top})`)

    const minTime = data[0].ts
    const maxTime = data[data.length - 1].ts
    const domainPad = 1000 * 30
    const x = d3
      .scaleTime()
      .domain([new Date(minTime.getTime() - domainPad), new Date(maxTime.getTime() + domainPad)])
      .range([0, innerWidth])

    const services = Array.from(new Set(data.map((d) => d.source)))
    const y = d3
      .scaleBand()
      .domain(services)
      .range([0, innerHeight])
      .padding(0.25)

    const xAxis = d3.axisBottom<Date>(x).ticks(6).tickSizeOuter(0)
    const yAxis = d3.axisLeft<string>(y).tickSize(0)

    g.append('g')
      .attr('transform', `translate(0,${innerHeight})`)
      .attr('class', 'axis axis-x')
      .call(xAxis)
      .selectAll('text')
      .style('fill', 'var(--color-muted-foreground)')
      .style('font-size', '10px')

    g.append('g')
      .attr('class', 'axis axis-y')
      .call(yAxis)
      .selectAll('text')
      .style('fill', 'var(--color-muted-foreground)')
      .style('font-size', '11px')

    g.selectAll('.axis line, .axis path').style('stroke', 'var(--color-border)')

    const tooltip = d3.select(tooltipRef.current)

    g.selectAll('circle')
      .data(data)
      .enter()
      .append('circle')
      .attr('cx', (d) => x(d.ts))
      .attr('cy', (d) => (y(d.source) ?? 0) + y.bandwidth() / 2)
      .attr('r', 7)
      .attr('fill', (d) => SEV_COLOR[d.severity_weight || 1] || 'var(--color-muted-foreground)')
      .attr('stroke', 'var(--color-background)')
      .attr('stroke-width', 1.2)
      .style('cursor', 'pointer')
      .on('mouseenter', function (event, d) {
        const time = d.ts.toLocaleString('en-US', {
          hour12: false,
          hour: '2-digit',
          minute: '2-digit',
          second: '2-digit',
        })
        // Build tooltip content using safe DOM text nodes — no innerHTML / html()
        const node = tooltipRef.current!
        node.textContent = ''
        const b = document.createElement('div')
        b.style.fontWeight = '600'
        b.textContent = d.api_action
        const l2 = document.createElement('div')
        l2.textContent = `${time} \u2022 ${d.source_ip ?? 'unknown IP'}`
        const l3 = document.createElement('div')
        l3.textContent = d.affected_resource ?? 'no resource recorded'
        const l4 = document.createElement('div')
        l4.style.color = 'var(--color-muted-foreground)'
        l4.textContent = d.impact_category ?? 'unclassified'
        node.append(b, l2, l3, l4)
        tooltip.style('opacity', 1)
      })
      .on('mousemove', function (event) {
        const [mx, my] = d3.pointer(event, wrapperRef.current)
        tooltip.style('left', `${mx + 12}px`).style('top', `${my - 10}px`)
      })
      .on('mouseleave', function () {
        tooltip.style('opacity', 0)
      })

    return () => {
      svg.selectAll('*').remove()
    }
  }, [data])

  return (
    <Card>
      <CardHeader className="pb-3">
        <CardTitle className="flex items-center gap-2 text-sm">
          Forensic Timeline
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
          <div ref={wrapperRef} className="relative overflow-hidden" style={{ minHeight: 260 }}>
            <svg ref={svgRef} />
          </div>
        )}
      </CardContent>
    </Card>
  )
}

export default ForensicTimeline
