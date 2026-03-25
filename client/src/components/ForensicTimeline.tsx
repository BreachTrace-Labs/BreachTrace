import { useEffect, useRef } from "react";
import * as d3 from "d3";
import type { ForensicEvent } from "../types";

const SEVERITY_COLORS: Record<number, string> = {
  1: "#22c55e", // green — Low
  2: "#eab308", // yellow — Medium
  3: "#f97316", // orange — High
  4: "#ef4444", // red — Critical
};

interface Props {
  events: ForensicEvent[];
  exposureStart: string;
  exposureEnd: string | null;
}

export default function ForensicTimeline({
  events,
  exposureStart,
  exposureEnd,
}: Props) {
  const svgRef = useRef<SVGSVGElement>(null);

  useEffect(() => {
    if (!svgRef.current || events.length === 0) return;

    const margin = { top: 20, right: 30, bottom: 40, left: 140 };
    const width = svgRef.current.clientWidth;
    const uniqueSources = [...new Set(events.map((e) => e.event_source))];
    const height = Math.max(200, uniqueSources.length * 50 + margin.top + margin.bottom);
    const innerW = width - margin.left - margin.right;
    const innerH = height - margin.top - margin.bottom;

    const svg = d3.select(svgRef.current);
    svg.selectAll("*").remove();
    svg.attr("height", height);

    const g = svg
      .append("g")
      .attr("transform", `translate(${margin.left},${margin.top})`);

    // Scales
    const start = new Date(exposureStart);
    const end = exposureEnd ? new Date(exposureEnd) : new Date();

    const x = d3.scaleTime().domain([start, end]).range([0, innerW]);

    const y = d3
      .scaleBand()
      .domain(uniqueSources)
      .range([0, innerH])
      .padding(0.3);

    // Axes
    g.append("g")
      .attr("transform", `translate(0,${innerH})`)
      .call(d3.axisBottom(x).ticks(6))
      .selectAll("text")
      .attr("fill", "#71717a")
      .attr("font-size", "10px");

    g.append("g")
      .call(d3.axisLeft(y))
      .selectAll("text")
      .attr("fill", "#71717a")
      .attr("font-size", "10px");

    g.selectAll(".domain, .tick line").attr("stroke", "#3f3f46");

    // Tooltip
    const tooltip = d3
      .select("body")
      .append("div")
      .attr("class", "bt-tooltip")
      .style("position", "absolute")
      .style("background", "#18181b")
      .style("border", "1px solid #3f3f46")
      .style("border-radius", "6px")
      .style("padding", "8px 12px")
      .style("font-size", "11px")
      .style("color", "#d4d4d8")
      .style("pointer-events", "none")
      .style("opacity", 0)
      .style("z-index", "9999");

    // Events
    g.selectAll("circle")
      .data(events)
      .join("circle")
      .attr("cx", (d) => x(new Date(d.timestamp)))
      .attr("cy", (d) => (y(d.event_source) ?? 0) + y.bandwidth() / 2)
      .attr("r", 7)
      .attr("fill", (d) => SEVERITY_COLORS[d.severity_weight ?? 1] ?? SEVERITY_COLORS[1])
      .attr("opacity", 0.85)
      .style("cursor", "pointer")
      .on("mouseover", (_event, d) => {
        tooltip
          .html(
            `<strong>${d.api_action}</strong><br/>` +
              `${new Date(d.timestamp).toLocaleTimeString()}<br/>` +
              `IP: ${d.source_ip ?? "—"}<br/>` +
              `Resource: ${d.affected_resource ?? "—"}<br/>` +
              `Category: ${d.impact_category ?? "—"}`
          )
          .style("opacity", 1);
      })
      .on("mousemove", (event) => {
        tooltip
          .style("left", event.pageX + 12 + "px")
          .style("top", event.pageY - 20 + "px");
      })
      .on("mouseout", () => {
        tooltip.style("opacity", 0);
      });

    return () => {
      tooltip.remove();
    };
  }, [events, exposureStart, exposureEnd]);

  return (
    <div className="bg-zinc-900 border border-zinc-800 rounded-lg p-4 overflow-x-auto">
      <svg ref={svgRef} className="w-full" style={{ minHeight: 200 }} />
    </div>
  );
}
