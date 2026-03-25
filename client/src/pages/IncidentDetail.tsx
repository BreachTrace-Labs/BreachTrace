import { useEffect, useState } from "react";
import { useParams, Link } from "react-router-dom";
import { getIncident, getIncidentTimeline } from "../api/incidents";
import ForensicTimeline from "../components/ForensicTimeline";
import BlastRadiusSummary from "../components/BlastRadiusSummary";
import AffectedResources from "../components/AffectedResources";
import RemediationChecklist from "../components/RemediationChecklist";
import SeverityBadge from "../components/SeverityBadge";
import StatusPipeline from "../components/StatusPipeline";
import type { IncidentRecord, ForensicEvent } from "../types";

export default function IncidentDetail() {
  const { id } = useParams<{ id: string }>();
  const [incident, setIncident] = useState<IncidentRecord | null>(null);
  const [events, setEvents] = useState<ForensicEvent[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (!id) return;
    Promise.all([getIncident(id), getIncidentTimeline(id)])
      .then(([inc, evts]) => {
        setIncident(inc);
        setEvents(evts);
      })
      .catch(() => setError("Failed to load incident"))
      .finally(() => setLoading(false));
  }, [id]);

  if (loading) {
    return (
      <div className="flex items-center justify-center h-64">
        <p className="text-zinc-400 text-sm">Loading incident...</p>
      </div>
    );
  }

  if (error || !incident) {
    return (
      <div className="flex items-center justify-center h-64">
        <p className="text-red-400 text-sm">{error ?? "Incident not found"}</p>
      </div>
    );
  }

  const duration = incident.exposure_end
    ? formatDuration(
        new Date(incident.exposure_start),
        new Date(incident.exposure_end)
      )
    : "Ongoing";

  return (
    <div className="space-y-8">
      {/* Back link */}
      <Link
        to="/"
        className="text-zinc-500 hover:text-zinc-300 text-sm transition-colors"
      >
        ← Back to Dashboard
      </Link>

      {/* Header */}
      <div className="flex flex-wrap items-start justify-between gap-4">
        <div>
          <h1 className="text-xl font-semibold text-zinc-100 font-mono">
            {incident.credential_hint}
          </h1>
          <p className="text-zinc-500 text-sm mt-1">
            {incident.credential_type} &middot; {incident.repo_url}
          </p>
        </div>
        <SeverityBadge severity={incident.overall_severity} />
      </div>

      {/* Status pipeline */}
      <StatusPipeline status={incident.status} />

      {/* Metadata row */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-4 text-sm">
        <MetaCard
          label="Exposure Start"
          value={new Date(incident.exposure_start).toLocaleString()}
        />
        <MetaCard
          label="Exposure End"
          value={
            incident.exposure_end
              ? new Date(incident.exposure_end).toLocaleString()
              : "—"
          }
        />
        <MetaCard label="Duration" value={duration} />
        <MetaCard label="Events" value={String(events.length)} />
      </div>

      {/* GDPR banner */}
      {incident.gdpr_flag && (
        <div className="border border-amber-600/40 bg-amber-950/30 rounded-lg px-4 py-3 text-amber-300 text-sm">
          ⚠️ Potential personal data access detected — GDPR notification may be
          required.
        </div>
      )}

      {/* Gemini report */}
      {incident.report_text && (
        <section>
          <h2 className="text-sm font-medium text-zinc-400 uppercase tracking-wider mb-3">
            Forensic Report
          </h2>
          <div className="bg-zinc-900 border border-zinc-800 rounded-lg p-5 text-zinc-300 text-sm whitespace-pre-wrap leading-relaxed">
            {incident.report_text}
          </div>
        </section>
      )}

      {/* D3 Timeline */}
      {events.length > 0 && (
        <section>
          <h2 className="text-sm font-medium text-zinc-400 uppercase tracking-wider mb-3">
            Forensic Timeline
          </h2>
          <ForensicTimeline
            events={events}
            exposureStart={incident.exposure_start}
            exposureEnd={incident.exposure_end}
          />
        </section>
      )}

      {/* Blast radius */}
      {events.length > 0 && (
        <section>
          <h2 className="text-sm font-medium text-zinc-400 uppercase tracking-wider mb-3">
            Blast Radius
          </h2>
          <BlastRadiusSummary events={events} />
        </section>
      )}

      {/* Affected resources */}
      {events.length > 0 && (
        <section>
          <h2 className="text-sm font-medium text-zinc-400 uppercase tracking-wider mb-3">
            Affected Resources
          </h2>
          <AffectedResources events={events} />
        </section>
      )}

      {/* Remediation checklist */}
      {incident.remediation_steps.length > 0 && (
        <section>
          <h2 className="text-sm font-medium text-zinc-400 uppercase tracking-wider mb-3">
            Remediation Checklist
          </h2>
          <RemediationChecklist steps={incident.remediation_steps} />
        </section>
      )}

      {/* Financial impact */}
      {incident.financial_impact && (
        <section>
          <h2 className="text-sm font-medium text-zinc-400 uppercase tracking-wider mb-3">
            Estimated Financial Impact
          </h2>
          <div className="bg-zinc-900 border border-zinc-800 rounded-lg p-4 text-zinc-300 text-sm font-mono">
            {incident.financial_impact}
          </div>
        </section>
      )}
    </div>
  );
}

function MetaCard({ label, value }: { label: string; value: string }) {
  return (
    <div className="bg-zinc-900 border border-zinc-800 rounded-lg p-3">
      <p className="text-zinc-500 text-xs mb-1">{label}</p>
      <p className="text-zinc-200 font-mono text-xs">{value}</p>
    </div>
  );
}

function formatDuration(start: Date, end: Date): string {
  const diffMs = end.getTime() - start.getTime();
  const seconds = Math.floor(diffMs / 1000);
  const minutes = Math.floor(seconds / 60);
  const hours = Math.floor(minutes / 60);

  if (hours > 0) return `${hours}h ${minutes % 60}m ${seconds % 60}s`;
  if (minutes > 0) return `${minutes}m ${seconds % 60}s`;
  return `${seconds}s`;
}
