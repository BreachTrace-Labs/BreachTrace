import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { getIncidents } from "../api/incidents";
import SeverityBadge from "../components/SeverityBadge";
import StatusBadge from "../components/StatusBadge";
import type { IncidentListItem } from "../types";

export default function Dashboard() {
  const [incidents, setIncidents] = useState<IncidentListItem[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    getIncidents()
      .then(setIncidents)
      .catch(() => setError("Failed to load incidents"))
      .finally(() => setLoading(false));
  }, []);

  if (loading) {
    return (
      <div className="flex items-center justify-center h-64">
        <p className="text-zinc-400 text-sm">Loading incidents...</p>
      </div>
    );
  }

  if (error) {
    return (
      <div className="flex items-center justify-center h-64">
        <p className="text-red-400 text-sm">{error}</p>
      </div>
    );
  }

  if (incidents.length === 0) {
    return (
      <div className="flex flex-col items-center justify-center h-64 gap-3">
        <div className="w-12 h-12 rounded-full bg-zinc-800 flex items-center justify-center">
          <span className="text-xl">🛡️</span>
        </div>
        <p className="text-zinc-400 text-sm text-center max-w-md">
          No incidents detected yet. Connect your GitHub repository to begin
          monitoring.
        </p>
      </div>
    );
  }

  return (
    <div>
      <h1 className="text-xl font-semibold text-zinc-100 mb-6">Incidents</h1>

      <div className="overflow-x-auto rounded-lg border border-zinc-800">
        <table className="w-full text-sm text-left">
          <thead className="text-xs uppercase text-zinc-500 bg-zinc-900/50">
            <tr>
              <th className="px-4 py-3">Credential</th>
              <th className="px-4 py-3">Exposed</th>
              <th className="px-4 py-3">Severity</th>
              <th className="px-4 py-3">Status</th>
              <th className="px-4 py-3 text-right">Events</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-zinc-800">
            {incidents.map((inc) => (
              <tr
                key={inc.incident_id}
                className="hover:bg-zinc-800/40 transition-colors"
              >
                <td className="px-4 py-3">
                  <Link
                    to={`/incident/${inc.incident_id}`}
                    className="text-zinc-200 hover:text-white font-mono text-xs"
                  >
                    {inc.credential_hint}
                  </Link>
                </td>
                <td className="px-4 py-3 text-zinc-400 text-xs">
                  {new Date(inc.exposure_start).toLocaleString()}
                </td>
                <td className="px-4 py-3">
                  <SeverityBadge severity={inc.overall_severity} />
                </td>
                <td className="px-4 py-3">
                  <StatusBadge status={inc.status} />
                </td>
                <td className="px-4 py-3 text-right text-zinc-400 font-mono text-xs">
                  {inc.event_count}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}
