import { useEffect, useState } from "react";
import { getExperimentRuns } from "../api/research";
import type { ExperimentRun } from "../types";

export default function Research() {
  const [runs, setRuns] = useState<ExperimentRun[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    getExperimentRuns()
      .then(setRuns)
      .catch(() => setError("Failed to load research data"))
      .finally(() => setLoading(false));
  }, []);

  if (loading) {
    return (
      <div className="flex items-center justify-center h-64">
        <p className="text-zinc-400 text-sm">Loading research data...</p>
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

  const avgDetection =
    runs.length > 0
      ? (
          runs.reduce((s, r) => s + r.detection_time_s, 0) / runs.length
        ).toFixed(1)
      : "—";
  const avgReport =
    runs.length > 0
      ? (
          runs.reduce((s, r) => s + r.report_time_s, 0) / runs.length
        ).toFixed(1)
      : "—";

  const severityCounts = runs.reduce(
    (acc, r) => {
      acc[r.overall_severity] = (acc[r.overall_severity] || 0) + 1;
      return acc;
    },
    {} as Record<string, number>
  );

  return (
    <div className="space-y-8">
      <h1 className="text-xl font-semibold text-zinc-100">
        Research & Evaluation
      </h1>

      {/* Track A — Detection Accuracy (placeholder until SecretBench run) */}
      <section>
        <h2 className="text-sm font-medium text-zinc-400 uppercase tracking-wider mb-3">
          Track A — Detection Accuracy (200 SecretBench Samples)
        </h2>
        <div className="grid grid-cols-3 gap-4">
          <MetricCard label="Precision" value="—%" />
          <MetricCard label="Recall" value="—%" />
          <MetricCard label="F1 Score" value="—%" />
        </div>
      </section>

      {/* Track B — Pipeline Metrics */}
      <section>
        <h2 className="text-sm font-medium text-zinc-400 uppercase tracking-wider mb-3">
          Track B — {runs.length} Full Pipeline Runs
        </h2>
        <div className="grid grid-cols-2 sm:grid-cols-4 gap-4">
          <MetricCard label="Total Runs" value={String(runs.length)} />
          <MetricCard label="Avg Detection" value={`${avgDetection}s`} />
          <MetricCard label="Avg Report" value={`${avgReport}s`} />
          <MetricCard label="Target" value="<60s" />
        </div>
      </section>

      {/* Severity Distribution */}
      <section>
        <h2 className="text-sm font-medium text-zinc-400 uppercase tracking-wider mb-3">
          Severity Distribution
        </h2>
        <div className="grid grid-cols-4 gap-4">
          {(["Low", "Medium", "High", "Critical"] as const).map((s) => (
            <MetricCard
              key={s}
              label={s}
              value={String(severityCounts[s] ?? 0)}
            />
          ))}
        </div>
      </section>

      {/* Experiment table */}
      {runs.length > 0 && (
        <section>
          <h2 className="text-sm font-medium text-zinc-400 uppercase tracking-wider mb-3">
            Experiment Runs
          </h2>
          <div className="overflow-x-auto rounded-lg border border-zinc-800">
            <table className="w-full text-sm text-left">
              <thead className="text-xs uppercase text-zinc-500 bg-zinc-900/50">
                <tr>
                  <th className="px-4 py-3">#</th>
                  <th className="px-4 py-3">Group</th>
                  <th className="px-4 py-3">Detection (s)</th>
                  <th className="px-4 py-3">Report (s)</th>
                  <th className="px-4 py-3">Severity</th>
                  <th className="px-4 py-3">External Use</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-zinc-800">
                {runs.map((r) => (
                  <tr
                    key={r.id}
                    className="hover:bg-zinc-800/40 transition-colors"
                  >
                    <td className="px-4 py-3 text-zinc-300 font-mono text-xs">
                      {r.run_number}
                    </td>
                    <td className="px-4 py-3 text-zinc-400 text-xs">
                      {r.experiment_group}
                    </td>
                    <td className="px-4 py-3 text-zinc-400 font-mono text-xs">
                      {r.detection_time_s}
                    </td>
                    <td className="px-4 py-3 text-zinc-400 font-mono text-xs">
                      {r.report_time_s}
                    </td>
                    <td className="px-4 py-3 text-zinc-400 text-xs">
                      {r.overall_severity}
                    </td>
                    <td className="px-4 py-3 text-zinc-400 text-xs">
                      {r.external_use_detected ? "Yes" : "No"}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </section>
      )}
    </div>
  );
}

function MetricCard({ label, value }: { label: string; value: string }) {
  return (
    <div className="bg-zinc-900 border border-zinc-800 rounded-lg p-4 text-center">
      <p className="text-zinc-500 text-xs mb-1">{label}</p>
      <p className="text-zinc-100 text-lg font-semibold font-mono">{value}</p>
    </div>
  );
}
