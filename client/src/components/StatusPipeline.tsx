import type { IncidentStatus } from "../types";

const STEPS: IncidentStatus[] = [
  "detecting",
  "collecting",
  "classifying",
  "scoring",
  "reporting",
  "complete",
];

interface Props {
  status: IncidentStatus;
}

export default function StatusPipeline({ status }: Props) {
  const currentIdx = STEPS.indexOf(status);

  return (
    <div className="flex items-center gap-1 overflow-x-auto">
      {STEPS.map((step, i) => {
        const isActive = i === currentIdx;
        const isDone = i < currentIdx;
        return (
          <div key={step} className="flex items-center gap-1">
            <div
              className={`px-3 py-1.5 rounded text-xs font-medium transition-colors ${
                isActive
                  ? "bg-indigo-500/20 text-indigo-300 border border-indigo-500/40"
                  : isDone
                    ? "bg-emerald-500/10 text-emerald-500"
                    : "bg-zinc-800/50 text-zinc-600"
              }`}
            >
              {step}
            </div>
            {i < STEPS.length - 1 && (
              <span
                className={`text-xs ${isDone ? "text-emerald-600" : "text-zinc-700"}`}
              >
                →
              </span>
            )}
          </div>
        );
      })}
    </div>
  );
}
