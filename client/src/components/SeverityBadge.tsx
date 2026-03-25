import type { SeverityLevel } from "../types";

const SEVERITY_STYLES: Record<string, string> = {
  Critical: "bg-red-500/15 text-red-400 border-red-500/30",
  High: "bg-orange-500/15 text-orange-400 border-orange-500/30",
  Medium: "bg-yellow-500/15 text-yellow-400 border-yellow-500/30",
  Low: "bg-green-500/15 text-green-400 border-green-500/30",
};

interface Props {
  severity: SeverityLevel | null;
}

export default function SeverityBadge({ severity }: Props) {
  if (!severity) {
    return (
      <span className="inline-block px-2 py-0.5 rounded text-xs border bg-zinc-800/50 text-zinc-500 border-zinc-700">
        —
      </span>
    );
  }

  return (
    <span
      className={`inline-block px-2 py-0.5 rounded text-xs font-medium border ${SEVERITY_STYLES[severity] ?? SEVERITY_STYLES.Low}`}
    >
      {severity}
    </span>
  );
}
