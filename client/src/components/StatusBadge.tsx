import type { IncidentStatus } from "../types";

const STATUS_STYLES: Record<IncidentStatus, string> = {
  detecting: "bg-blue-500/15 text-blue-400",
  collecting: "bg-indigo-500/15 text-indigo-400",
  classifying: "bg-violet-500/15 text-violet-400",
  scoring: "bg-purple-500/15 text-purple-400",
  reporting: "bg-fuchsia-500/15 text-fuchsia-400",
  complete: "bg-emerald-500/15 text-emerald-400",
};

interface Props {
  status: IncidentStatus;
}

export default function StatusBadge({ status }: Props) {
  return (
    <span
      className={`inline-block px-2 py-0.5 rounded text-xs font-medium ${STATUS_STYLES[status]}`}
    >
      {status}
    </span>
  );
}
