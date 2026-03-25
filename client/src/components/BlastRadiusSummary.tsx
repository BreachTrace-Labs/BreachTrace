import type { ForensicEvent, ImpactCategory } from "../types";

const CATEGORY_LABELS: Record<ImpactCategory, string> = {
  reconnaissance: "Reconnaissance",
  data_access: "Data Access",
  exfiltration: "Data Exfiltration",
  resource_abuse: "Resource Abuse",
  privilege_escalation: "Privilege Escalation",
  financial_abuse: "Financial Abuse",
  communication_abuse: "Communication Abuse",
  code_compromise: "Code Compromise",
};

const CATEGORY_COLORS: Record<ImpactCategory, string> = {
  reconnaissance: "bg-green-500/15 text-green-400",
  data_access: "bg-yellow-500/15 text-yellow-400",
  exfiltration: "bg-red-500/15 text-red-400",
  resource_abuse: "bg-orange-500/15 text-orange-400",
  privilege_escalation: "bg-red-500/15 text-red-300",
  financial_abuse: "bg-orange-500/15 text-orange-300",
  communication_abuse: "bg-blue-500/15 text-blue-400",
  code_compromise: "bg-purple-500/15 text-purple-400",
};

interface Props {
  events: ForensicEvent[];
}

export default function BlastRadiusSummary({ events }: Props) {
  const categoryCounts = events.reduce(
    (acc, e) => {
      if (e.impact_category) {
        acc[e.impact_category] = (acc[e.impact_category] || 0) + 1;
      }
      return acc;
    },
    {} as Record<string, number>
  );

  const worstWeight = Math.max(...events.map((e) => e.severity_weight ?? 0));
  const worstCategory = events.find(
    (e) => e.severity_weight === worstWeight
  )?.impact_category;

  return (
    <div className="bg-zinc-900 border border-zinc-800 rounded-lg p-5">
      <div className="flex items-center justify-between mb-4">
        <div className="flex items-center gap-2">
          <span className="text-sm font-medium text-zinc-300">AWS</span>
          <span className="text-zinc-600 text-xs">
            {events.length} event{events.length !== 1 ? "s" : ""}
          </span>
        </div>
        {worstCategory && (
          <span className="text-xs text-zinc-500">
            Worst:{" "}
            {CATEGORY_LABELS[worstCategory as ImpactCategory] ?? worstCategory}
          </span>
        )}
      </div>

      <div className="flex flex-wrap gap-2">
        {Object.entries(categoryCounts).map(([cat, count]) => (
          <span
            key={cat}
            className={`inline-flex items-center gap-1.5 px-2.5 py-1 rounded text-xs font-medium ${
              CATEGORY_COLORS[cat as ImpactCategory] ?? "bg-zinc-800 text-zinc-400"
            }`}
          >
            {CATEGORY_LABELS[cat as ImpactCategory] ?? cat}
            <span className="opacity-60">×{count}</span>
          </span>
        ))}
      </div>
    </div>
  );
}
