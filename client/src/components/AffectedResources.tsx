import type { ForensicEvent } from "../types";

interface Props {
  events: ForensicEvent[];
}

export default function AffectedResources({ events }: Props) {
  const grouped = events.reduce(
    (acc, e) => {
      if (!e.affected_resource) return acc;
      const type = e.resource_type ?? "Unknown";
      if (!acc[type]) acc[type] = new Set<string>();
      acc[type].add(e.affected_resource);
      return acc;
    },
    {} as Record<string, Set<string>>
  );

  const entries = Object.entries(grouped);
  if (entries.length === 0) {
    return (
      <p className="text-zinc-600 text-sm">No specific resources identified.</p>
    );
  }

  return (
    <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-3">
      {entries.map(([type, resources]) => (
        <div
          key={type}
          className="bg-zinc-900 border border-zinc-800 rounded-lg p-4"
        >
          <p className="text-zinc-500 text-xs mb-2">{type}</p>
          <ul className="space-y-1">
            {[...resources].map((r) => (
              <li key={r} className="text-zinc-300 text-xs font-mono truncate">
                {r}
              </li>
            ))}
          </ul>
        </div>
      ))}
    </div>
  );
}
