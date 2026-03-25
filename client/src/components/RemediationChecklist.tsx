import { useState } from "react";

interface Props {
  steps: string[];
}

export default function RemediationChecklist({ steps }: Props) {
  const [checked, setChecked] = useState<Record<number, boolean>>({});

  return (
    <div className="bg-zinc-900 border border-zinc-800 rounded-lg p-5 space-y-2">
      {steps.map((step, i) => (
        <label
          key={i}
          className="flex items-start gap-3 cursor-pointer group"
        >
          <input
            type="checkbox"
            checked={!!checked[i]}
            onChange={() =>
              setChecked((prev) => ({ ...prev, [i]: !prev[i] }))
            }
            className="mt-0.5 accent-emerald-500"
          />
          <span
            className={`text-sm transition-colors ${
              checked[i]
                ? "text-zinc-600 line-through"
                : "text-zinc-300 group-hover:text-zinc-100"
            }`}
          >
            {step}
          </span>
        </label>
      ))}
    </div>
  );
}
