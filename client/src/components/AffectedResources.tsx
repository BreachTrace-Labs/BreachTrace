import type { ForensicEvent } from '../types'

interface Props {
  events: ForensicEvent[]
}

const AffectedResources: React.FC<Props> = ({ events }) => {
  const resources = [...new Set(events.map((e) => e.affected_resource).filter(Boolean))]

  return (
    <div className="p-4 border rounded">
      <h2 className="text-lg font-semibold mb-2">Affected Resources</h2>
      {resources.length === 0 ? (
        <p className="text-sm text-gray-400">None detected</p>
      ) : (
        <ul className="space-y-1 text-sm">
          {resources.map((r) => (
            <li key={r} className="font-mono text-xs bg-gray-100 px-2 py-0.5 rounded">{r}</li>
          ))}
        </ul>
      )}
    </div>
  )
}

export default AffectedResources
