import type { IncidentRecord } from '../types'

interface Props {
  incident: IncidentRecord
}

const BlastRadiusSummary: React.FC<Props> = ({ incident }) => {
  return (
    <div className="p-4 border rounded">
      <h2 className="text-lg font-semibold mb-2">Blast Radius</h2>
      <p className="text-sm text-gray-400">AWS card — TODO Day 5 ({incident.events.length} events)</p>
    </div>
  )
}

export default BlastRadiusSummary
