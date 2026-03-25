import type { ForensicEvent } from '../types'

interface Props {
  events: ForensicEvent[]
}

const ForensicTimeline: React.FC<Props> = ({ events }) => {
  return (
    <div className="p-4 border rounded">
      <h2 className="text-lg font-semibold mb-2">Forensic Timeline</h2>
      <p className="text-sm text-gray-400">D3 timeline — TODO Day 5 ({events.length} events)</p>
    </div>
  )
}

export default ForensicTimeline
