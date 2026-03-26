import type { IncidentRecord } from '../types'

interface Props {
  severity: IncidentRecord['overall_severity']
}

const COLOUR: Record<string, string> = {
  LOW: 'bg-green-100 text-green-800',
  MEDIUM: 'bg-yellow-100 text-yellow-800',
  HIGH: 'bg-orange-100 text-orange-800',
  CRITICAL: 'bg-red-100 text-red-800',
}

const SeverityBadge: React.FC<Props> = ({ severity }) => {
  if (!severity) return null
  return (
    <span className={`inline-block px-2 py-0.5 rounded text-sm font-medium ${COLOUR[severity] ?? ''}`}>
      {severity}
    </span>
  )
}

export default SeverityBadge
