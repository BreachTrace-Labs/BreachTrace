import type { IncidentRecord } from '../types'
import { Badge } from '@/components/ui/badge'
import type { BadgeProps } from '@/components/ui/badge'

interface Props {
  severity: IncidentRecord['overall_severity']
  className?: string
}

const VARIANT_MAP: Record<string, BadgeProps['variant']> = {
  LOW: 'low',
  MEDIUM: 'medium',
  HIGH: 'high',
  CRITICAL: 'critical',
}

const SeverityBadge: React.FC<Props> = ({ severity, className }) => {
  if (!severity) return null
  return (
    <Badge variant={VARIANT_MAP[severity] ?? 'outline'} className={className}>
      {severity}
    </Badge>
  )
}

export default SeverityBadge
