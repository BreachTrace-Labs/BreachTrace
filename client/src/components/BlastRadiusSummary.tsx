import type { IncidentRecord, ForensicEvent } from '../types'
import { Card, CardHeader, CardTitle, CardContent } from '@/components/ui/card'
import SeverityBadge from './SeverityBadge'

interface Props {
  incident: IncidentRecord
}

const CATEGORY_COLORS: Record<string, string> = {
  reconnaissance: 'var(--color-sev-low)',
  data_access: 'var(--color-sev-medium)',
  exfiltration: 'var(--color-sev-critical)',
  resource_abuse: 'var(--color-sev-high)',
  privilege_escalation: 'var(--color-sev-critical)',
  financial_abuse: 'var(--color-sev-high)',
  communication_abuse: 'var(--color-sev-medium)',
  code_compromise: 'var(--color-sev-critical)',
}

const CATEGORY_LABELS: Record<string, string> = {
  reconnaissance: 'Reconnaissance',
  data_access: 'Data Access',
  exfiltration: 'Exfiltration',
  resource_abuse: 'Resource Abuse',
  privilege_escalation: 'Privilege Escalation',
  financial_abuse: 'Financial Abuse',
  communication_abuse: 'Communication Abuse',
  code_compromise: 'Code Compromise',
}

function groupByCategory(events: ForensicEvent[]) {
  return events.reduce<Record<string, number>>((acc, e) => {
    const cat = e.impact_category ?? 'unclassified'
    acc[cat] = (acc[cat] ?? 0) + 1
    return acc
  }, {})
}

const BlastRadiusSummary: React.FC<Props> = ({ incident }) => {
  const { events, overall_severity } = incident
  const cats = groupByCategory(events)
  const total = events.length
  const entries = Object.entries(cats).sort((a, b) => b[1] - a[1])

  const worstCat = entries[0]?.[0] ?? null

  return (
    <Card>
      <CardHeader className="pb-3">
        <CardTitle className="flex items-center justify-between text-sm">
          Blast Radius
          <SeverityBadge severity={overall_severity} />
        </CardTitle>
      </CardHeader>
      <CardContent>
        {total === 0 ? (
          <p className="text-sm" style={{ color: 'var(--color-muted-foreground)' }}>
            Awaiting forensic data
          </p>
        ) : (
          <div className="space-y-3">
            {/* Platform pill */}
            <div
              className="flex items-center justify-between text-xs pb-3 border-b"
              style={{ borderColor: 'var(--color-border)' }}
            >
              <span
                className="font-semibold uppercase tracking-wider"
                style={{ color: 'var(--color-muted-foreground)' }}
              >
                AWS CloudTrail
              </span>
              <span className="font-mono font-semibold">{total} events</span>
            </div>

            {/* Category breakdown */}
            {entries.map(([cat, count]) => {
              const pct = Math.round((count / total) * 100)
              const color = CATEGORY_COLORS[cat] ?? 'var(--color-muted-foreground)'
              return (
                <div key={cat}>
                  <div className="flex items-center justify-between mb-1">
                    <span className="text-xs font-medium">
                      {CATEGORY_LABELS[cat] ?? cat}
                    </span>
                    <span
                      className="text-xs font-mono"
                      style={{ color: 'var(--color-muted-foreground)' }}
                    >
                      {count}
                    </span>
                  </div>
                  <div
                    className="h-1 rounded-full overflow-hidden"
                    style={{ backgroundColor: 'var(--color-muted)' }}
                  >
                    <div
                      className="h-full rounded-full"
                      style={{ width: `${pct}%`, backgroundColor: color }}
                    />
                  </div>
                </div>
              )
            })}

            {/* Worst category */}
            {worstCat && (
              <p
                className="text-xs pt-1"
                style={{ color: 'var(--color-muted-foreground)' }}
              >
                Highest risk:{' '}
                <span style={{ color: 'var(--color-foreground)', fontWeight: 600 }}>
                  {CATEGORY_LABELS[worstCat] ?? worstCat}
                </span>
              </p>
            )}
          </div>
        )}
      </CardContent>
    </Card>
  )
}

export default BlastRadiusSummary
