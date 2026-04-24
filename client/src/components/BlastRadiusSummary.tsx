import type { IncidentRecord, ForensicEvent } from '../types'
import { Card, CardHeader, CardTitle, CardContent } from '@/components/ui/card'
import SeverityBadge from './SeverityBadge'

interface Props {
  incident: IncidentRecord
}

const CATEGORY_COLORS: Record<string, string> = {
  reconnaissance:       'var(--color-sev-low)',
  data_access:          'var(--color-sev-medium)',
  exfiltration:         'var(--color-sev-critical)',
  resource_abuse:       'var(--color-sev-high)',
  privilege_escalation: 'var(--color-sev-critical)',
  financial_abuse:      'var(--color-sev-high)',
  communication_abuse:  'var(--color-sev-medium)',
  code_compromise:      'var(--color-sev-critical)',
}

const CATEGORY_LABELS: Record<string, string> = {
  reconnaissance:       'Reconnaissance',
  data_access:          'Data Access',
  exfiltration:         'Exfiltration',
  resource_abuse:       'Resource Abuse',
  privilege_escalation: 'Privilege Escalation',
  financial_abuse:      'Financial Abuse',
  communication_abuse:  'Communication Abuse',
  code_compromise:      'Code Compromise',
}

const CATEGORY_DESC: Record<string, string> = {
  reconnaissance:       'Listing buckets, users, or instances without accessing data',
  data_access:          'Reading files, databases, or customer records',
  exfiltration:         'Bulk data download, public bucket exposure, DB dumps',
  resource_abuse:       'Spawning instances or clusters for unauthorized workloads',
  privilege_escalation: 'Creating IAM users, keys, or attaching admin policies',
  financial_abuse:      'Creating charges, accessing billing, or fraudulent spend',
  communication_abuse:  'Sending unauthorised email or SMS via your credentials',
  code_compromise:      'Publishing malicious packages or force-pushing to repos',
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
          <div className="space-y-4">
            {/* Platform + total */}
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

            {/* Category rows */}
            {entries.map(([cat, count]) => {
              const pct = Math.round((count / total) * 100)
              const color = CATEGORY_COLORS[cat] ?? 'var(--color-muted-foreground)'
              const label = CATEGORY_LABELS[cat] ?? cat
              const desc = CATEGORY_DESC[cat]
              const isWorst = cat === worstCat

              return (
                <div key={cat} className="space-y-1">
                  <div className="flex items-center justify-between">
                    <div className="flex items-center gap-1.5">
                      {isWorst && (
                        <span
                          className="w-1.5 h-1.5 rounded-full shrink-0"
                          style={{ backgroundColor: color }}
                        />
                      )}
                      <span
                        className="text-xs font-medium"
                        style={{ color: isWorst ? color : 'var(--color-foreground)' }}
                      >
                        {label}
                      </span>
                    </div>
                    <span
                      className="text-xs font-mono"
                      style={{ color: 'var(--color-muted-foreground)' }}
                    >
                      {count}
                    </span>
                  </div>

                  {/* Progress bar */}
                  <div
                    className="h-1 rounded-full overflow-hidden"
                    style={{ backgroundColor: 'var(--color-muted)' }}
                  >
                    <div
                      className="h-full rounded-full"
                      style={{ width: `${pct}%`, backgroundColor: color }}
                    />
                  </div>

                  {/* Inline description — subtle, always visible */}
                  {desc && (
                    <p
                      className="text-[10px] leading-snug"
                      style={{ color: 'var(--color-muted-foreground)', opacity: 0.75 }}
                    >
                      {desc}
                    </p>
                  )}
                </div>
              )
            })}

            {/* Worst category call-out */}
            {worstCat && CATEGORY_LABELS[worstCat] && (
              <div
                className="flex items-center gap-2 pt-1 mt-1 border-t text-xs"
                style={{ borderColor: 'var(--color-border)' }}
              >
                <span style={{ color: 'var(--color-muted-foreground)' }}>Highest risk</span>
                <span
                  className="font-semibold"
                  style={{ color: CATEGORY_COLORS[worstCat] ?? 'var(--color-foreground)' }}
                >
                  {CATEGORY_LABELS[worstCat]}
                </span>
              </div>
            )}
          </div>
        )}
      </CardContent>
    </Card>
  )
}

export default BlastRadiusSummary
