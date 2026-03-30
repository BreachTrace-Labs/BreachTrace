import type { ForensicEvent } from '../types'
import { Card, CardHeader, CardTitle, CardContent } from '@/components/ui/card'
import { cn } from '@/lib/utils'

interface Props {
  events: ForensicEvent[]
}

const SEV_DOT: Record<number, string> = {
  1: 'bg-[var(--color-sev-low)]',
  2: 'bg-[var(--color-sev-medium)]',
  3: 'bg-[var(--color-sev-high)]',
  4: 'bg-[var(--color-sev-critical)]',
}

const CATEGORY_LABEL: Record<string, string> = {
  reconnaissance: 'Recon',
  data_access: 'Data Access',
  exfiltration: 'Exfiltration',
  resource_abuse: 'Resource Abuse',
  privilege_escalation: 'Priv Escalation',
  financial_abuse: 'Financial Abuse',
  communication_abuse: 'Comm Abuse',
  code_compromise: 'Code Compromise',
}

function formatTs(ts: string) {
  const d = new Date(ts)
  return d.toLocaleTimeString('en-US', {
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
    hour12: false,
  })
}

const ForensicTimeline: React.FC<Props> = ({ events }) => {
  const sorted = [...events].sort(
    (a, b) => new Date(a.timestamp).getTime() - new Date(b.timestamp).getTime()
  )

  return (
    <Card>
      <CardHeader className="pb-3">
        <CardTitle className="flex items-center gap-2 text-sm">
          Forensic Timeline
          <span
            className="ml-auto text-xs font-mono px-1.5 py-0.5 rounded"
            style={{ backgroundColor: 'var(--color-muted)', color: 'var(--color-muted-foreground)' }}
          >
            {events.length} events
          </span>
        </CardTitle>
      </CardHeader>
      <CardContent className="p-0">
        {sorted.length === 0 ? (
          <p
            className="text-sm px-5 pb-5"
            style={{ color: 'var(--color-muted-foreground)' }}
          >
            No events collected yet
          </p>
        ) : (
          <div className="divide-y" style={{ borderColor: 'var(--color-border)' }}>
            {sorted.map((e, i) => (
              <div
                key={e.event_id}
                className="flex items-start gap-4 px-5 py-3 text-sm group"
              >
                {/* Timeline connector */}
                <div className="flex flex-col items-center gap-1 pt-1 shrink-0">
                  <div
                    className={cn(
                      'w-2 h-2 rounded-full shrink-0',
                      e.severity_weight ? SEV_DOT[e.severity_weight] : 'bg-[var(--color-muted-foreground)]'
                    )}
                  />
                  {i < sorted.length - 1 && (
                    <div
                      className="w-px flex-1 min-h-[12px]"
                      style={{ backgroundColor: 'var(--color-border)' }}
                    />
                  )}
                </div>

                {/* Content */}
                <div className="flex-1 min-w-0">
                  <div className="flex items-baseline gap-3 flex-wrap">
                    <span
                      className="font-mono text-[11px] shrink-0"
                      style={{ color: 'var(--color-muted-foreground)' }}
                    >
                      {formatTs(e.timestamp)}
                    </span>
                    <span className="font-mono text-xs font-semibold truncate">
                      {e.api_action}
                    </span>
                    {e.impact_category && (
                      <span
                        className="text-[10px] uppercase tracking-wider font-semibold shrink-0"
                        style={{ color: 'var(--color-muted-foreground)' }}
                      >
                        {CATEGORY_LABEL[e.impact_category] ?? e.impact_category}
                      </span>
                    )}
                  </div>
                  <div
                    className="mt-0.5 flex items-center gap-3 text-[11px] font-mono"
                    style={{ color: 'var(--color-muted-foreground)' }}
                  >
                    {e.source_ip && <span>{e.source_ip}</span>}
                    {e.affected_resource && (
                      <span className="truncate">{e.affected_resource}</span>
                    )}
                    {!e.success && (
                      <span style={{ color: 'var(--color-sev-critical)' }}>
                        {e.error_code ?? 'failed'}
                      </span>
                    )}
                  </div>
                </div>
              </div>
            ))}
          </div>
        )}
      </CardContent>
    </Card>
  )
}

export default ForensicTimeline
