import type { ForensicEvent } from '../types'
import { Card, CardHeader, CardTitle, CardContent } from '@/components/ui/card'
import { Globe } from 'lucide-react'

interface Props {
  events: ForensicEvent[]
}

type IPEntry = {
  ip: string
  count: number
  actions: string[]
}

function buildIPTable(events: ForensicEvent[]): IPEntry[] {
  const map = new Map<string, IPEntry>()
  for (const e of events) {
    const ip = e.source_ip ?? 'unknown'
    if (!map.has(ip)) map.set(ip, { ip, count: 0, actions: [] })
    const entry = map.get(ip)!
    entry.count++
    if (e.api_action && !entry.actions.includes(e.api_action)) {
      entry.actions.push(e.api_action)
    }
  }
  return Array.from(map.values()).sort((a, b) => b.count - a.count)
}

function ipLabel(ip: string) {
  if (ip === 'unknown') return 'unknown'
  // AWS internal calls show up as service DNS names
  if (ip.includes('.amazonaws.com') || ip === 'AWS Internal') return ip
  return ip
}

const SourceIPs: React.FC<Props> = ({ events }) => {
  const ips = buildIPTable(events)

  return (
    <Card>
      <CardHeader className="pb-3">
        <CardTitle className="flex items-center gap-2 text-sm">
          <Globe size={13} strokeWidth={2} />
          Source IPs
          {ips.length > 0 && (
            <span
              className="ml-auto text-xs font-mono px-1.5 py-0.5 rounded"
              style={{ backgroundColor: 'var(--color-muted)', color: 'var(--color-muted-foreground)' }}
            >
              {ips.length}
            </span>
          )}
        </CardTitle>
      </CardHeader>
      <CardContent>
        {ips.length === 0 ? (
          <p className="text-sm" style={{ color: 'var(--color-muted-foreground)' }}>
            No IP data collected yet
          </p>
        ) : (
          <div className="space-y-3">
            {ips.map(({ ip, count, actions }) => (
              <div
                key={ip}
                className="border-l-2 pl-3 py-1"
                style={{ borderColor: 'var(--color-border)' }}
              >
                <div className="flex items-center justify-between gap-2">
                  <span
                    className="font-mono text-xs font-semibold truncate flex-1 min-w-0"
                    style={{ color: 'var(--color-foreground)' }}
                    title={ip}
                  >
                    {ipLabel(ip)}
                  </span>
                  <span
                    className="text-xs font-mono shrink-0 px-1.5 py-0.5 rounded"
                    style={{
                      backgroundColor: 'var(--color-muted)',
                      color: 'var(--color-muted-foreground)',
                    }}
                  >
                    {count} {count === 1 ? 'call' : 'calls'}
                  </span>
                </div>
                {actions.length > 0 && (
                  <p
                    className="text-[11px] mt-0.5 truncate"
                    style={{ color: 'var(--color-muted-foreground)' }}
                    title={actions.join(', ')}
                  >
                    {actions.slice(0, 3).join(', ')}
                    {actions.length > 3 && ` +${actions.length - 3} more`}
                  </p>
                )}
              </div>
            ))}
          </div>
        )}
      </CardContent>
    </Card>
  )
}

export default SourceIPs
