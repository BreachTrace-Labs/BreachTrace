import type { ForensicEvent } from '../types'
import { Card, CardHeader, CardTitle, CardContent } from '@/components/ui/card'
import { Database, Server, Key, Box } from 'lucide-react'

interface Props {
  events: ForensicEvent[]
}

type GroupedResource = {
  type: string
  resources: string[]
  count: number
}

const RESOURCE_ICONS: Record<string, React.ReactNode> = {
  bucket: <Database size={13} strokeWidth={2} />,
  instance: <Server size={13} strokeWidth={2} />,
  key: <Key size={13} strokeWidth={2} />,
}

function getIcon(type: string | null) {
  if (!type) return <Box size={13} strokeWidth={2} />
  const lower = type.toLowerCase()
  for (const [key, icon] of Object.entries(RESOURCE_ICONS)) {
    if (lower.includes(key)) return icon
  }
  return <Box size={13} strokeWidth={2} />
}

const AffectedResources: React.FC<Props> = ({ events }) => {
  const grouped = events.reduce<Record<string, GroupedResource>>((acc, e) => {
    if (!e.affected_resource) return acc
    const type = e.resource_type ?? 'resource'
    if (!acc[type]) acc[type] = { type, resources: [], count: 0 }
    if (!acc[type].resources.includes(e.affected_resource)) {
      acc[type].resources.push(e.affected_resource)
    }
    acc[type].count++
    return acc
  }, {})

  const groups = Object.values(grouped)

  return (
    <Card>
      <CardHeader className="pb-3">
        <CardTitle className="flex items-center gap-2 text-sm">
          Affected Resources
          {groups.length > 0 && (
            <span
              className="ml-auto text-xs font-mono px-1.5 py-0.5 rounded"
              style={{ backgroundColor: 'var(--color-muted)', color: 'var(--color-muted-foreground)' }}
            >
              {groups.reduce((s, g) => s + g.resources.length, 0)}
            </span>
          )}
        </CardTitle>
      </CardHeader>
      <CardContent>
        {groups.length === 0 ? (
          <p className="text-sm" style={{ color: 'var(--color-muted-foreground)' }}>
            No resources affected
          </p>
        ) : (
          <div className="space-y-4">
            {groups.map((g) => (
              <div key={g.type}>
                <div
                  className="flex items-center gap-1.5 mb-2 text-xs font-semibold uppercase tracking-wider"
                  style={{ color: 'var(--color-muted-foreground)' }}
                >
                  {getIcon(g.type)}
                  {g.type}
                  <span className="ml-auto">{g.count} events</span>
                </div>
                <ul className="space-y-1">
                  {g.resources.map((r) => (
                    <li
                      key={r}
                      className="font-mono text-xs py-1.5 px-2 border-l-2 truncate"
                      style={{
                        borderColor: 'var(--color-border)',
                        color: 'var(--color-foreground)',
                      }}
                      title={r}
                    >
                      {r}
                    </li>
                  ))}
                </ul>
              </div>
            ))}
          </div>
        )}
      </CardContent>
    </Card>
  )
}

export default AffectedResources
