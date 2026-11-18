import type { ForensicEvent } from '../types'
import { Card, CardHeader, CardTitle, CardContent } from '@/components/ui/card'
import { Box, Layers3 } from 'lucide-react'

export default function AffectedResources({ events, collecting, error }: { events: ForensicEvent[]; collecting: boolean; error: boolean }) {
  const groups = new Map<string, { resources: Set<string>; count: number }>()
  for (const event of events) {
    if (!event.affected_resource) continue
    const type = event.resource_type || 'Other resources'
    const group = groups.get(type) ?? { resources: new Set<string>(), count: 0 }
    group.resources.add(event.affected_resource); group.count++; groups.set(type, group)
  }
  const total = [...groups.values()].reduce((sum, group) => sum + group.resources.size, 0)
  return <Card className="forensic-card"><CardHeader className="forensic-card-header"><div className="forensic-card-heading"><span className="forensic-icon"><Layers3 size={17}/></span><div><CardTitle>Affected resources</CardTitle><p>Resources named in selected events</p></div></div>{total > 0 && <span className="forensic-count">{total} {total === 1 ? 'resource' : 'resources'}</span>}</CardHeader><CardContent className="forensic-card-content">
    {!groups.size ? <div className="forensic-empty"><Box size={18}/><div><strong>No resources identified</strong><p>{collecting ? 'Collection is in progress.' : error ? 'Collection failed; resources could not be assessed.' : events.length ? 'The selected events do not identify a resource.' : 'No events in the selected time range. Affected resources are unknown.'}</p></div></div> : <><div className="forensic-resource-groups">{[...groups].map(([type,group]) => <section key={type}><div className="forensic-resource-title"><span>{type.replace(/_/g, ' ')}</span><span>{group.count} {group.count === 1 ? 'event' : 'events'}</span></div><ul className="forensic-list">{[...group.resources].map(resource => <li key={resource}><code>{resource}</code></li>)}</ul></section>)}</div><p className="forensic-meta">A listed resource does not by itself prove impact or attribution to this credential.</p></>}
  </CardContent></Card>
}
