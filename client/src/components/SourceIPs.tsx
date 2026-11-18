import type { ForensicEvent } from '../types'
import { Card, CardHeader, CardTitle, CardContent } from '@/components/ui/card'
import { Globe, Info } from 'lucide-react'

export default function SourceIPs({ events, platform, collecting, error }: { events: ForensicEvent[]; platform: string; collecting: boolean; error: boolean }) {
  const counts = new Map<string, { count: number; actions: Set<string> }>()
  for (const event of events) {
    const ip = event.source_ip?.trim()
    if (!ip) continue
    const entry = counts.get(ip) ?? { count: 0, actions: new Set<string>() }
    entry.count++; if (event.api_action) entry.actions.add(event.api_action); counts.set(ip, entry)
  }
  const missing = events.filter(event => !event.source_ip?.trim()).length
  const entries = [...counts.entries()].sort((a,b) => b[1].count-a[1].count)
  return <Card className="forensic-card"><CardHeader className="forensic-card-header"><div className="forensic-card-heading"><span className="forensic-icon"><Globe size={17}/></span><div><CardTitle>Source IPs</CardTitle><p>Addresses reported by the provider</p></div></div>{entries.length > 0 && <span className="forensic-count">{entries.length} {entries.length === 1 ? 'address' : 'addresses'}</span>}</CardHeader><CardContent className="forensic-card-content">
    {entries.length ? <ul className="forensic-list">{entries.map(([ip, entry]) => <li key={ip}><div className="forensic-list-title"><code>{ip}</code><span>{entry.count} {entry.count === 1 ? 'event' : 'events'}</span></div>{entry.actions.size > 0 && <p>{[...entry.actions].slice(0,3).join(', ')}{entry.actions.size > 3 && ` +${entry.actions.size - 3} more`}</p>}</li>)}</ul> : <div className="forensic-empty"><Globe size={18}/><div><strong>No source IPs available</strong><p>{collecting ? 'Collection is in progress.' : error ? 'Collection failed; source IPs could not be assessed.' : events.length ? 'The selected events do not contain source IPs.' : 'No events in the selected time range. Source IPs are unknown.'}</p></div></div>}
    {missing > 0 && entries.length > 0 && <p className="forensic-meta">{missing} {missing === 1 ? 'event has' : 'events have'} no source IP.</p>}
    {platform === 'stripe' && <p className="forensic-provider-note"><Info size={14}/>Stripe Events and the supported sandbox request stream do not supply source IPs.</p>}
    {platform === 'twilio' && <p className="forensic-provider-note"><Info size={14}/>Twilio message and call records do not supply source IPs; some Monitor events may.</p>}
  </CardContent></Card>
}
