import type { IncidentRecord } from '@/types'

export default function GCPRecordCorrelation({ incident }: { incident: IncidentRecord }) {
  const correlation = incident.gcp_record_correlation
  if (!correlation || correlation.raw_record_count === 0) return null
  const events = new Map(incident.events.map(event => [event.event_id, event]))
  const groups = correlation.groups.slice(0, 50)
  return <section className="mb-6 rounded-md border bg-muted/20 p-4" aria-label="Related GCP audit records">
    <h3 className="font-semibold">Related audit records</h3>
    <p className="mt-1 text-sm text-muted-foreground">All collected history: {correlation.raw_record_count} stored records · {correlation.group_count} related {correlation.group_count === 1 ? 'group' : 'groups'} · {correlation.ungrouped_record_count} ungrouped. Grouping does not prove a leaked key was used or that an operation succeeded.</p>
    {groups.length === 0 ? <p className="mt-3 text-sm text-muted-foreground">No records share a supported correlation identifier. Individual records remain in the timeline below.</p> : <div className="mt-3 space-y-2">
      {groups.map(group => <details key={group.event_ids[0]} className="rounded-md border bg-card p-3">
        <summary className="cursor-pointer text-sm font-medium">{group.kind === 'provider_operation' ? 'Provider operation' : 'Client invocation'} · {group.record_count} records <span className="text-muted-foreground">· {group.confidence} confidence</span></summary>
        <p className="mt-2 text-xs text-muted-foreground">{group.kind === 'provider_operation' ? 'Records share the provider operation ID and producer.' : 'Records share a client-supplied gcloud invocation ID. A command can contain multiple actions; the identifier can be spoofed.'} Record outcomes: {group.successful_count} successful, {group.failed_count} failed.</p>
        <ul className="mt-2 space-y-2 text-sm">{group.event_ids.slice(0, 50).map(id => {
          const event = events.get(id)
          return event ? <li key={id} className="border-t pt-2"><span className="font-mono break-all">{event.api_action}</span> · {event.success ? 'Succeeded' : event.is_denied ? 'Denied' : 'Failed'}<span className="block text-xs text-muted-foreground">{new Date(event.timestamp).toLocaleString()}{event.affected_resource ? ` · ${event.affected_resource}` : ''}</span></li> : null
        })}</ul>
        {group.event_ids.length > 50 && <p className="mt-2 text-xs text-muted-foreground">Showing 50 of {group.event_ids.length} records in this group. All records remain in the timeline.</p>}
      </details>)}
      {correlation.group_count > groups.length && <p className="text-xs text-muted-foreground">Showing {groups.length} of {correlation.group_count} groups. All records remain in the timeline.</p>}
    </div>}
  </section>
}
