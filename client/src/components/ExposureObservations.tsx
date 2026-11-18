import { useEffect, useState } from 'react'
import { realClient, USE_MOCK } from '@/api/client'
import { Button } from '@/components/ui/button'

type Observation = { id: string; kind: string; observed_at: string; recorded_at: string; recorded_by: string; source: string; confidence: string; credential_hint: string }
const labels: Record<string, string> = { revoked: 'Revoked', rotated: 'Rotated', expired: 'Expired', active: 'Still active', inconclusive: 'Inconclusive' }

export default function ExposureObservations({ incidentId, canManage }: { incidentId: string; canManage: boolean }) {
  const [items, setItems] = useState<Observation[]>([])
  const [error, setError] = useState('')
  const [open, setOpen] = useState(false)
  const [busy, setBusy] = useState(false)
  const [kind, setKind] = useState('revoked')
  const [when, setWhen] = useState('')
  const [source, setSource] = useState('')
  const [confidence, setConfidence] = useState('medium')
  useEffect(() => {
    if (USE_MOCK) return
    let active = true
    realClient.get<Observation[]>(`/incidents/${incidentId}/exposure-observations`).then(({ data }) => { if (active) setItems(data) }).catch(() => { if (active) setError('Could not load exposure observations.') })
    return () => { active = false }
  }, [incidentId])
  if (USE_MOCK) return null
  async function submit(event: React.FormEvent) {
    event.preventDefault(); setBusy(true); setError('')
    try {
      const { data } = await realClient.post<Observation>(`/incidents/${incidentId}/exposure-observations`, { kind, observed_at: new Date(when).toISOString(), source, confidence })
      setItems(current => [data, ...current]); setOpen(false); setWhen(''); setSource('')
    } catch (err) {
      const detail = (err as { response?: { data?: { detail?: unknown } } }).response?.data?.detail
      setError(typeof detail === 'string' ? detail : 'Could not save the observation. Check its time and source.')
    } finally { setBusy(false) }
  }
  return <section className="rounded-lg border bg-card p-5 space-y-4" aria-label="Exposure evidence">
    <div className="flex flex-wrap items-start justify-between gap-3"><div><h2 className="font-semibold">Exposure evidence</h2><p className="text-sm text-muted-foreground">Record what your team observed about this credential.</p></div>{canManage && <Button size="sm" variant="outline" onClick={() => { setOpen(!open); setError('') }}>{open ? 'Cancel' : 'Record observation'}</Button>}</div>
    <p className="text-sm text-muted-foreground">These are operator-reported observations, not provider-verified closure. They do not change the event window or prove when exposure ended.</p>
    {open && <form onSubmit={e => void submit(e)} className="space-y-3"><label className="block text-sm">Observation<select className="mt-1 w-full rounded border bg-background p-2" value={kind} onChange={e => setKind(e.target.value)}>{Object.entries(labels).map(([value, label]) => <option key={value} value={value}>{label}</option>)}</select></label><label className="block text-sm">Time observed (your local time)<input className="mt-1 w-full rounded border bg-background p-2" type="datetime-local" required value={when} onChange={e => setWhen(e.target.value)}/></label><label className="block text-sm">Evidence source<input className="mt-1 w-full rounded border bg-background p-2" required minLength={3} maxLength={200} value={source} onChange={e => setSource(e.target.value)} placeholder="For example, provider audit record ID"/></label><p className="text-xs text-muted-foreground">Do not enter credentials or sensitive provider URLs. A failed login alone does not prove revocation.</p><label className="block text-sm">Your confidence<select className="mt-1 w-full rounded border bg-background p-2" value={confidence} onChange={e => setConfidence(e.target.value)}><option value="low">Low</option><option value="medium">Medium</option><option value="high">High</option></select></label><Button type="submit" loading={busy}>Save observation</Button></form>}
    {error && <p role="alert" className="text-sm text-red-500">{error}</p>}
    {!items.length ? <p className="text-sm text-muted-foreground">No observations recorded yet.</p> : <ul className="space-y-3">{items.map(item => <li key={item.id} className="border-t pt-3 text-sm"><strong>{labels[item.kind] ?? item.kind}</strong> <span className="text-muted-foreground">· Operator reported · {item.confidence} confidence</span><p>Observed {new Date(item.observed_at).toLocaleString()} · {item.credential_hint}</p><p className="break-words">Source: {item.source}</p><p className="text-xs text-muted-foreground">Recorded by {item.recorded_by} on {new Date(item.recorded_at).toLocaleString()}</p></li>)}</ul>}
  </section>
}
