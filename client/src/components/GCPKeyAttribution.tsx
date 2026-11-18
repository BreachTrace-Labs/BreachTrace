import { useState } from 'react'
import { realClient, USE_MOCK } from '@/api/client'
import { Button } from '@/components/ui/button'
import type { IncidentRecord } from '@/types'

export default function GCPKeyAttribution({ incident, canManage, onChange }: { incident: IncidentRecord; canManage: boolean; onChange: (incident: IncidentRecord) => void }) {
  const [open, setOpen] = useState(false); const [key, setKey] = useState(''); const [confirmed, setConfirmed] = useState(false); const [busy, setBusy] = useState(false); const [error, setError] = useState('')
  if (USE_MOCK || !incident.principal_id) return null
  async function submit(event: React.FormEvent) {
    event.preventDefault(); setBusy(true); setError('')
    try {
      await realClient.post(`/incidents/${incident.incident_id}/gcp-key-association`, { key_id: key.trim(), confirms_incident_key: confirmed })
      const { data } = await realClient.get<IncidentRecord>(`/incidents/${incident.incident_id}`)
      onChange(data); setOpen(false); setKey(''); setConfirmed(false)
    } catch { setError('Could not associate this key ID. Check its format and your access, then try again.') } finally { setBusy(false) }
  }
  return <section className="rounded-lg border bg-card p-5 space-y-3"><div className="flex flex-wrap items-start justify-between gap-3"><div><h2 className="font-semibold">GCP key attribution</h2><p className="text-sm text-muted-foreground">Compare audit records with the associated service-account key ID.</p></div>{canManage && <Button size="sm" variant="outline" onClick={() => { setOpen(!open); setError('') }}>{open ? 'Cancel' : incident.gcp_key_association ? 'Change key ID' : 'Associate key ID'}</Button>}</div>
    {incident.gcp_key_association ? <p className="text-sm">Associated key {incident.gcp_key_association.key_hint} · {incident.gcp_key_association.verification === 'detected_in_commit' ? 'found in the committed key document' : incident.gcp_key_association.verification === 'detected_in_simulation' ? 'found in the simulated key document' : `reported by ${incident.gcp_key_association.recorded_by ?? 'a team member'}`}</p> : <p className="text-sm text-muted-foreground">No key ID associated. Activity remains service-account level.</p>}
    <p className="text-sm text-muted-foreground">Matching events identify the key used to obtain credentials, if Google supplied the key name. Detection does not verify that a key is valid or was misused; manually associated IDs are reported by your team. Missing key names remain inconclusive. Other events remain visible as context.</p>
    {open && <form onSubmit={e => void submit(e)} className="space-y-3"><label className="block text-sm">Service-account key ID<input className="mt-1 w-full rounded border bg-background p-2 font-mono" required pattern="[a-fA-F0-9]{40}" maxLength={40} value={key} onChange={e => setKey(e.target.value)} autoComplete="off"/></label><p className="text-xs text-muted-foreground">Enter the 40-character key ID, never the private key or service-account JSON.</p><label className="flex gap-2 text-sm"><input type="checkbox" required checked={confirmed} onChange={e => setConfirmed(e.target.checked)}/>I have verified this ID belongs to the credential involved in this incident.</label><Button type="submit" loading={busy}>Associate key ID</Button></form>}{error && <p role="alert" className="text-sm text-red-500">{error}</p>}</section>
}
