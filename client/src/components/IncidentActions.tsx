import { useEffect, useState } from 'react'
import { realClient, USE_MOCK } from '@/api/client'
import type { IncidentRecord } from '@/types'
import { Button } from '@/components/ui/button'

type Member = { id: string; full_name: string; email: string; is_active: boolean }
type Audit = { id: string; action: string; actor_name: string | null; created_at: string; detail: Record<string, unknown> | null }
const choices = [
  {value:'false_positive', label:'False positive', description:'The detected value is not a credential exposure.'},
  {value:'test_credential', label:'Test credential', description:'The value is a test credential.'},
  {value:'acknowledged', label:'Acknowledged', description:'The team has reviewed the incident.'},
  {value:'rotated', label:'Rotated', description:'The credential has been rotated.'},
]
const message = (error: unknown) => { const detail = (error as { response?: { data?: { detail?: unknown } } }).response?.data?.detail; return typeof detail === 'string' ? detail : 'The action could not be completed. Check your access and try again.' }

export default function IncidentActions({ incident, canManage, onChange }: { incident: IncidentRecord; canManage: boolean; onChange: (incident: IncidentRecord) => void }) {
  const [open, setOpen] = useState(false); const [type, setType] = useState('false_positive'); const [reason, setReason] = useState('')
  const [members, setMembers] = useState<Member[]>([]); const [assignee, setAssignee] = useState(''); const [audit, setAudit] = useState<Audit[] | null>(null)
  const [error, setError] = useState(''); const [busy, setBusy] = useState(false)
  useEffect(() => {
    if (!canManage || !incident.project_id || USE_MOCK) return
    let active = true
    realClient.get<Member[]>(`/projects/${incident.project_id}/members`).then(({data}) => { if (active) setMembers(data.filter(member => member.is_active)) }).catch(() => { if (active) setError('Could not load project members.') })
    return () => { active = false }
  }, [canManage, incident.project_id])
  if (USE_MOCK) return null
  const dismiss = async (event: React.FormEvent) => {
    event.preventDefault(); setBusy(true); setError('')
    try { const {data} = await realClient.post<IncidentRecord>(`/incidents/${incident.incident_id}/dismiss`, { dismissal_type:type, reason }); onChange(data); setOpen(false); setReason(''); setAudit(null) }
    catch (err) { setError(message(err)) } finally { setBusy(false) }
  }
  const assign = async () => {
    if (!assignee) return
    setBusy(true); setError('')
    try { const {data} = await realClient.post<IncidentRecord>(`/incidents/${incident.incident_id}/assign`, { user_id:assignee }); onChange(data); setAudit(null) }
    catch (err) { setError(message(err)) } finally { setBusy(false) }
  }
  const loadAudit = async () => {
    if (audit) { setAudit(null); return }
    setError(''); setBusy(true)
    try { const {data} = await realClient.get<Audit[]>(`/incidents/${incident.incident_id}/audit`); setAudit(data) }
    catch (err) { setError(message(err)) } finally { setBusy(false) }
  }
  return <section className="space-y-3" aria-label="Incident actions">
    {incident.dismissed && <div className="border rounded p-4 text-sm bg-yellow-500/10"><strong>Dismissed as {(incident.dismissal_type ?? '').replaceAll('_',' ')}</strong> by {incident.dismissed_by_name ?? 'a team member'}{incident.dismissed_at ? ` on ${new Date(incident.dismissed_at).toLocaleString()}` : ''}: {incident.dismissal_reason}</div>}
    <div className="flex flex-wrap gap-3 items-center"><span className="text-sm">Assigned to: {incident.assigned_to_name ?? 'Unassigned'}</span>
      <Button size="sm" variant="outline" onClick={() => setOpen(true)}>Dismiss</Button>
      {canManage && <><select aria-label="Assign incident" className="border rounded p-2 bg-transparent text-sm" value={assignee} onChange={event => setAssignee(event.target.value)}><option value="">Select a project member</option>{members.map(member => <option key={member.id} value={member.id}>{member.full_name}</option>)}</select><Button size="sm" variant="outline" disabled={!assignee || busy} onClick={() => void assign()}>Assign</Button><Button size="sm" variant="outline" disabled={busy} onClick={() => void loadAudit()}>{audit ? 'Hide audit trail' : 'View audit trail'}</Button></>}
    </div>
    {error && <p role="alert" className="text-red-500 text-sm">{error}</p>}
    {open && <div className="fixed inset-0 z-[70] bg-black/60 flex items-center justify-center p-4" role="dialog" aria-modal="true" aria-labelledby="dismiss-title"><form className="w-full max-w-lg bg-background border rounded p-6 space-y-4" onSubmit={event => void dismiss(event)}><h2 id="dismiss-title" className="font-semibold text-lg">Dismiss incident</h2><fieldset className="space-y-2"><legend className="text-sm font-medium">Reason for dismissal</legend>{choices.map(choice => <label key={choice.value} className="flex gap-2 text-sm"><input type="radio" name="dismissal-type" value={choice.value} checked={type===choice.value} onChange={() => setType(choice.value)} /><span><strong>{choice.label}</strong><span className="block text-muted-foreground">{choice.description}</span></span></label>)}</fieldset><label className="block text-sm">Explanation (at least 10 characters)<textarea className="block w-full mt-1 border rounded p-2 bg-transparent" minLength={10} maxLength={500} required value={reason} onChange={event => setReason(event.target.value)} /></label><div className="flex gap-2"><Button disabled={busy || reason.trim().length<10}>Confirm dismissal</Button><Button type="button" variant="outline" onClick={() => setOpen(false)}>Cancel</Button></div></form></div>}
    {audit && <div className="border rounded p-4 space-y-2"><h2 className="font-semibold">Incident audit trail</h2>{audit.length ? audit.map(item => <p key={item.id} className="text-sm">{new Date(item.created_at).toLocaleString()} · {item.actor_name ?? 'System'} · {item.action}</p>) : <p className="text-sm">No audit entries.</p>}</div>}
  </section>
}
