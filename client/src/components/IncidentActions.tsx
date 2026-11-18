import { useEffect, useState } from 'react'
import { realClient, USE_MOCK } from '@/api/client'
import type { IncidentRecord } from '@/types'
import { Button } from '@/components/ui/button'
import { Modal, SlideOver } from '@/components/ui/overlay'
import './incident-actions.css'

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
  const [open, setOpen] = useState(false); const [assignOpen, setAssignOpen] = useState(false); const [type, setType] = useState(''); const [reason, setReason] = useState('')
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
    try { const {data} = await realClient.post<IncidentRecord>(`/incidents/${incident.incident_id}/dismiss`, { dismissal_type:type, reason }); onChange(data); setOpen(false); setReason(''); setType(''); setAudit(null) }
    catch (err) { setError(message(err)) } finally { setBusy(false) }
  }
  const assign = async () => {
    if (!assignee) return
    setBusy(true); setError('')
    try { const {data} = await realClient.post<IncidentRecord>(`/incidents/${incident.incident_id}/assign`, { user_id:assignee }); onChange(data); setAudit(null); setAssignOpen(false) }
    catch (err) { setError(message(err)) } finally { setBusy(false) }
  }
  const loadAudit = async () => {
    if (audit) { setAudit(null); return }
    setError(''); setBusy(true)
    try { const {data} = await realClient.get<Audit[]>(`/incidents/${incident.incident_id}/audit`); setAudit(data) }
    catch (err) { setError(message(err)) } finally { setBusy(false) }
  }
  return <section className="incident-actions" aria-label="Incident actions">
    {incident.dismissed && <div className="incident-dismissed" role="status"><strong>Dismissed as {(incident.dismissal_type ?? '').replaceAll('_',' ')}</strong> by {incident.dismissed_by_name ?? 'a team member'}{incident.dismissed_at ? ` on ${new Date(incident.dismissed_at).toLocaleString()}` : ''}<p>{incident.dismissal_reason}</p></div>}
    <div className="incident-action-row"><span>Assigned to: {incident.assigned_to_name ?? 'Unassigned'}</span><Button size="sm" variant="outline" onClick={() => { setError(''); setOpen(true) }}>Dismiss</Button>{canManage && <><Button size="sm" variant="outline" onClick={() => { setError(''); setAssignOpen(true) }}>Assign</Button><Button size="sm" variant="outline" loading={busy && !open && !assignOpen} onClick={() => void loadAudit()}>{audit ? 'Hide audit trail' : 'View audit trail'}</Button></>}</div>
    {error && !open && !assignOpen && <p role="alert" className="incident-action-error">{error}</p>}
    <Modal open={open} title="Dismiss incident" onClose={() => setOpen(false)} preventClose={busy} footer={<><Button type="button" variant="ghost" disabled={busy} onClick={() => setOpen(false)}>Cancel</Button><Button type="submit" form="dismiss-incident" variant="danger" loading={busy} disabled={!type || reason.trim().length < 10}>Dismiss incident</Button></>}>
      <form id="dismiss-incident" className="incident-action-form" onSubmit={event => void dismiss(event)}><fieldset><legend>Reason for dismissal</legend>{choices.map(choice => <label key={choice.value} className="incident-radio"><input type="radio" name="dismissal-type" value={choice.value} checked={type === choice.value} onChange={() => setType(choice.value)}/><span><strong>{choice.label}</strong><small>{choice.description}</small></span></label>)}</fieldset><label>Reason<textarea minLength={10} maxLength={500} required value={reason} onChange={event => setReason(event.target.value)} placeholder="Briefly describe why this is being dismissed..."/></label><p className="incident-action-hint">{reason.length}/500 characters · at least 10 required</p>{error && <p role="alert" className="incident-action-error">{error}</p>}</form>
    </Modal>
    <Modal open={assignOpen} title="Assign incident" onClose={() => setAssignOpen(false)} preventClose={busy} footer={<><Button type="button" variant="ghost" disabled={busy} onClick={() => setAssignOpen(false)}>Cancel</Button><Button loading={busy} disabled={!assignee} onClick={() => void assign()}>Assign</Button></>}><div className="incident-action-form"><p>Choose an active project member. An email notification will be queued if delivery is configured.</p><label>Project member<select value={assignee} onChange={event => setAssignee(event.target.value)}><option value="">Select a member</option>{members.map(member => <option key={member.id} value={member.id}>{member.full_name} · {member.email}</option>)}</select></label>{error && <p role="alert" className="incident-action-error">{error}</p>}</div></Modal>
    <SlideOver open={audit !== null} title="Incident audit trail" onClose={() => setAudit(null)}><div className="incident-audit">{audit?.length ? audit.map(item => <p key={item.id}><time>{new Date(item.created_at).toLocaleString()}</time> · {item.actor_name ?? 'System'} · {item.action}</p>) : <p>No audit entries.</p>}</div></SlideOver>
  </section>
}
