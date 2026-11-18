import { useCallback, useEffect, useState, type FormEvent } from 'react'
import { realClient } from '@/api/client'
import { Button } from '@/components/ui/button'
import { SlideOver } from '@/components/ui/overlay'
import './project-management.css'

type Config = {
  id: string
  channel: 'email' | 'slack'
  target: string | null
  target_display: string
  enabled: boolean
  min_severity: string
}
type Delivery = { id: string; type: string; channel: string; incident_id: string | null; status: string; outcome: string | null; attempts: number; max_attempts: number; last_error: string | null; created_at: string }

const levels = ['low', 'medium', 'high', 'critical']
const input = 'min-w-0 w-full rounded-md border bg-transparent p-2 text-sm'
const errorMessage = (error: unknown) => {
  const detail = (error as { response?: { data?: { detail?: unknown } } }).response?.data?.detail
  return typeof detail === 'string' ? detail : 'Could not update notification settings.'
}

export default function ProjectNotifications({ projectId, projectName }: { projectId: string; projectName: string }) {
  const [open, setOpen] = useState(false)
  const [items, setItems] = useState<Config[]>([])
  const [deliveries, setDeliveries] = useState<Delivery[]>([])
  const [smtpReady, setSmtpReady] = useState(false)
  const [channel, setChannel] = useState<'email' | 'slack'>('email')
  const [target, setTarget] = useState('')
  const [replacementTargets, setReplacementTargets] = useState<Record<string, string>>({})
  const [severity, setSeverity] = useState('low')
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')
  const [notice, setNotice] = useState('')

  const load = useCallback(async () => {
    try {
      const { data } = await realClient.get<{ items: Config[]; smtp_configured: boolean }>(`/projects/${projectId}/notifications`)
      setItems(data.items)
      setSmtpReady(data.smtp_configured)
      const history = await realClient.get<Delivery[]>(`/projects/${projectId}/notification-deliveries`)
      setDeliveries(history.data)
      setError(previous => previous === 'Could not load notification settings.' ? '' : previous)
    } catch { setError(previous => previous || 'Could not load notification settings.') }
  }, [projectId])

  useEffect(() => { void load() }, [load])
  useEffect(() => { const timer = window.setInterval(() => { void load() }, 5000); return () => window.clearInterval(timer) }, [load])

  async function save(action: () => Promise<unknown>, message: string) {
    setBusy(true); setError(''); setNotice('')
    try { await action(); await load(); setNotice(message) }
    catch (err) { setError(errorMessage(err)) }
    finally { setBusy(false) }
  }

  async function add(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    await save(async () => {
      await realClient.post(`/projects/${projectId}/notifications`, { channel, target, min_severity: severity })
      setTarget(''); setOpen(false)
    }, 'Notification destination added.')
  }

  return <section className="rounded-lg border bg-card p-5 space-y-4" aria-label={`Notifications for ${projectName}`}>
    <div className="pm-heading"><div><h2>Notifications · {projectName}</h2><p>Send alerts when a new incident is processed. Severity filters use the forensic score.</p></div><Button onClick={() => { setError(''); setOpen(true) }}>Add notification</Button></div>
    {!smtpReady && <p className="text-sm border rounded p-3">SMTP is not configured on the backend. Email notifications and welcome emails will not be delivered until SMTP_HOST and SMTP_FROM are set.</p>}
    {error && !open && <p role="alert" className="text-red-500 text-sm">{error}</p>}{notice && <p role="status" className="text-sm">{notice}</p>}
    {items.length === 0 ? <p className="text-sm text-muted-foreground">No notification destinations configured.</p> : <div className="space-y-2">
      {items.map(item => <div key={item.id} className="border rounded p-3 flex flex-wrap gap-3 items-center justify-between">
        <div className="min-w-0"><strong className="capitalize">{item.channel}</strong><p className="text-sm break-all">{item.target_display}</p></div>
        <label className="flex items-center gap-2 text-sm"><span>Minimum severity</span>
          <select aria-label={`Minimum severity for ${item.target_display}`} className="border rounded p-2 bg-transparent" value={item.min_severity}
            disabled={busy} onChange={e => void save(() => realClient.put(`/projects/${projectId}/notifications/${item.id}`, { min_severity: e.target.value }), 'Severity filter updated.')}>
            {levels.map(level => <option key={level} value={level}>{level}</option>)}
          </select>
        </label>
        <label className="flex items-center gap-2 text-sm"><input type="checkbox" checked={item.enabled} disabled={busy}
          onChange={e => void save(() => realClient.put(`/projects/${projectId}/notifications/${item.id}`, { enabled: e.target.checked }), e.target.checked ? 'Notification enabled.' : 'Notification disabled.')} />Enabled</label>
        {item.channel === 'slack' && <form className="flex flex-wrap gap-2 w-full sm:flex-nowrap" onSubmit={e => { e.preventDefault(); void save(async () => { await realClient.put(`/projects/${projectId}/notifications/${item.id}`, { target: replacementTargets[item.id] }); setReplacementTargets(previous => ({ ...previous, [item.id]: '' })) }, 'Slack webhook replaced.') }}>
          <input className={`${input} min-w-0 flex-1`} type="url" aria-label="Replace Slack webhook URL" placeholder="Replace Slack webhook URL" value={replacementTargets[item.id] ?? ''} onChange={e => setReplacementTargets(previous => ({ ...previous, [item.id]: e.target.value }))} />
          <Button type="submit" variant="outline" disabled={busy || !replacementTargets[item.id]}>Replace</Button>
        </form>}
        <Button size="sm" variant="outline" disabled={busy} onClick={() => { if (window.confirm(`Remove this ${item.channel} notification destination?`)) void save(() => realClient.delete(`/projects/${projectId}/notifications/${item.id}`), 'Notification destination removed.') }}>Remove</Button>
      </div>)}
    </div>}
    <SlideOver open={open} title="Add notification" onClose={() => { setOpen(false); setTarget(''); setError('') }} preventClose={busy} footer={<><Button type="button" variant="ghost" disabled={busy} onClick={() => { setOpen(false); setTarget(''); setError('') }}>Cancel</Button><Button type="submit" form="notification-form" loading={busy}>Add destination</Button></>}>
    <form id="notification-form" className="grid gap-3" onSubmit={add}>
      <label htmlFor="notification-channel" className="text-sm font-medium">Channel</label>
      <select id="notification-channel" className={input} aria-label="Notification channel" value={channel} onChange={e => { setChannel(e.target.value as 'email' | 'slack'); setTarget('') }}>
        <option value="email">Email</option><option value="slack">Slack incoming webhook</option>
      </select>
      <label htmlFor="notification-severity" className="text-sm font-medium">Minimum severity</label><select id="notification-severity" className={input} aria-label="New notification minimum severity" value={severity} onChange={e => setSeverity(e.target.value)}>
        {levels.map(level => <option key={level} value={level}>Minimum: {level}</option>)}
      </select>
      <label htmlFor="notification-target" className="text-sm font-medium">{channel === 'email' ? 'Email address' : 'Slack incoming webhook URL'}</label><input id="notification-target" className={input} required aria-label={channel === 'email' ? 'Notification email address' : 'Slack incoming webhook URL'}
        type={channel === 'email' ? 'email' : 'url'} autoComplete="off"
        placeholder={channel === 'email' ? 'security@example.com' : 'https://hooks.slack.com/services/…'} value={target} onChange={e => setTarget(e.target.value)} />
      <p className="sm:col-span-2 text-xs text-muted-foreground">Slack webhook URLs are encrypted and cannot be viewed after saving. Incidents without a severity score notify only destinations set to “low” and are labeled “not assessed.”</p>
      {error && <p role="alert" className="pm-error">{error}</p>}
    </form></SlideOver>
    <div className="space-y-2"><h3 className="font-medium">Recent deliveries</h3>
      {deliveries.length === 0 ? <p className="text-sm text-muted-foreground">No deliveries yet.</p> : deliveries.map(delivery => <div className="border rounded p-3 text-sm" key={delivery.id}>
        <div className="flex flex-wrap items-center justify-between gap-2"><span>{delivery.channel} · {delivery.type === 'incident_assigned' ? 'Assignment' : 'New incident'} · {delivery.status === 'complete' ? delivery.outcome ?? 'complete' : delivery.status} · Attempt {delivery.attempts}/{delivery.max_attempts}</span>
          {delivery.status === 'failed' && <Button size="sm" variant="outline" disabled={busy} onClick={() => void save(() => realClient.post(`/projects/${projectId}/notification-deliveries/${delivery.id}/retry`), 'Delivery queued for retry.')}>Retry</Button>}</div>
        {delivery.incident_id && <p className="text-xs text-muted-foreground">Incident: {delivery.incident_id}</p>}
        {delivery.last_error && <p className="text-xs text-muted-foreground">{delivery.last_error}</p>}
      </div>)}
    </div>
  </section>
}
