import { useEffect, useState } from 'react'
import { realClient } from '@/api/client'
import { Button } from '@/components/ui/button'

type Schedule = { enabled: boolean; interval_minutes: number; next_run_at: string | null; status: string; error: string | null; last_run: { last_run_at: string; queued: number; skipped: number; reason?: string } | null }

export default function AutoRefreshSettings({ incidentId }: { incidentId: string }) {
  const [schedule, setSchedule] = useState<Schedule | null>(null)
  const [enabled, setEnabled] = useState(false)
  const [minutes, setMinutes] = useState(60)
  const [busy, setBusy] = useState(false)
  const [message, setMessage] = useState('')
  const [error, setError] = useState('')
  useEffect(() => {
    let active = true
    realClient.get<Schedule>(`/incidents/${incidentId}/auto-refresh`).then(({data}) => {
      if (active) { setSchedule(data); setEnabled(data.enabled); setMinutes(data.interval_minutes) }
    }).catch(() => { if (active) setError('Could not load automatic refresh settings.') })
    return () => { active = false }
  }, [incidentId])
  async function save(event: React.FormEvent) {
    event.preventDefault(); setBusy(true); setError(''); setMessage('')
    try {
      const {data} = await realClient.put<Schedule>(`/incidents/${incidentId}/auto-refresh`, { enabled, interval_minutes: minutes })
      setSchedule(data); setEnabled(data.enabled); setMinutes(data.interval_minutes); setMessage('Automatic refresh settings saved.')
    } catch (err) {
      const detail = (err as { response?: { data?: { detail?: unknown } } }).response?.data?.detail
      setError(typeof detail === 'string' ? detail : 'Could not save automatic refresh settings.')
    } finally { setBusy(false) }
  }
  return <details className="rounded-sm border bg-card p-4"><summary className="cursor-pointer text-sm font-semibold">Automatic log refresh</summary><form className="space-y-3 pt-3" onSubmit={event => void save(event)}>
    <p className="text-sm text-muted-foreground">Set a separate refresh interval for this credential incident. It uses the project’s verified provider connection.</p>
    <label className="flex items-center gap-2"><input type="checkbox" checked={enabled} onChange={event => setEnabled(event.target.checked)} disabled={!schedule || busy} /> Automatically refresh incident logs</label>
    <label className="block">Refresh interval (minutes)<input className="mt-1 block w-full rounded border bg-transparent p-2" type="number" min={15} max={10080} step={1} value={minutes} onChange={event => setMinutes(Number(event.target.value))} disabled={!schedule || busy} required /></label>
    <p className="text-sm text-muted-foreground">Minimum 15 minutes; maximum 7 days. A run is skipped if the reader is unavailable or a collection is already in progress. The backend must be running.</p>
    {schedule?.enabled && <p className="text-sm">Status: {schedule.status}{schedule.next_run_at ? ` · Next run: ${new Date(schedule.next_run_at).toLocaleString()}` : ''}</p>}
    {schedule?.last_run && <p className="text-sm">Last run: {new Date(schedule.last_run.last_run_at).toLocaleString()} · {schedule.last_run.queued ? 'refresh queued' : 'skipped'}{schedule.last_run.reason ? ` · ${schedule.last_run.reason}` : ''}.</p>}
    {schedule?.error && <p role="alert">Last schedule error: {schedule.error}</p>}
    <Button type="submit" disabled={!schedule || busy} loading={busy}>Save schedule</Button>
    {error && <p role="alert" className="settings-error">{error}</p>}{message && <p role="status" className="settings-message">{message}</p>}
  </form></details>
}
