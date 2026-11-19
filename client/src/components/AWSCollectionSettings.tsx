import { useState } from 'react'
import { realClient } from '@/api/client'
import { Button } from '@/components/ui/button'

type Settings = { regions: string; trail_bucket: string; trail_prefix: string }

export default function AWSCollectionSettings({ projectId, onSaved }: { projectId: string; onSaved: () => Promise<void> }) {
  const [settings, setSettings] = useState<Settings>({ regions: '', trail_bucket: '', trail_prefix: '' })
  const [loaded, setLoaded] = useState(false)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')
  const [notice, setNotice] = useState('')
  const url = `/projects/${projectId}/wallet/aws-collection-settings`
  const message = (err: unknown) => { const detail = (err as { response?: { data?: { detail?: unknown } } }).response?.data?.detail; return typeof detail === 'string' ? detail : 'Unable to update CloudTrail settings.' }
  async function load() {
    setBusy(true); setError('')
    try { const { data } = await realClient.get<Settings>(url); setSettings(data); setLoaded(true) }
    catch (err) { setError(message(err)) } finally { setBusy(false) }
  }
  async function save(event: React.FormEvent) {
    event.preventDefault(); setBusy(true); setError(''); setNotice('')
    try { const { data } = await realClient.put<Settings>(url, settings); setSettings(data); setNotice('Settings saved. Refresh logs to collect with these settings.'); await onSaved() }
    catch (err) { setError(message(err)) } finally { setBusy(false) }
  }
  const input = 'mt-1 block w-full rounded-sm border bg-transparent p-2 text-sm'
  return <details className="mb-4 rounded-sm border p-3" onToggle={event => { if (event.currentTarget.open && !loaded && !busy) void load() }}>
    <summary className="cursor-pointer text-sm font-medium">CloudTrail collection settings</summary>
    <p className="mt-2 text-sm text-muted-foreground">Optional. Configure an S3 trail source for data events or additional regions for management events. The project wallet reader needs access to the configured sources.</p>
    {loaded && <form className="mt-3 space-y-3" onSubmit={event => void save(event)}>
      <label className="block text-sm">Additional regions, comma separated<input className={input} value={settings.regions} onChange={event => setSettings({ ...settings, regions: event.target.value })} /></label>
      <label className="block text-sm">CloudTrail S3 bucket<input className={input} value={settings.trail_bucket} onChange={event => setSettings({ ...settings, trail_bucket: event.target.value })} /></label>
      <label className="block text-sm">CloudTrail S3 prefix<input className={input} value={settings.trail_prefix} onChange={event => setSettings({ ...settings, trail_prefix: event.target.value })} /></label>
      <p className="text-xs text-muted-foreground">Enter both S3 fields, or leave both empty. A narrow prefix limits the files scanned.</p>
      <Button type="submit" size="sm" disabled={busy}>Save settings</Button>
    </form>}
    {error && <p role="alert" className="mt-2 text-sm text-destructive">{error} {!loaded && <button className="underline" onClick={() => void load()} disabled={busy}>Try again</button>}</p>}
    {notice && <p role="status" className="mt-2 text-sm">{notice}</p>}
  </details>
}
