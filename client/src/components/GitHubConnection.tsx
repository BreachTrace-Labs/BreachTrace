import { useEffect, useState } from 'react'
import { realClient } from '@/api/client'
import { Button } from '@/components/ui/button'

type Status = { configured: boolean; updated_at: string | null }
export default function GitHubConnection({ projectId, onSaved }: { projectId: string; onSaved: (configured: boolean) => void }) {
  const [status, setStatus] = useState<Status | null>(null)
  const [token, setToken] = useState(''); const [busy, setBusy] = useState(false); const [error, setError] = useState('')
  useEffect(() => {
    let active = true
    realClient.get<Status>(`/projects/${projectId}/github-connection`).then(({data}) => { if (active) { setStatus(data); onSaved(data.configured) } }).catch(() => { if (active) setError('Could not load the GitHub connection.') })
    return () => { active = false }
  }, [projectId, onSaved])
  async function save(event: React.FormEvent) {
    event.preventDefault(); setBusy(true); setError('')
    try { const {data} = await realClient.put<Status>(`/projects/${projectId}/github-connection`, {token: token.trim()}); setStatus(data); setToken(''); onSaved(true) }
    catch (err) { const detail = (err as {response?: {data?: {detail?: unknown}}}).response?.data?.detail; setError(typeof detail === 'string' ? detail : 'Could not save the connection.') } finally { setBusy(false) }
  }
  async function remove() {
    setBusy(true); setError('')
    try { await realClient.delete(`/projects/${projectId}/github-connection`); setStatus({configured:false,updated_at:null}); setToken(''); onSaved(false) }
    catch { setError('Could not remove the connection.') } finally { setBusy(false) }
  }
  return <div className="space-y-3 rounded border p-4"><h3 className="text-sm font-semibold">Project GitHub connection</h3><p className="text-sm text-muted-foreground">Save a personal access token here. It is encrypted, shared only with this project’s backend operations, and cannot be retrieved after saving.</p><p className="text-sm" role="status">{status?.configured ? 'Token saved. GitHub checks its permissions when you register or scan.' : status ? 'No token saved for this project.' : 'Loading connection…'}</p><form onSubmit={event => void save(event)} className="space-y-3"><label className="block text-sm">{status?.configured ? 'Replacement GitHub token' : 'GitHub personal access token'}<input type="password" required minLength={20} maxLength={300} autoComplete="off" value={token} onChange={event => setToken(event.target.value)} className="mt-1 block w-full rounded border bg-transparent p-2" /></label><p className="text-xs text-muted-foreground">Select this repository on a fine-grained token. Grant Contents: read for commit diffs and private scans; add Webhooks: read and write for automatic registration. GitHub sign-in permissions are separate.</p><div className="flex gap-2"><Button type="submit" loading={busy}>{status?.configured ? 'Replace token' : 'Save token'}</Button>{status?.configured && <Button type="button" variant="outline" disabled={busy} onClick={() => { if (window.confirm('Remove this project’s GitHub token? Private scans and commit reads will stop until another token is saved.')) void remove() }}>Remove token</Button>}</div></form>{error && <p className="text-sm text-red-500" role="alert">{error}</p>}</div>
}
