import { useCallback, useEffect, useState } from 'react'
import { realClient } from '@/api/client'
import { Button } from '@/components/ui/button'

type Provider = 'aws' | 'gcp' | 'azure' | 'stripe' | 'twilio'
type Entry = { id: string; provider: Provider; label: string | null; verification_status: 'pending' | 'ok' | 'error'; verification_error: string | null; last_verified_at: string | null }
const fields: Record<Provider, { key: string; label: string; secret?: boolean }[]> = {
  aws: [{key:'access_key_id',label:'Access Key ID'},{key:'secret_access_key',label:'Secret Access Key',secret:true},{key:'region',label:'Region'}],
  gcp: [{key:'service_account_json',label:'Service account JSON',secret:true}],
  azure: [{key:'tenant_id',label:'Directory (tenant) ID'},{key:'client_id',label:'Application (client) ID'},{key:'client_secret',label:'Client secret value',secret:true},{key:'subscription_id',label:'Subscription ID'}],
  stripe: [{key:'api_key',label:'Secret or restricted API key',secret:true}],
  twilio: [{key:'account_sid',label:'Account SID (AC…)'}],
}
const twilioFields: Record<'api_key' | 'auth_token', { key: string; label: string; secret?: boolean }[]> = {
  api_key: [{key:'api_key_sid',label:'API Key SID (SK…)'},{key:'api_key_secret',label:'API Key Secret',secret:true}],
  auth_token: [{key:'auth_token',label:'Account Auth Token',secret:true}],
}
const verificationDescriptions: Record<Provider, string> = {
  aws: 'Verifies identity with STS. CloudTrail read permission is checked during collection.',
  gcp: 'Checks access to Cloud Audit Logs for the project in the service account JSON.',
  azure: 'Checks Activity Log read access for the subscription. Use the application’s appId and matching secret value, not the service principal object ID or secret key ID.',
  stripe: 'Checks Events read access. Use a restricted key where possible and match the account and test or live mode.',
  twilio: 'Checks access to Messages in this account. Calls and Monitor Events permissions are checked during collection.',
}
const input = 'min-w-0 w-full rounded-md border bg-transparent p-2 text-sm'
const detail = (err: unknown) => { const value = (err as { response?: { data?: { detail?: unknown } } }).response?.data?.detail; return typeof value === 'string' ? value : 'Unable to complete the request. Check your settings and try again.' }

export default function ProjectWallet({ projectId, projectName }: { projectId: string; projectName: string }) {
  const [entries, setEntries] = useState<Entry[]>([]); const [provider, setProvider] = useState<Provider>('stripe')
  const [twilioAuth, setTwilioAuth] = useState<'api_key' | 'auth_token'>('api_key')
  const [credentials, setCredentials] = useState<Record<string, string>>({}); const [label, setLabel] = useState(''); const [error, setError] = useState(''); const [notice, setNotice] = useState(''); const [busy, setBusy] = useState(false)
  const load = useCallback(async () => { const {data} = await realClient.get<Entry[]>(`/projects/${projectId}/wallet`); setEntries(data) }, [projectId])
  useEffect(() => { let active = true; realClient.get<Entry[]>(`/projects/${projectId}/wallet`).then(({data}) => { if (active) { setEntries(data); setError('') } }).catch(() => { if (active) setError('Could not load wallet connections.') }); return () => { active = false } }, [projectId])
  useEffect(() => { if (!entries.some(entry => entry.verification_status === 'pending')) return; const timer = window.setInterval(() => { void load().catch(() => setError('Could not refresh verification status.')) }, 2000); return () => window.clearInterval(timer) }, [entries, load])
  async function save(event: React.FormEvent) {
    event.preventDefault(); setBusy(true); setError(''); setNotice('')
    try { await realClient.post(`/projects/${projectId}/wallet`, { provider, label: label.trim() || null, credentials }); setCredentials({}); setLabel(''); setNotice('Connection saved. Verification has started.'); await load() }
    catch (err) { setError(detail(err)) } finally { setBusy(false) }
  }
  async function modify(entry: Entry, action: 'verify' | 'delete') {
    if (action === 'delete' && !window.confirm(`Remove the ${entry.provider.toUpperCase()} connection from ${projectName}?`)) return
    setError(''); setNotice(''); setBusy(true)
    try { if (action === 'delete') await realClient.delete(`/projects/${projectId}/wallet/${entry.id}`); else await realClient.post(`/projects/${projectId}/wallet/${entry.id}/verify`); await load(); setNotice(action === 'delete' ? 'Connection removed.' : 'Verification has started.') }
    catch (err) { setError(detail(err)) } finally { setBusy(false) }
  }
  return <section className="rounded-lg border bg-card p-5 space-y-4"><h2 className="font-semibold">Credential wallet · {projectName}</h2>
    <p className="text-sm text-muted-foreground">Credentials are encrypted at rest and cannot be displayed after saving. Use restricted, read-only credentials where supported. Verification checks a specific read operation.</p>
    <p className="text-sm text-muted-foreground">Verified connections are used to collect activity for this project. Choose the account and environment that own the exposed credentials.</p>
    {error && <p role="alert" className="text-red-500 text-sm">{error}</p>}{notice && <p role="status" className="text-sm">{notice}</p>}
    {entries.length === 0 && <p className="text-sm">No connections configured.</p>}
    {entries.map(entry => <div className="border rounded p-3 space-y-2" key={entry.id}><div className="flex flex-wrap items-center justify-between gap-2"><div><strong>{entry.provider.toUpperCase()}</strong>{entry.label ? ` · ${entry.label}` : ''}<span className="ml-2 text-sm">{entry.verification_status === 'ok' ? 'Verified' : entry.verification_status === 'pending' ? 'Verifying…' : 'Verification failed'}</span></div><div className="flex gap-2"><Button size="sm" variant="outline" disabled={busy || entry.verification_status === 'pending'} onClick={() => void modify(entry, 'verify')}>Verify</Button><Button size="sm" variant="outline" disabled={busy} onClick={() => void modify(entry, 'delete')}>Remove</Button></div></div>{entry.verification_error && <p className="text-sm text-red-500">{entry.verification_error}</p>}{entry.last_verified_at && <p className="text-xs text-muted-foreground">Last checked {new Date(entry.last_verified_at).toLocaleString()}</p>}</div>)}
    <form className="space-y-3" onSubmit={event => void save(event)}><h3 className="font-medium">Add or replace a connection</h3>
      <label className="block text-sm">Provider<select className={`${input} mt-1`} value={provider} onChange={event => { setProvider(event.target.value as Provider); setCredentials({}); setError('') }}><option value="stripe">Stripe</option><option value="aws">AWS</option><option value="gcp">Google Cloud</option><option value="azure">Azure</option><option value="twilio">Twilio</option></select></label>
      <label className="block text-sm">Label (optional)<input className={`${input} mt-1`} maxLength={80} value={label} onChange={event => setLabel(event.target.value)} /></label>
      {provider === 'gcp' && <label className="block text-sm">Upload service account JSON<input className="block mt-1" type="file" accept="application/json,.json" onChange={event => { const file = event.target.files?.[0]; if (file) void file.text().then(text => setCredentials({service_account_json:text})).catch(() => setError('Could not read file.')) }} /></label>}
      {provider === 'twilio' && <label className="block text-sm">Authentication method<select className={`${input} mt-1`} value={twilioAuth} onChange={event => { setTwilioAuth(event.target.value as 'api_key' | 'auth_token'); setCredentials(current => ({account_sid: current.account_sid ?? ''})) }}><option value="api_key">API key SID and secret</option><option value="auth_token">Account Auth Token</option></select></label>}
      {[...fields[provider], ...(provider === 'twilio' ? twilioFields[twilioAuth] : [])].map(field => <label className="block text-sm" key={field.key}>{field.label}{field.key === 'service_account_json' ? <textarea className={`${input} mt-1 font-mono`} rows={4} required value={credentials[field.key] ?? ''} onChange={event => setCredentials({...credentials,[field.key]:event.target.value})} /> : <input className={`${input} mt-1`} required type={field.secret ? 'password' : 'text'} autoComplete="off" value={credentials[field.key] ?? ''} onChange={event => setCredentials({...credentials,[field.key]:event.target.value})} />}</label>)}
      <p className="text-sm text-muted-foreground">{verificationDescriptions[provider]}</p>
      {provider === 'twilio' && <p className="text-sm text-muted-foreground">Use the owning Account SID with an API key from the same account. Service and Environment SIDs identify Serverless resources and are not login credentials.</p>}
      <Button disabled={busy}>{busy ? 'Saving…' : 'Save and verify'}</Button>
    </form>
  </section>
}
