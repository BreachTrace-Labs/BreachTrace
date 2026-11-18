import { useCallback, useEffect, useState } from 'react'
import { realClient } from '@/api/client'
import { Button } from '@/components/ui/button'
import { SlideOver, Modal } from '@/components/ui/overlay'
import { ProviderIcon } from '@/components/ui/provider-icon'
import { Badge } from '@/components/ui/badge'
import { useAuth } from '@/context/AuthContext'
import './project-management.css'

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
  const { user } = useAuth(); const canManage = user?.role === 'org_admin' || user?.role === 'security_lead'
  const [open, setOpen] = useState(false); const [remove, setRemove] = useState<Entry | null>(null); const [loading, setLoading] = useState(true)
  const [entries, setEntries] = useState<Entry[]>([]); const [provider, setProvider] = useState<Provider>('stripe')
  const [twilioAuth, setTwilioAuth] = useState<'api_key' | 'auth_token'>('api_key')
  const [credentials, setCredentials] = useState<Record<string, string>>({}); const [label, setLabel] = useState(''); const [error, setError] = useState(''); const [notice, setNotice] = useState(''); const [busy, setBusy] = useState(false)
  const availableProviders = (Object.keys(fields) as Provider[]).filter(value => canManage || !entries.some(entry => entry.provider === value))
  const load = useCallback(async () => { const {data} = await realClient.get<Entry[]>(`/projects/${projectId}/wallet`); setEntries(data) }, [projectId])
  useEffect(() => { let active = true; realClient.get<Entry[]>(`/projects/${projectId}/wallet`).then(({data}) => { if (active) { setEntries(data); setError(''); setLoading(false) } }).catch(() => { if (active) { setError('Could not load wallet connections.'); setLoading(false) } }); return () => { active = false } }, [projectId])
  useEffect(() => { if (!entries.some(entry => entry.verification_status === 'pending')) return; const timer = window.setInterval(() => { void load().catch(() => setError('Could not refresh verification status.')) }, 2000); return () => window.clearInterval(timer) }, [entries, load])
  async function save(event: React.FormEvent) {
    event.preventDefault(); setBusy(true); setError(''); setNotice('')
    try { await realClient.post(`/projects/${projectId}/wallet`, { provider, label: label.trim() || null, credentials }); setCredentials({}); setLabel(''); setNotice('Connection saved. Verification has started.'); setOpen(false); await load() }
    catch (err) { setError(detail(err)) } finally { setBusy(false) }
  }
  async function modify(entry: Entry, action: 'verify' | 'delete') {
    setError(''); setNotice(''); setBusy(true)
    try { if (action === 'delete') await realClient.delete(`/projects/${projectId}/wallet/${entry.id}`); else await realClient.post(`/projects/${projectId}/wallet/${entry.id}/verify`); await load(); setRemove(null); setNotice(action === 'delete' ? 'Connection removed.' : 'Verification has started.') }
    catch (err) { setError(detail(err)) } finally { setBusy(false) }
  }
  return <section className="pm-section" aria-label={`Credential wallet for ${projectName}`}><div className="pm-heading"><div><h2>Credential wallet · {projectName}</h2><p>Verified connections are used for activity collection in this project. Choose the account and environment that own the exposed credentials.</p>{!canManage && <p>Connections are shared with this project. Ask an administrator or security lead to replace, verify again, or remove one, or to refresh an existing incident.</p>}</div><Button disabled={!canManage && (loading || availableProviders.length === 0)} onClick={() => { setError(''); if (!canManage && !availableProviders.includes(provider)) setProvider(availableProviders[0]); setOpen(true) }}>Add connection</Button></div>
    {error && !open && !remove && <p role="alert" className="pm-error">{error}</p>}{notice && <p role="status">{notice}</p>}
    {loading ? <p role="status">Loading connections…</p> : entries.length === 0 ? <p>No connections configured. Add a provider reader to enable supported collection.</p> : <div className="pm-table-wrap"><table className="pm-table"><thead><tr><th>Provider</th><th>Label</th><th>Status</th><th>Last verified</th>{canManage && <th>Actions</th>}</tr></thead><tbody>{entries.map(entry => <tr key={entry.id}><td><ProviderIcon provider={entry.provider}/></td><td>{entry.label || '—'}</td><td title={entry.verification_error || undefined}><Badge variant={entry.verification_status === 'ok' ? 'success' : entry.verification_status === 'pending' ? 'warning' : 'critical'}>{entry.verification_status === 'ok' ? 'Verified' : entry.verification_status === 'pending' ? 'Verifying' : 'Error'}</Badge>{entry.verification_error && <p className="pm-error">{entry.verification_error}</p>}</td><td>{entry.last_verified_at ? new Date(entry.last_verified_at).toLocaleString() : '—'}</td>{canManage && <td><div className="pm-actions"><Button size="sm" variant="outline" disabled={busy || entry.verification_status === 'pending'} onClick={() => void modify(entry, 'verify')}>Verify</Button><Button size="sm" variant="outline" disabled={busy} onClick={() => { setError(''); setRemove(entry) }}>Remove</Button></div></td>}</tr>)}</tbody></table></div>}
    <SlideOver open={open} title="Add provider connection" onClose={() => { setOpen(false); setCredentials({}); setError('') }} preventClose={busy} footer={<><Button type="button" variant="ghost" disabled={busy} onClick={() => { setOpen(false); setCredentials({}); setError('') }}>Cancel</Button><Button type="submit" form="wallet-form" loading={busy}>Save and verify</Button></>}>
    <form id="wallet-form" className="space-y-3" onSubmit={event => void save(event)}><p className="pm-notice">Use credentials you are authorized to share with this project. Use restricted, read-only credentials where supported. Values are encrypted and cannot be retrieved after saving.</p>
      <label className="block text-sm">Provider<select className={`${input} mt-1`} value={provider} onChange={event => { setProvider(event.target.value as Provider); setCredentials({}); setError('') }}><option value="stripe" disabled={!availableProviders.includes('stripe')}>Stripe</option><option value="aws" disabled={!availableProviders.includes('aws')}>AWS</option><option value="gcp" disabled={!availableProviders.includes('gcp')}>Google Cloud</option><option value="azure" disabled={!availableProviders.includes('azure')}>Azure</option><option value="twilio" disabled={!availableProviders.includes('twilio')}>Twilio</option></select></label>
      <label className="block text-sm">Label (optional)<input className={`${input} mt-1`} maxLength={80} value={label} onChange={event => setLabel(event.target.value)} /></label>
      {provider === 'gcp' && <label className="block text-sm">Upload service account JSON<input className="block mt-1" type="file" accept="application/json,.json" onChange={event => { const file = event.target.files?.[0]; if (file) void file.text().then(text => setCredentials({service_account_json:text})).catch(() => setError('Could not read file.')) }} /></label>}
      {provider === 'twilio' && <label className="block text-sm">Authentication method<select className={`${input} mt-1`} value={twilioAuth} onChange={event => { setTwilioAuth(event.target.value as 'api_key' | 'auth_token'); setCredentials(current => ({account_sid: current.account_sid ?? ''})) }}><option value="api_key">API key SID and secret</option><option value="auth_token">Account Auth Token</option></select></label>}
      {[...fields[provider], ...(provider === 'twilio' ? twilioFields[twilioAuth] : [])].map(field => <label className="block text-sm" key={field.key}>{field.label}{field.key === 'service_account_json' ? <textarea className={`${input} mt-1 font-mono`} rows={4} required value={credentials[field.key] ?? ''} onChange={event => setCredentials({...credentials,[field.key]:event.target.value})} /> : <input className={`${input} mt-1`} required type={field.secret ? 'password' : 'text'} autoComplete="off" value={credentials[field.key] ?? ''} onChange={event => setCredentials({...credentials,[field.key]:event.target.value})} />}</label>)}
      <p className="text-sm text-muted-foreground">{verificationDescriptions[provider]}</p>
      {provider === 'twilio' && <p className="text-sm text-muted-foreground">Use the owning Account SID with an API key from the same account. Service and Environment SIDs identify Serverless resources and are not login credentials.</p>}
      {error && <p role="alert" className="pm-error">{error}</p>}
    </form>
    </SlideOver>
    <Modal open={!!remove} title="Remove connection" onClose={() => setRemove(null)} preventClose={busy} footer={<><Button variant="ghost" disabled={busy} onClick={() => setRemove(null)}>Cancel</Button><Button variant="danger" loading={busy} onClick={() => { if (remove) void modify(remove, 'delete') }}>Remove connection</Button></>}><p>This will stop future collection using this {remove?.provider.toUpperCase()} connection. Existing incident records are retained.</p>{error && <p role="alert" className="pm-error">{error}</p>}</Modal>
  </section>
}
