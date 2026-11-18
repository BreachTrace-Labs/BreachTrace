import { useState } from 'react'
import { realClient, USE_MOCK } from '@/api/client'
import { Button } from '@/components/ui/button'

type Result = { events: { id: string; timestamp: string; source_ip: string | null; resource: string | null; outcome: string; key_match: 'matched' | 'different_key' | 'unavailable' }[]; range_start: string; range_end: string; truncated: boolean; key_comparison: string }

export default function AzureSignIns({ incidentId, canManage, hasApplication, exposureStart, exposureEnd }: { incidentId: string; canManage: boolean; hasApplication: boolean; exposureStart: string; exposureEnd: string | null }) {
  const [keyId, setKeyId] = useState(''); const [busy, setBusy] = useState(false); const [result, setResult] = useState<Result | null>(null); const [error, setError] = useState('')
  const matchedInWindow = result?.events.filter(item => item.key_match === 'matched' && Date.parse(item.timestamp) >= Date.parse(exposureStart) && (!exposureEnd || Date.parse(item.timestamp) <= Date.parse(exposureEnd))) ?? []
  if (USE_MOCK || !canManage) return null
  async function collect(event: React.FormEvent) {
    event.preventDefault(); setBusy(true); setError(''); setResult(null)
    try { const { data } = await realClient.post<Result>(`/incidents/${incidentId}/azure-signins`, { credential_key_id: keyId.trim() || null }, { timeout: 100_000 }); setResult(data) }
    catch (err) { const detail = (err as { response?: { data?: { detail?: unknown } } }).response?.data?.detail; setError(typeof detail === 'string' ? detail : 'Could not retrieve sign-in evidence.') }
    finally { setBusy(false) }
  }
  return <section className="rounded-lg border bg-card p-5 space-y-3"><h2 className="font-semibold">Azure sign-in evidence</h2><p className="text-sm text-muted-foreground">Query Microsoft Graph for recent service-principal sign-ins using this project’s Azure reader. This is separate from Azure Activity Log and does not establish which credential caused subsequent resource operations.</p>
    {!hasApplication ? <p className="text-sm text-muted-foreground">Associate the Azure application ID with this incident before querying sign-ins.</p> : <form className="space-y-3" onSubmit={e => void collect(e)}><label className="block text-sm">Credential key ID (optional)<input className="mt-1 w-full rounded border bg-background p-2 font-mono" value={keyId} onChange={e => setKeyId(e.target.value)} placeholder="00000000-0000-0000-0000-000000000000" pattern="[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}" /></label><p className="text-xs text-muted-foreground">Only enter the key ID if you have independently identified it for this incident. Do not enter the client secret. The ID is used for this query and is not saved.</p><Button type="submit" variant="outline" loading={busy}>Retrieve sign-in evidence</Button></form>}
    <p className="text-xs text-muted-foreground">Requires Microsoft Graph AuditLog.Read.All application permission and admin consent, plus a supported Entra license. This uses the beta API; retention and provider coverage apply.</p>
    {error && <p role="alert" className="text-sm text-red-500">{error}</p>}
    {result && <div className="space-y-3" role="status">{result.key_comparison === 'operator_reported' && <p className="text-sm"><strong>{matchedInWindow.length} matching key sign-in{matchedInWindow.length === 1 ? '' : 's'} after this commit</strong> in the queried exposure window. This identifies authentication evidence, not subsequent resource operations; missing logs or key IDs remain inconclusive.</p>}<p className="text-sm text-muted-foreground">Queried {new Date(result.range_start).toLocaleString()} to {new Date(result.range_end).toLocaleString()}. Results are temporary and are not added to the incident timeline.{result.truncated ? ' The page limit was reached; results are incomplete.' : ''}</p>{result.events.length === 0 ? <p className="text-sm">No matching sign-ins returned. This does not prove that no activity occurred.</p> : <ul className="space-y-3">{result.events.map((item, index) => <li className="border-t pt-3 text-sm" key={`${item.id}-${index}`}><strong>{new Date(item.timestamp).toLocaleString()} · {item.outcome}</strong><p>{item.resource ?? 'Resource not reported'} · IP: {item.source_ip ?? 'Not reported'}</p><p className="text-muted-foreground">{item.key_match === 'matched' ? 'Matches the key ID supplied for this query' : item.key_match === 'different_key' ? 'Different credential key ID' : 'Key comparison unavailable'}</p></li>)}</ul>}</div>}
  </section>
}
