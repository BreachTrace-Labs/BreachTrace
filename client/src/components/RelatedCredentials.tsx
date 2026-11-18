import { useState } from 'react'
import { Link } from 'react-router-dom'
import { GitCommitHorizontal, ChevronDown } from 'lucide-react'
import client from '@/api/client'

type RelatedItem = { incident_id: string; credential_type: string; credential_hint: string; status: string; forensic_tier: number; dismissed: boolean }
type RelatedResponse = { commit_available: boolean; total: number; offset: number; items: RelatedItem[] }

export default function RelatedCredentials({ incidentId }: { incidentId: string }) {
  const [data, setData] = useState<RelatedResponse | null>(null)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState('')
  const load = async (offset = 0) => {
    setLoading(true); setError('')
    try { const response = await client.get<RelatedResponse>(`/incidents/${incidentId}/related-credentials`, { params: { offset } }); setData(response.data) }
    catch { setError('Could not load related credentials. Try again.') }
    finally { setLoading(false) }
  }
  return <details className="related-credentials" onToggle={event => { if (event.currentTarget.open && !data && !loading && !error) void load() }}><summary><span><GitCommitHorizontal size={17}/> Other credentials in this commit</span><ChevronDown size={16}/></summary><div className="related-credentials-body"><p>Other recorded incidents from the same commit in this project.</p>
    {loading ? <p role="status">Loading related credentials…</p> : error ? <p role="alert">{error} <button type="button" onClick={() => void load(data?.offset ?? 0)}>Retry</button></p> : data && !data.commit_available ? <p>A commit identifier is unavailable for this incident.</p> : data && data.total === 0 ? <p>No other recorded credentials were found for this commit.</p> : data && <><ul>{data.items.map(item => <li key={item.incident_id}><Link to={`/incidents/${item.incident_id}`}><span><strong>{item.credential_type.replace(/_/g, ' ')}</strong><code>{item.credential_hint}</code></span><span>{item.dismissed ? 'Dismissed' : item.forensic_tier === 2 ? 'Detection only' : item.status.replace(/_/g, ' ')} →</span></Link></li>)}</ul>{data.total > 25 && <div className="related-credentials-pagination"><button type="button" disabled={data.offset === 0} onClick={() => void load(Math.max(0, data.offset - 25))}>Previous</button><span>{data.offset + 1}–{data.offset + data.items.length} of {data.total}</span><button type="button" disabled={data.offset + data.items.length >= data.total} onClick={() => void load(data.offset + 25)}>Next</button></div>}</>}
  </div></details>
}
