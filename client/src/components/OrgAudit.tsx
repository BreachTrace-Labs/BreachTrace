import { useEffect, useRef, useState } from 'react'
import { realClient } from '@/api/client'
import { useProjects } from '@/context/ProjectContext'
import { Button } from '@/components/ui/button'
import './project-management.css'

type Entry = { id: string; actor_name: string | null; project_id: string | null; action: string; created_at: string; detail: Record<string, unknown> | null }
const pageSize = 50
export default function OrgAudit({ users }: { users: { id: string; full_name: string; email: string }[] }) {
  const { projects } = useProjects(); const [entries, setEntries] = useState<Entry[]>([]); const [action, setAction] = useState(''); const [actor, setActor] = useState(''); const [project, setProject] = useState(''); const [from, setFrom] = useState(''); const [to, setTo] = useState(''); const [error, setError] = useState(''); const [loading, setLoading] = useState(true); const [hasMore, setHasMore] = useState(false); const sequence = useRef(0)
  useEffect(() => {
    const requests = sequence; const current = ++requests.current
    async function load() { setLoading(true); setError(''); try { const {data} = await realClient.get<Entry[]>('/org/audit', { params: { limit: pageSize, offset: 0, action: action || undefined, user_id: actor || undefined, project_id: project || undefined, date_from: from ? new Date(`${from}T00:00:00`).toISOString() : undefined, date_to: to ? new Date(`${to}T23:59:59.999`).toISOString() : undefined } }); if (requests.current === current) { setEntries(data); setHasMore(data.length === pageSize) } } catch { if (requests.current === current) { setEntries([]); setError('Could not load the audit log.') } } finally { if (requests.current === current) setLoading(false) } }
    void load(); return () => { requests.current++ }
  }, [action, actor, project, from, to])
  async function more() { const current = ++sequence.current; setLoading(true); setError(''); try { const {data} = await realClient.get<Entry[]>('/org/audit', { params: { limit: pageSize, offset: entries.length, action: action || undefined, user_id: actor || undefined, project_id: project || undefined, date_from: from ? new Date(`${from}T00:00:00`).toISOString() : undefined, date_to: to ? new Date(`${to}T23:59:59.999`).toISOString() : undefined } }); if (sequence.current === current) { setEntries(previous => [...previous, ...data.filter(item => !previous.some(old => old.id === item.id))]); setHasMore(data.length === pageSize) } } catch { if (sequence.current === current) setError('Could not load more audit entries.') } finally { if (sequence.current === current) setLoading(false) } }
  const input = 'border rounded p-2 bg-transparent text-sm'
  return <section className="pm-section"><div className="pm-heading"><div><h2>Organisation audit log</h2><p>Review actions recorded across the organisation.</p></div></div>
    <div className="flex flex-wrap gap-2"><input className={input} aria-label="Filter audit action" placeholder="Action, e.g. incident.dismissed" value={action} onChange={e => setAction(e.target.value)} /><select className={input} aria-label="Filter actor" value={actor} onChange={e => setActor(e.target.value)}><option value="">All users</option>{users.map(item => <option key={item.id} value={item.id}>{item.full_name} · {item.email}</option>)}</select><select className={input} aria-label="Filter project" value={project} onChange={e => setProject(e.target.value)}><option value="">All projects</option>{projects.map(item => <option key={item.id} value={item.id}>{item.name}</option>)}</select><label className="text-xs">From <input className={input} type="date" value={from} onChange={e => setFrom(e.target.value)} /></label><label className="text-xs">To <input className={input} type="date" value={to} onChange={e => setTo(e.target.value)} /></label></div>
    {error && <p role="alert" className="pm-error">{error}</p>}
    {entries.length ? <div className="pm-table-wrap"><table className="pm-table"><thead><tr><th>Time</th><th>Actor</th><th>Action</th><th>Project</th><th>Detail</th></tr></thead><tbody>{entries.map(entry => <tr key={entry.id}><td>{new Date(entry.created_at).toLocaleString()}</td><td>{entry.actor_name ?? 'System'}</td><td><code>{entry.action}</code></td><td>{projects.find(p => p.id === entry.project_id)?.name ?? (entry.project_id ? 'Archived project' : '—')}</td><td className="break-all">{entry.detail ? JSON.stringify(entry.detail) : '—'}</td></tr>)}</tbody></table></div> : !loading && !error ? <p>No audit entries match these filters.</p> : null}
    {loading && <p role="status">Loading audit entries…</p>}{hasMore && <div><Button size="sm" variant="outline" loading={loading} onClick={() => void more()}>Load more</Button></div>}
  </section>
}
