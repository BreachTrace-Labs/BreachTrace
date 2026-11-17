import { useCallback, useEffect, useState } from 'react'
import { realClient } from '@/api/client'
import { useProjects } from '@/context/ProjectContext'
import { Button } from '@/components/ui/button'

type Entry = { id: string; actor_user_id: string | null; actor_name: string | null; project_id: string | null; incident_id: string | null; action: string; created_at: string; detail: Record<string, unknown> | null }
const pageSize = 25
export default function OrgAudit({ users }: { users: { id: string; full_name: string; email: string }[] }) {
  const { projects } = useProjects()
  const [entries, setEntries] = useState<Entry[]>([]); const [action, setAction] = useState(''); const [actor, setActor] = useState(''); const [project, setProject] = useState(''); const [from, setFrom] = useState(''); const [to, setTo] = useState(''); const [offset, setOffset] = useState(0); const [error, setError] = useState('')
  const load = useCallback(async () => {
    try {
      const {data} = await realClient.get<Entry[]>('/org/audit', { params: { limit:pageSize, offset, action:action || undefined, user_id:actor || undefined, project_id:project || undefined, date_from:from ? new Date(`${from}T00:00:00`).toISOString() : undefined, date_to:to ? new Date(`${to}T23:59:59.999`).toISOString() : undefined } })
      setEntries(data); setError('')
    } catch { setError('Could not load the audit log.') }
  }, [action, actor, project, from, to, offset])
  useEffect(() => { void Promise.resolve().then(load) }, [load])
  const input = 'border rounded p-2 bg-transparent text-sm'
  return <section className="rounded-lg border bg-card p-5 space-y-4"><h2 className="font-semibold">Organisation audit log</h2>
    <div className="flex flex-wrap gap-2"><input className={input} aria-label="Filter audit action" placeholder="Action, e.g. incident.dismissed" value={action} onChange={e => { setAction(e.target.value); setOffset(0) }} /><select className={input} aria-label="Filter actor" value={actor} onChange={e => { setActor(e.target.value); setOffset(0) }}><option value="">All users</option>{users.map(item => <option key={item.id} value={item.id}>{item.full_name} · {item.email}</option>)}</select><select className={input} aria-label="Filter project" value={project} onChange={e => { setProject(e.target.value); setOffset(0) }}><option value="">All projects</option>{projects.map(item => <option key={item.id} value={item.id}>{item.name}</option>)}</select><label className="text-xs">From <input className={input} type="date" value={from} onChange={e => { setFrom(e.target.value); setOffset(0) }} /></label><label className="text-xs">To <input className={input} type="date" value={to} onChange={e => { setTo(e.target.value); setOffset(0) }} /></label></div>
    {error && <p role="alert" className="text-red-500 text-sm">{error}</p>}
    {entries.length ? <div className="overflow-auto"><table className="w-full text-sm text-left"><thead><tr><th className="p-2">Time</th><th className="p-2">Actor</th><th className="p-2">Action</th><th className="p-2">Project</th><th className="p-2">Detail</th></tr></thead><tbody>{entries.map(entry => <tr key={entry.id} className="border-t"><td className="p-2 whitespace-nowrap">{new Date(entry.created_at).toLocaleString()}</td><td className="p-2">{entry.actor_name ?? 'System'}</td><td className="p-2">{entry.action}</td><td className="p-2">{projects.find(p => p.id===entry.project_id)?.name ?? (entry.project_id ? 'Archived project' : '—')}</td><td className="p-2 break-all">{entry.detail ? JSON.stringify(entry.detail) : '—'}</td></tr>)}</tbody></table></div> : <p className="text-sm">No matching audit entries.</p>}
    <div className="flex gap-2"><Button size="sm" variant="outline" disabled={offset===0} onClick={() => setOffset(Math.max(0,offset-pageSize))}>Previous</Button><Button size="sm" variant="outline" disabled={entries.length<pageSize} onClick={() => setOffset(offset+pageSize)}>Next</Button></div>
  </section>
}
