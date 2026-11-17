import { useCallback, useEffect, useState } from 'react'
import { realClient } from '@/api/client'
import { useAuth } from '@/context/AuthContext'
import { useProjects } from '@/context/ProjectContext'
import { Button } from '@/components/ui/button'
import ProjectWallet from '@/components/ProjectWallet'

type Member = { id: string; email: string; full_name: string; role: string; is_active?: boolean }
const input = 'border rounded p-2 bg-transparent w-full'
const reason = (error: unknown) => { const detail = (error as { response?: { data?: { detail?: unknown } } }).response?.data?.detail; return typeof detail === 'string' ? detail : 'The request failed. Check the entered information and try again.' }

export default function Admin() {
  const { user } = useAuth(); const { projects, selected, select, refresh, error: projectError } = useProjects()
  const [members, setMembers] = useState<Member[]>([]); const [eligible, setEligible] = useState<Member[]>([]); const [users, setUsers] = useState<Member[]>([])
  const [name, setName] = useState(''); const [repo, setRepo] = useState(''); const [memberId, setMemberId] = useState('')
  const [rename, setRename] = useState(''); const [orgName, setOrgName] = useState('')
  const [fullName, setFullName] = useState(''); const [email, setEmail] = useState(''); const [password, setPassword] = useState(''); const [role, setRole] = useState('developer'); const [error, setError] = useState(''); const [notice, setNotice] = useState('')
  const refreshTeam = useCallback(async () => {
    try {
      if (selected) { const [a,b] = await Promise.all([realClient.get<Member[]>(`/projects/${selected.id}/members`), realClient.get<Member[]>(`/projects/${selected.id}/eligible-members`)]); setMembers(a.data); setEligible(b.data) }
      else { setMembers([]); setEligible([]) }
      if (user?.role === 'org_admin') setUsers((await realClient.get<Member[]>('/org/users')).data)
    } catch (err) { setError(reason(err)) }
  }, [selected, user])
  useEffect(() => { void Promise.resolve().then(refreshTeam) }, [refreshTeam])
  useEffect(() => { void Promise.resolve().then(() => setRename(selected?.name ?? '')) }, [selected])
  useEffect(() => { if (user?.role === 'org_admin') void realClient.get<{ name: string }>('/org').then(({ data }) => setOrgName(data.name)).catch(() => setError('Could not load organisation details.')) }, [user?.role])
  async function action(fn: () => Promise<unknown>, success: string) { setError(''); setNotice(''); try { await fn(); await refresh(); await refreshTeam(); setNotice(success) } catch (err) { setError(reason(err)) } }
  if (user?.role === 'developer') return <div className="space-y-4"><h1 className="text-xl font-bold">Projects</h1>{projects.length ? projects.map(p => <div key={p.id} className="border p-3 rounded">{p.name} · {p.github_repo_full_name}</div>) : <p>You have not been added to a project yet.</p>}</div>
  return <div className="max-w-4xl space-y-8"><h1 className="text-xl font-bold">Organisation and projects</h1>
    {(error || projectError) && <p role="alert" className="text-red-500">{error || projectError}</p>}{notice && <p role="status">{notice}</p>}
    <section className="border rounded p-5 space-y-4"><h2 className="font-semibold">Projects</h2>
      {projects.map(p => <button key={p.id} type="button" onClick={() => select(p.id)} className={`block w-full text-left border rounded p-3 ${selected?.id === p.id ? 'border-primary' : ''}`}><strong>{p.name}</strong> · {p.github_repo_full_name} · {p.member_count} members</button>)}
      {!projects.length && <p className="text-sm text-muted-foreground">No projects yet.</p>}
      <form className="grid sm:grid-cols-2 gap-2" onSubmit={e => { e.preventDefault(); void action(async () => { await realClient.post('/projects', { name, github_repo_url: repo }); setName(''); setRepo('') }, 'Project created.') }}>
        <input className={input} required placeholder="Project name" aria-label="Project name" value={name} onChange={e => setName(e.target.value)} /><input className={input} required type="url" placeholder="https://github.com/owner/repository" aria-label="Repository URL" value={repo} onChange={e => setRepo(e.target.value)} /><Button className="sm:col-span-2" type="submit">Create project</Button>
      </form>
    </section>
    {selected && <ProjectWallet key={selected.id} projectId={selected.id} projectName={selected.name} />}
    {selected && <section className="border rounded p-5 space-y-4"><h2 className="font-semibold">Members · {selected.name}</h2>
      <form className="flex gap-2" onSubmit={e => { e.preventDefault(); void action(() => realClient.put(`/projects/${selected.id}`, { name: rename }), 'Project renamed.') }}><input className={input} aria-label="Project name" required value={rename} onChange={e => setRename(e.target.value)} /><Button>Rename</Button></form>
      {members.map(m => <div key={m.id} className="flex justify-between gap-3 items-center text-sm"><span>{m.full_name} · {m.email} · {m.role}</span><Button size="sm" variant="outline" onClick={() => { if (window.confirm(`Remove ${m.full_name} from this project?`)) void action(() => realClient.delete(`/projects/${selected.id}/members/${m.id}`), 'Member removed.') }}>Remove</Button></div>)}
      <form className="flex gap-2" onSubmit={e => { e.preventDefault(); if (memberId) void action(() => realClient.post(`/projects/${selected.id}/members`, { user_id: memberId }), 'Member added.') }}><select aria-label="Add member" className={input} value={memberId} onChange={e => setMemberId(e.target.value)} required><option value="">Select a team member</option>{eligible.filter(m => !members.some(x => x.id === m.id)).map(m => <option value={m.id} key={m.id}>{m.full_name} · {m.email}</option>)}</select><Button>Add member</Button></form>
      {user?.role === 'org_admin' && <Button variant="outline" onClick={() => { if (window.confirm(`Delete project ${selected.name}? Existing incidents are retained.`)) void action(() => realClient.delete(`/projects/${selected.id}`), 'Project deleted.') }}>Delete project</Button>}
    </section>}
    {user?.role === 'org_admin' && <section className="border rounded p-5 space-y-4"><h2 className="font-semibold">Team</h2>
      <form className="flex gap-2" onSubmit={e => { e.preventDefault(); void action(() => realClient.put('/org', { name: orgName }), 'Organisation name updated.') }}><input className={input} aria-label="Organisation name" required value={orgName} onChange={e => setOrgName(e.target.value)} /><Button>Save organisation name</Button></form>
      {users.map(u => <div key={u.id} className="flex flex-wrap gap-3 justify-between items-center text-sm"><span>{u.full_name} · {u.email} · {u.role}{u.is_active === false ? ' · inactive' : ''}</span>{u.role !== 'org_admin' && <div className="flex gap-2"><select className="border rounded p-1 bg-transparent" aria-label={`Role for ${u.full_name}`} value={u.role} onChange={e => void action(() => realClient.put(`/org/users/${u.id}`, { role: e.target.value }), 'Role updated.')}><option value="developer">Developer</option><option value="security_lead">Security lead</option></select><Button size="sm" variant="outline" onClick={() => void action(() => realClient.put(`/org/users/${u.id}`, { is_active: !u.is_active }), u.is_active ? 'User deactivated.' : 'User reactivated.')}>{u.is_active ? 'Deactivate' : 'Reactivate'}</Button></div>}</div>)}
      <form className="grid sm:grid-cols-2 gap-2" onSubmit={e => { e.preventDefault(); void action(async () => { await realClient.post('/org/users/invite', { email, full_name: fullName, role, temporary_password: password }); setFullName(''); setEmail(''); setPassword('') }, 'User created. Share the temporary password securely; email delivery is not configured yet.') }}>
        <input className={input} required placeholder="Full name" aria-label="Full name" value={fullName} onChange={e => setFullName(e.target.value)} /><input className={input} type="email" required placeholder="Email" aria-label="Email" value={email} onChange={e => setEmail(e.target.value)} /><select className={input} aria-label="Role" value={role} onChange={e => setRole(e.target.value)}><option value="developer">Developer</option><option value="security_lead">Security lead</option></select><input className={input} type="password" minLength={10} required placeholder="Temporary password" aria-label="Temporary password" value={password} onChange={e => setPassword(e.target.value)} /><Button className="sm:col-span-2">Create user</Button>
      </form>
    </section>}
  </div>
}
