import { BrandLogo } from '@/components/BrandLogo'
import { useEffect, useState } from 'react'
import { Link, Navigate } from 'react-router-dom'
import { realClient } from '@/api/client'
import { useAuth } from '@/context/AuthContext'
import { useProjects, type Project } from '@/context/ProjectContext'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { CodeBlock } from '@/components/ui/code-block'
import ProjectWallet from '@/components/ProjectWallet'
import './auth.css'

export default function Onboarding() {
  const { user, loading } = useAuth(); const { refresh, select } = useProjects()
  const [step, setStep] = useState(1); const [name, setName] = useState(''); const [repo, setRepo] = useState(''); const [project, setProject] = useState<Project | null>(null)
  const [url, setUrl] = useState(''); const [hookId, setHookId] = useState<number | null>(null); const [busy, setBusy] = useState(false); const [error, setError] = useState('')
  useEffect(() => { if (user && !user.must_change_password && user.role !== 'developer') realClient.get<{ webhook_url: string }>('/webhook/info').then(({ data }) => setUrl(data.webhook_url)).catch(() => {}) }, [user])
  if (loading) return <main className="ui-session-loading">Checking session…</main>
  if (!user) return <Navigate to="/login" state={{ from: '/onboarding' }} replace />
  if (user.must_change_password) return <Navigate to="/change-password" replace />
  if (user.role === 'developer') return <Navigate to="/dashboard" replace />
  const match = /^https:\/\/github\.com\/([A-Za-z0-9][A-Za-z0-9-]{0,38})\/([A-Za-z0-9_.-]+)\/?$/.exec(repo.trim())
  function detail(err: unknown, fallback: string) { const value = (err as { response?: { data?: { detail?: unknown } } }).response?.data?.detail; return typeof value === 'string' ? value : fallback }
  return <main className="setup-page"><section className="setup-card onboarding-card"><Link to="/" className="auth-wordmark" aria-label="BreachTrace home"><BrandLogo /></Link><p className="onboarding-progress">Step {step} of 5</p>
    {step === 1 && <div className="setup-form"><h1>Welcome to BreachTrace, {user.full_name.split(' ')[0]}</h1><p>Connect your first repository to start monitoring future pushes.</p><ul className="onboarding-list"><li>Create a project for your repository</li><li>Register a GitHub webhook</li><li>Optionally connect a provider for activity collection</li></ul><Button onClick={() => setStep(2)}>Get started →</Button></div>}
    {step === 2 && <form className="setup-form" onSubmit={async e => { e.preventDefault(); setError(''); if (!name.trim() || !match) { setError('Enter a project name and a GitHub repository URL in the format shown.'); return } setBusy(true); try { const { data } = await realClient.post<Project>('/projects', { name: name.trim(), github_repo_url: repo.trim() }); setProject(data); await refresh(); select(data.id); setStep(3) } catch (err) { setError(detail(err, 'Could not create the project. Check the repository and try again.')) } finally { setBusy(false) } }}><h1>Name your first project</h1><p>A project represents one GitHub repository you want to monitor.</p><Input label="Project name" value={name} onChange={e => setName(e.target.value)} required maxLength={120}/><Input label="GitHub repository URL" type="url" value={repo} onChange={e => setRepo(e.target.value)} required hint={match ? `${match[1]}/${match[2]} ✓` : 'Use https://github.com/owner/repository'}/>{error && <p className="auth-error" role="alert">{error}</p>}<Button loading={busy}>Create project →</Button></form>}
    {step === 3 && <div className="setup-form"><h1>Connect GitHub</h1><p>Register a push webhook using the GitHub token configured on the server. It needs repository webhook administration access.</p><Input label="Public HTTPS webhook URL" value={url} onChange={e => setUrl(e.target.value)} hint="The URL must be reachable by GitHub and end in /webhook/github."/><CodeBlock value={url}/>{hookId !== null && <p role="status">Webhook registered ✓ (ID {hookId})</p>}{error && <p className="auth-error" role="alert">{error}</p>}<div className="setup-actions"><Button variant="ghost" onClick={() => { setError(''); setStep(4) }}>Do this later</Button><Button loading={busy} onClick={async () => { if (!project) return; setError(''); setBusy(true); try { const { data } = await realClient.post<{webhook_id: number}>('/webhook/register', { project_id: project.id, webhook_url: url }); setHookId(data.webhook_id); await refresh() } catch (err) { setError(detail(err, 'Could not register the webhook. Check the URL and server configuration.')) } finally { setBusy(false) } }}>{hookId === null ? 'Register webhook' : 'Register again'}</Button>{hookId !== null && <Button onClick={() => setStep(4)}>Continue →</Button>}</div></div>}
    {step === 4 && project && <div className="setup-form"><h1>Connect a provider</h1><p>Provider connections are optional. They let BreachTrace collect available activity when a supported credential is detected.</p><ProjectWallet projectId={project.id} projectName={project.name}/><Button onClick={() => setStep(5)}>Continue →</Button></div>}
    {step === 5 && <div className="setup-done"><span className="setup-check">✓</span><h1>Your project is ready</h1><p>{project?.name} · {project?.github_repo_full_name}</p><p>Webhook: {hookId !== null ? 'registered' : 'not registered yet'}. Provider connections can be managed in Admin.</p><Link to="/dashboard" className="setup-link">Go to Dashboard →</Link></div>}
    {step < 2 && <Link to="/dashboard" className="onboarding-skip" onClick={() => sessionStorage.setItem(`bt_onboarding_skipped_${user.id}`, 'true')}>Skip for now →</Link>}
  </section></main>
}
