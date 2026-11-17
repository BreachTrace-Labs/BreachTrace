import { useEffect, useState } from 'react'
import { Link, Navigate, useNavigate } from 'react-router-dom'
import { realClient } from '@/api/client'
import { useAuth } from '@/context/AuthContext'
import { Button } from '@/components/ui/button'

const input = 'block w-full border rounded p-2 bg-transparent mt-1'
function message(error: unknown) {
  const response = (error as { response?: { status?: number; data?: { detail?: unknown } } }).response
  if (response?.status === 401) return 'Invalid email or password.'
  if (response?.status === 429) return 'Too many sign-in attempts. Wait a minute and try again.'
  return typeof response?.data?.detail === 'string' ? response.data.detail : 'Could not complete the request. Check your details and backend connection.'
}
function Card({ title, children }: { title: string; children: React.ReactNode }) {
  return <main className="min-h-screen flex items-center justify-center p-6 bg-background text-foreground"><div className="w-full max-w-md space-y-5 border rounded p-6 bg-card"><p className="font-bold">BreachTrace</p><h1 className="text-xl font-bold">{title}</h1>{children}</div></main>
}
export function Login() {
  const { user, login } = useAuth(); const navigate = useNavigate()
  const [email, setEmail] = useState(''); const [password, setPassword] = useState(''); const [error, setError] = useState(''); const [busy, setBusy] = useState(false)
  const [needsSetup, setNeedsSetup] = useState(false)
  useEffect(() => { realClient.get('/auth/setup-status').then(({ data }) => setNeedsSetup(data.setup_required)).catch(() => {}) }, [])
  if (user) return <Navigate to={user.must_change_password ? '/change-password' : '/'} replace />
  if (needsSetup) return <Navigate to="/setup" replace />
  return <Card title="Sign in"><form className="space-y-4" onSubmit={async e => { e.preventDefault(); setBusy(true); setError(''); try { await login(email, password); navigate('/', { replace: true }) } catch (err) { setError(message(err)) } finally { setBusy(false) } }}>
    <label className="block">Email<input className={input} type="email" autoComplete="username" required value={email} onChange={e => setEmail(e.target.value)} /></label>
    <label className="block">Password<input className={input} type="password" autoComplete="current-password" required value={password} onChange={e => setPassword(e.target.value)} /></label>
    {error && <p role="alert" className="text-red-500 text-sm">{error}</p>}<Button disabled={busy} type="submit">{busy ? 'Signing in…' : 'Sign in'}</Button>
  </form><p className="text-sm text-muted-foreground">Contact your admin if you don’t have an account.</p></Card>
}
export function Setup() {
  const navigate = useNavigate(); const [setup, setSetup] = useState<boolean | null>(null)
  const [org, setOrg] = useState(''); const [slug, setSlug] = useState(''); const [edited, setEdited] = useState(false)
  const [name, setName] = useState(''); const [email, setEmail] = useState(''); const [password, setPassword] = useState(''); const [confirm, setConfirm] = useState(''); const [error, setError] = useState(''); const [busy, setBusy] = useState(false)
  useEffect(() => { realClient.get('/auth/setup-status').then(({ data }) => setSetup(data.setup_required)).catch(() => setError('Cannot reach the backend.')) }, [])
  if (setup === false) return <Navigate to="/login" replace />
  return <Card title="Set up your organisation">{setup === null ? <p role="status">{error || 'Checking setup…'}</p> : <form className="space-y-3" onSubmit={async e => { e.preventDefault(); if (password !== confirm) { setError('Passwords do not match.'); return } setBusy(true); setError(''); try { await realClient.post('/auth/register', { org_name: org, slug, admin_email: email, admin_password: password, admin_full_name: name }); navigate('/login', { replace: true }) } catch (err) { setError(message(err)) } finally { setBusy(false) } }}>
    <label className="block">Organisation name<input className={input} required value={org} onChange={e => { setOrg(e.target.value); if (!edited) setSlug(e.target.value.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, '')) }} /></label>
    <label className="block">Organisation slug<input className={input} required pattern="[a-z0-9]+(-[a-z0-9]+)*" value={slug} onChange={e => { setEdited(true); setSlug(e.target.value) }} /></label>
    <label className="block">Full name<input className={input} required value={name} onChange={e => setName(e.target.value)} /></label>
    <label className="block">Admin email<input className={input} type="email" autoComplete="username" required value={email} onChange={e => setEmail(e.target.value)} /></label>
    <label className="block">Password<input className={input} type="password" minLength={10} autoComplete="new-password" required value={password} onChange={e => setPassword(e.target.value)} /></label>
    <label className="block">Confirm password<input className={input} type="password" minLength={10} autoComplete="new-password" required value={confirm} onChange={e => setConfirm(e.target.value)} /></label>
    {error && <p role="alert" className="text-red-500 text-sm">{error}</p>}<Button disabled={busy}>Create organisation</Button>
  </form>}<Link to="/login" className="text-sm underline">Sign in</Link></Card>
}
export function ChangePassword() {
  const { user, reload } = useAuth(); const navigate = useNavigate(); const [current, setCurrent] = useState(''); const [next, setNext] = useState(''); const [confirm, setConfirm] = useState(''); const [error, setError] = useState(''); const [busy, setBusy] = useState(false)
  if (!user) return <Navigate to="/login" replace />
  return <Card title="Change password"><form className="space-y-4" onSubmit={async e => { e.preventDefault(); if (next !== confirm) { setError('Passwords do not match.'); return } setBusy(true); setError(''); try { await realClient.post('/auth/change-password', { current_password: current, new_password: next }); await reload(); navigate('/', { replace: true }) } catch (err) { setError(message(err)) } finally { setBusy(false) } }}>
    <label className="block">Current password<input className={input} type="password" required autoComplete="current-password" value={current} onChange={e => setCurrent(e.target.value)} /></label>
    <label className="block">New password<input className={input} type="password" minLength={10} required autoComplete="new-password" value={next} onChange={e => setNext(e.target.value)} /></label>
    <label className="block">Confirm new password<input className={input} type="password" minLength={10} required autoComplete="new-password" value={confirm} onChange={e => setConfirm(e.target.value)} /></label>
    {error && <p role="alert" className="text-red-500 text-sm">{error}</p>}<Button disabled={busy}>Change password</Button>
  </form></Card>
}
