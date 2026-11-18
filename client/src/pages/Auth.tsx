import { useEffect, useState } from 'react'
import { Link, Navigate, useLocation, useNavigate } from 'react-router-dom'
import { Activity, ArrowUpRight, Fingerprint, Search } from 'lucide-react'
import { realClient, USE_MOCK } from '@/api/client'
import { useAuth } from '@/context/AuthContext'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { startGitHubLogin } from '@/lib/githubAuth'
import { BrandLogo } from '@/components/BrandLogo'
import './auth.css'

function AuthLogo({ mobile = false }: { mobile?: boolean }) {
  return <Link to="/" className={mobile ? 'auth-wordmark auth-mobile-brand' : 'auth-wordmark'} aria-label="BreachTrace home"><BrandLogo /></Link>
}

function message(error: unknown) {
  const response = (error as { response?: { status?: number; data?: { detail?: unknown } } }).response
  if (response?.status === 401) return 'Incorrect email or password.'
  if (response?.status === 429) return 'Too many sign-in attempts. Wait a minute and try again.'
  return typeof response?.data?.detail === 'string' ? response.data.detail : 'Could not complete the request. Check your details and backend connection.'
}
export function Login() {
  const { user, login, startPreview } = useAuth(); const navigate = useNavigate(); const location = useLocation()
  const [email, setEmail] = useState(''); const [password, setPassword] = useState(''); const [showPassword, setShowPassword] = useState(false); const [error, setError] = useState(''); const [busy, setBusy] = useState(false)
  const [needsSetup, setNeedsSetup] = useState(false); const [githubBusy, setGithubBusy] = useState(false)
  useEffect(() => { if (!USE_MOCK) realClient.get('/auth/setup-status').then(({ data }) => setNeedsSetup(data.setup_required)).catch(() => {}) }, [])
  const requested = (location.state as { from?: unknown } | null)?.from
  const destination = typeof requested === 'string' && requested.startsWith('/') && !requested.startsWith('//') ? requested : '/dashboard'
  if (user) return <Navigate to={user.must_change_password ? '/change-password' : destination} replace />
  if (needsSetup) return <Navigate to="/setup" replace />
  if (USE_MOCK) return <main className="setup-page"><section className="setup-card setup-form"><Link to="/" className="auth-back">← About BreachTrace</Link><h1>Preview session ended</h1><p>Open the preview again to explore synthetic incidents.</p><Button onClick={() => { startPreview(); navigate(destination, { replace: true }) }}>Open preview</Button></section></main>
  return <main className="auth-login"><section className="auth-brand"><AuthLogo /><div className="auth-brand-content"><span className="auth-brand-kicker"><span aria-hidden="true" /> CREDENTIAL EXPOSURE RESPONSE</span><h1>From leak to impact, in one place.</h1><p>Investigate exposed credentials with the evidence available to your team.</p><div className="auth-brand-steps"><div><span className="auth-step-icon"><Search size={18} aria-hidden="true" /></span><span><strong>Detect exposures</strong><small>Find credentials in your repositories</small></span></div><div><span className="auth-step-icon"><Fingerprint size={18} aria-hidden="true" /></span><span><strong>Investigate activity</strong><small>Follow available evidence and timelines</small></span></div><div><span className="auth-step-icon"><Activity size={18} aria-hidden="true" /></span><span><strong>Coordinate a response</strong><small>Bring investigation and remediation together</small></span></div></div></div><Link className="auth-brand-footer" to="/">Explore BreachTrace <ArrowUpRight size={15} aria-hidden="true" /></Link></section><section className="auth-login-panel"><div className="auth-form"><Link to="/" className="auth-back">← About BreachTrace</Link><AuthLogo mobile /><h1>Sign in</h1><p>Welcome back. Enter your account details to continue.</p><form onSubmit={async e => { e.preventDefault(); setBusy(true); setError(''); try { await login(email, password); navigate(destination, { replace: true }) } catch (err) { setError(message(err)) } finally { setBusy(false) } }}>
    <Input label="Email address" type="email" autoComplete="username" autoFocus required value={email} onChange={e => setEmail(e.target.value)} />
    <Input label="Password" type={showPassword ? 'text' : 'password'} autoComplete="current-password" required value={password} onChange={e => setPassword(e.target.value)} suffix={<button type="button" className="auth-password-toggle" onClick={() => setShowPassword(value => !value)} aria-label={showPassword ? 'Hide password' : 'Show password'}>{showPassword ? 'Hide' : 'Show'}</button>} />
    {error && <p role="alert" className="auth-error">{error}</p>}<Button className="auth-submit" loading={busy} type="submit">Sign in</Button>
  </form><div className="auth-github"><span>or</span><Button variant="outline" className="auth-submit" loading={githubBusy} disabled={busy} onClick={async () => { setError(''); setGithubBusy(true); try { await startGitHubLogin(destination) } catch (err) { setError(err instanceof Error ? err.message : 'Could not start GitHub sign-in.'); setGithubBusy(false) } }}>Continue with GitHub</Button><p>Requires an invitation and a matching verified GitHub email.</p></div><p>Contact your administrator if you need an account.</p></div></section></main>
}
function passwordStrength(password: string) {
  if (!password) return ''
  const variety = [/[a-z]/.test(password), /[A-Z]/.test(password), /[0-9]/.test(password), /[^a-zA-Z0-9]/.test(password)].filter(Boolean).length
  if (password.length < 10) return 'Weak'
  if (password.length < 12 || variety < 2) return 'Fair'
  if (password.length < 16 || variety < 3) return 'Good'
  return 'Strong'
}

export function Setup() {
  const [setup, setSetup] = useState<boolean | null>(null); const [step, setStep] = useState(1)
  const [org, setOrg] = useState(''); const [slug, setSlug] = useState(''); const [edited, setEdited] = useState(false)
  const [name, setName] = useState(''); const [email, setEmail] = useState(''); const [password, setPassword] = useState(''); const [confirm, setConfirm] = useState(''); const [showPassword, setShowPassword] = useState(false); const [error, setError] = useState(''); const [busy, setBusy] = useState(false)
  useEffect(() => { realClient.get('/auth/setup-status').then(({ data }) => setSetup(data.setup_required)).catch(() => setError('Cannot reach the backend. Check your connection and reload this page.')) }, [])
  if (setup === false) return <Navigate to="/login" replace />
  return <main className="setup-page auth-signup"><section className="setup-card"><AuthLogo /><ol className="setup-progress" aria-label="Setup progress">{['Organisation', 'Admin account', 'Done'].map((label, index) => <li key={label} aria-current={step === index + 1 ? 'step' : undefined}><span>{index + 1}</span>{label}</li>)}</ol>
    {setup === null ? <p role="status">{error || 'Checking setup…'}</p> : step === 3 ? <div className="setup-done"><span className="setup-check" aria-hidden="true">✓</span><h1>BreachTrace is ready</h1><p>Your organisation {org} has been created. Sign in to set up your first project.</p><Link to="/login" state={{ from: '/onboarding' }} className="setup-link">Sign in to continue →</Link></div> : <form className="setup-form" onSubmit={async e => { e.preventDefault(); setError(''); if (step === 1) { if (org.trim().length < 3) { setError('Organisation name must contain at least 3 characters.'); return } setStep(2); return } if (!name.trim()) { setError('Enter your full name.'); return } if (password !== confirm) { setError('Passwords do not match.'); return } setBusy(true); try { await realClient.post('/auth/register', { org_name: org.trim(), slug, admin_email: email, admin_password: password, admin_full_name: name.trim() }); setStep(3); setPassword(''); setConfirm('') } catch (err) { setError(message(err)) } finally { setBusy(false) } }}>
      <h1>{step === 1 ? 'Set up your organisation' : 'Create your admin account'}</h1><p>{step === 1 ? 'Start by naming your organisation.' : 'Use these details to sign in and manage your organisation.'}</p>
      {step === 1 ? <><Input label="Organisation name" required minLength={3} maxLength={120} value={org} onChange={e => { setOrg(e.target.value); if (!edited) setSlug(e.target.value.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, '').slice(0, 60)) }} /><Input label="Slug" required maxLength={60} pattern="[a-z0-9]+(-[a-z0-9]+)*" hint="This identifies your deployment. It cannot be changed later." value={slug} onChange={e => { setEdited(true); setSlug(e.target.value) }} /></> : <><Input label="Your full name" required maxLength={120} value={name} onChange={e => setName(e.target.value)} /><Input label="Email address" type="email" autoComplete="username" required value={email} onChange={e => setEmail(e.target.value)} /><Input label="Password" type={showPassword ? 'text' : 'password'} minLength={10} maxLength={72} autoComplete="new-password" required value={password} onChange={e => setPassword(e.target.value)} hint={password ? `Strength: ${passwordStrength(password)}. Use at least 10 characters.` : 'Use at least 10 characters.'} suffix={<button type="button" className="auth-password-toggle" onClick={() => setShowPassword(value => !value)}>{showPassword ? 'Hide' : 'Show'}</button>} /><Input label="Confirm password" type="password" autoComplete="new-password" required value={confirm} onChange={e => setConfirm(e.target.value)} hint={confirm && confirm === password ? 'Passwords match.' : undefined} /></>}
      {error && <p role="alert" className="auth-error">{error}</p>}<div className="setup-actions">{step === 2 && <Button type="button" variant="ghost" onClick={() => { setStep(1); setError('') }}>Back</Button>}<Button type="submit" loading={busy}>{step === 1 ? 'Continue' : 'Create organisation'}</Button></div>
    </form>}
  </section></main>
}
export function ChangePassword() {
  const { user, reload } = useAuth(); const navigate = useNavigate(); const [current, setCurrent] = useState(''); const [next, setNext] = useState(''); const [confirm, setConfirm] = useState(''); const [error, setError] = useState(''); const [busy, setBusy] = useState(false)
  if (!user) return <Navigate to="/login" replace />
  return <main className="setup-page"><section className="setup-card"><AuthLogo /><form className="setup-form password-form" onSubmit={async e => { e.preventDefault(); if (next !== confirm) { setError('Passwords do not match.'); return } setBusy(true); setError(''); try { await realClient.post('/auth/change-password', { current_password: current, new_password: next }); await reload(); navigate('/dashboard', { replace: true }) } catch (err) { setError(message(err)) } finally { setBusy(false) } }}>
    <h1>Set a new password</h1><p>Enter your temporary password and choose a permanent one before continuing.</p>
    <Input label="Current password" type="password" required autoComplete="current-password" value={current} onChange={e => setCurrent(e.target.value)} />
    <Input label="New password" type="password" minLength={10} maxLength={72} required autoComplete="new-password" value={next} onChange={e => setNext(e.target.value)} hint={next ? `Strength: ${passwordStrength(next)}. Use at least 10 characters.` : 'Use at least 10 characters.'} />
    <Input label="Confirm new password" type="password" required autoComplete="new-password" value={confirm} onChange={e => setConfirm(e.target.value)} />
    {error && <p role="alert" className="auth-error">{error}</p>}<Button loading={busy} type="submit">Set password and continue</Button>
  </form></section></main>
}
