import { useEffect, useRef, useState } from 'react'
import { Link, useNavigate } from 'react-router-dom'
import { useAuth } from '@/context/AuthContext'
import { consumeGitHubCallback } from '@/lib/githubAuth'
import { Spinner } from '@/components/ui/spinner'
import './auth.css'

export default function GitHubCallback() {
  const { githubLogin } = useAuth(); const navigate = useNavigate(); const started = useRef(false); const [error, setError] = useState('')
  useEffect(() => {
    if (started.current) return
    started.current = true
    const params = new URLSearchParams(window.location.search)
    window.history.replaceState(window.history.state, '', window.location.pathname)
    async function finish() {
      try {
        const {code, verifier, destination} = consumeGitHubCallback(params)
        const user = await githubLogin(code, verifier)
        navigate(user.must_change_password ? '/change-password' : destination, { replace: true })
      } catch (err) {
        const detail = (err as { response?: { data?: { detail?: unknown } } }).response?.data?.detail
        setError(typeof detail === 'string' ? detail : err instanceof Error ? err.message : 'GitHub sign-in failed. Please try again.')
      }
    }
    void finish()
  }, [githubLogin, navigate])
  return <main className="setup-page"><section className="setup-card setup-form"><h1>GitHub sign-in</h1>{error ? <><p role="alert" className="auth-error">{error}</p><Link to="/login" className="setup-link">Return to sign in</Link></> : <p role="status"><Spinner size="sm"/> Verifying your account…</p>}</section></main>
}
