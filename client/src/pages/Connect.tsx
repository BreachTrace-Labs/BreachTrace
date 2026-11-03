import { useEffect, useState } from 'react'
import { Link } from 'react-router-dom'
import {
  CheckCircle2,
  AlertCircle,
  Copy,
  Check,
  ExternalLink,
  Loader2,
  Webhook,
} from 'lucide-react'
import client from '@/api/client'
import { Button } from '@/components/ui/button'
import RepositoryScan from '@/components/RepositoryScan'

/* ─── types ────────────────────────────────────────────────────────── */

interface WebhookInfo {
  webhook_url: string
  secret_hint: string
  environment: string
}

interface RegisterResult {
  success: boolean
  already_existed: boolean
  webhook_id: number
  message: string
}

/* ─── small helpers ─────────────────────────────────────────────────── */

function CopyButton({ text }: { text: string }) {
  const [copied, setCopied] = useState(false)
  const [copyError, setCopyError] = useState(false)
  const copy = async () => {
    try {
      await navigator.clipboard.writeText(text)
      setCopied(true); setCopyError(false)
      setTimeout(() => setCopied(false), 2000)
    } catch { setCopyError(true) }
  }
  return (
    <button
      onClick={copy}
      className="p-1 rounded transition-colors hover:opacity-70"
      style={{ color: 'var(--color-muted-foreground)' }}
      title={copyError ? 'Copy failed; select and copy the text manually' : copied ? 'Copied' : 'Copy'}
      aria-label={copyError ? 'Copy failed' : copied ? 'Copied' : 'Copy to clipboard'}
    >
      {copied ? <Check size={13} strokeWidth={2.5} /> : <Copy size={13} strokeWidth={2} />}
    </button>
  )
}

function CodeBlock({ children }: { children: string }) {
  return (
    <div
      className="flex items-center justify-between px-3 py-2 rounded font-mono text-xs border"
      style={{
        backgroundColor: 'var(--color-background)',
        borderColor: 'var(--color-border)',
        color: 'var(--color-foreground)',
      }}
    >
      <span className="truncate">{children}</span>
      <CopyButton text={children} />
    </div>
  )
}

function Section({
  step,
  title,
  children,
}: {
  step: number
  title: string
  children: React.ReactNode
}) {
  return (
    <div
      className="border rounded p-6 space-y-4"
      style={{ backgroundColor: 'var(--color-card)', borderColor: 'var(--color-border)' }}
    >
      <div className="flex items-center gap-3">
        <span
          className="w-6 h-6 rounded-full flex items-center justify-center text-xs font-bold shrink-0"
          style={{
            backgroundColor: 'var(--color-foreground)',
            color: 'var(--color-background)',
          }}
        >
          {step}
        </span>
        <h2 className="text-sm font-semibold">{title}</h2>
      </div>
      {children}
    </div>
  )
}

/* ─── main component ─────────────────────────────────────────────────── */

const Connect: React.FC = () => {
  const [infoError, setInfoError] = useState(false)

  const [repoUrl, setRepoUrl] = useState('')
  const [webhookUrl, setWebhookUrl] = useState('http://localhost:8000/webhook/github')
  const [registering, setRegistering] = useState(false)
  const [result, setResult] = useState<RegisterResult | null>(null)
  const [registerError, setRegisterError] = useState<string | null>(null)
  const [scanOnConnect, setScanOnConnect] = useState(true)
  const [scanTrigger, setScanTrigger] = useState(0)

  // Fetch the webhook URL from the backend on mount to auto-fill the field
  useEffect(() => {
    client
      .get<WebhookInfo>('/webhook/info')
      .then(({ data }) => {
        setWebhookUrl(data.webhook_url)
      })
      .catch(() => setInfoError(true))
  }, [])

  const handleRegister = async () => {
    if (!repoUrl.trim()) return
    setRegistering(true)
    setResult(null)
    setRegisterError(null)
    try {
      const { data } = await client.post<RegisterResult>('/webhook/register', {
        repo_url: repoUrl.trim(),
        webhook_url: webhookUrl,
      })
      setResult(data)
      if (data.success && scanOnConnect) setScanTrigger(value => value + 1)
    } catch (err: unknown) {
      const msg =
        (err as { response?: { data?: { detail?: string } } })?.response?.data?.detail ??
        'Failed to register webhook. Check the backend logs.'
      setRegisterError(msg)
    } finally {
      setRegistering(false)
    }
  }

  return (
    <div className="space-y-8 max-w-2xl">
      {/* Page header */}
      <div>
        <h1 className="text-xl font-bold tracking-tight">Scan GitHub Repository</h1>
        <p className="mt-1 text-sm" style={{ color: 'var(--color-muted-foreground)' }}>
          Check existing files for credential leaks. Optionally connect a webhook for future pushes.
        </p>
      </div>

      <RepositoryScan repoUrl={repoUrl} onRepoUrlChange={url => {
        setRepoUrl(url); setResult(null); setRegisterError(null)
      }} trigger={scanTrigger} />

      <details className="space-y-6">
        <summary className="cursor-pointer font-semibold">Monitor future commits (optional)</summary>
        <label className="flex items-center gap-2 text-sm"><input type="checkbox" checked={scanOnConnect} onChange={e => setScanOnConnect(e.target.checked)} />Also scan the existing codebase after connecting</label>

      {/* Step 1 — Expose the backend (ngrok) */}
      <Section step={1} title="Expose the backend for webhook delivery">
        <p className="text-sm" style={{ color: 'var(--color-muted-foreground)' }}>
          GitHub must be able to reach your backend over HTTPS. Run ngrok in a separate terminal:
        </p>
        <CodeBlock>ngrok http 8000</CodeBlock>
        <p className="text-sm" style={{ color: 'var(--color-muted-foreground)' }}>
          Copy the <strong>Forwarding</strong> URL (e.g.{' '}
          <span className="font-mono text-xs">https://abc123.ngrok.io</span>) — you will use it in
          Step 2.
        </p>
        {infoError && (
          <div
            className="text-xs px-3 py-2 rounded border"
            style={{
              borderColor: 'var(--color-sev-critical)',
              backgroundColor: 'var(--color-background)',
              color: 'var(--color-sev-critical)',
            }}
          >
            Backend is not reachable — make sure uvicorn is running on port 8000.
          </div>
        )}
      </Section>

      {/* Step 2 — Register webhook */}
      <Section step={2} title="Register webhook on your GitHub repository">
        <p className="text-sm" style={{ color: 'var(--color-muted-foreground)' }}>
          Use the repository URL entered above. BreachTrace will register the webhook
          automatically using your configured GitHub token.
        </p>

        <div className="space-y-2">
          <label className="text-xs font-semibold uppercase tracking-wider" style={{ color: 'var(--color-muted-foreground)' }}>
            Repository URL
          </label>
          <div className="flex gap-2 items-center">
            <p className="text-sm break-all flex-1">{repoUrl.trim() || 'Enter a repository URL above to enable webhook registration.'}</p>
            <Button
              onClick={handleRegister}
              disabled={registering || !repoUrl.trim()}
              size="sm"
              className="gap-2 shrink-0"
            >
              {registering ? (
                <Loader2 size={13} strokeWidth={2} className="animate-spin" />
              ) : (
                <Webhook size={13} strokeWidth={2} />
              )}
              {registering ? 'Registering…' : 'Register Webhook'}
            </Button>
          </div>
        </div>

        {/* Editable webhook URL */}
        <div className="space-y-2">
          <label className="text-xs font-semibold uppercase tracking-wider" style={{ color: 'var(--color-muted-foreground)' }}>
            Webhook URL
          </label>
          <p className="text-xs" style={{ color: 'var(--color-muted-foreground)' }}>
            Replace <span className="font-mono">localhost:8000</span> with your ngrok URL if you need GitHub to reach a local server.
          </p>
          <div className="flex gap-2">
            <input
              type="text"
              value={webhookUrl}
              onChange={(e) => setWebhookUrl(e.target.value)}
              className="flex-1 px-3 py-2 text-xs font-mono border rounded outline-none"
              style={{
                backgroundColor: 'var(--color-background)',
                borderColor: 'var(--color-border)',
                color: 'var(--color-foreground)',
              }}
            />
            <CopyButton text={webhookUrl} />
          </div>
        </div>

        {/* Success state */}
        {result && (
          <div
            className="flex items-start gap-3 px-4 py-3 rounded border text-sm"
            style={{
              borderColor: 'var(--color-sev-low)',
              backgroundColor: 'var(--color-background)',
            }}
          >
            <CheckCircle2
              size={16}
              strokeWidth={2}
              className="shrink-0 mt-0.5"
              style={{ color: 'var(--color-sev-low)' }}
            />
            <div>
              <p className="font-semibold" style={{ color: 'var(--color-sev-low)' }}>
                {result.already_existed ? 'Webhook already active' : 'Webhook registered!'}
              </p>
              <p style={{ color: 'var(--color-muted-foreground)' }}>{result.message}</p>
              {!result.already_existed && (
                <p className="mt-1 font-mono text-xs" style={{ color: 'var(--color-muted-foreground)' }}>
                  Hook ID: {result.webhook_id}
                </p>
              )}
            </div>
          </div>
        )}

        {/* Error state */}
        {registerError && (
          <div
            className="flex items-start gap-3 px-4 py-3 rounded border text-sm"
            style={{
              borderColor: 'var(--color-sev-critical)',
              backgroundColor: 'var(--color-background)',
            }}
          >
            <AlertCircle
              size={16}
              strokeWidth={2}
              className="shrink-0 mt-0.5"
              style={{ color: 'var(--color-sev-critical)' }}
            />
            <div>
              <p className="font-semibold" style={{ color: 'var(--color-sev-critical)' }}>
                Registration failed
              </p>
              <p style={{ color: 'var(--color-muted-foreground)' }}>{registerError}</p>
            </div>
          </div>
        )}
      </Section>

      <Section step={3} title="Preview detection with synthetic incidents">
        <p className="text-sm text-muted-foreground">The local demo includes fabricated AI credentials detected as plaintext, encoded values and split strings. A demo detection does not prove real key validity or provider activity.</p>
        <Link to="/?platform=ai" className="inline-flex items-center gap-2 text-sm font-medium underline underline-offset-4">View AI detection examples <ExternalLink size={13} /></Link>
        <p className="text-xs text-muted-foreground">Webhook detections depend on delivery and API access. Cloud activity reconstruction also requires authorized provider logs. No fixed processing time is guaranteed.</p>
      </Section>

      {/* Manual fallback */}
      <Section step={4} title="Manual setup (if auto-register fails)">
        <p className="text-sm" style={{ color: 'var(--color-muted-foreground)' }}>
          If the GitHub token doesn't have admin access to the repo, add the webhook manually:
        </p>
        <ol className="space-y-2 text-sm" style={{ color: 'var(--color-muted-foreground)' }}>
          <li>1. Open your repo on GitHub → <strong>Settings → Webhooks → Add webhook</strong></li>
          <li>2. Payload URL:</li>
        </ol>
        <CodeBlock>{webhookUrl}</CodeBlock>
        <ol className="space-y-2 text-sm" style={{ color: 'var(--color-muted-foreground)' }} start={3}>
          <li>3. Content type: <strong>application/json</strong></li>
          <li>4. Secret: use the value from your <strong>.env</strong> → <code className="font-mono text-xs">GITHUB_WEBHOOK_SECRET</code></li>
          <li>5. Events: select <strong>Just the push event</strong></li>
          <li>6. Click <strong>Add webhook</strong></li>
        </ol>
        <a
          href="https://docs.github.com/en/developers/webhooks-and-events/webhooks/creating-webhooks"
          target="_blank"
          rel="noopener noreferrer"
          className="inline-flex items-center gap-1.5 text-xs underline underline-offset-2 hover:opacity-70"
          style={{ color: 'var(--color-muted-foreground)' }}
        >
          <ExternalLink size={11} strokeWidth={2} />
          GitHub webhook docs
        </a>
      </Section>
      </details>
    </div>
  )
}

export default Connect
