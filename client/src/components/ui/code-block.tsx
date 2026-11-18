import { useEffect, useRef, useState } from 'react'
import './system.css'
export function CodeBlock({ value }: { value: string }) {
  const [copied, setCopied] = useState(false); const [error, setError] = useState(false); const timer = useRef<ReturnType<typeof setTimeout> | undefined>(undefined)
  useEffect(() => () => clearTimeout(timer.current), [])
  async function copy() { try { await navigator.clipboard.writeText(value); setCopied(true); setError(false); clearTimeout(timer.current); timer.current = setTimeout(() => setCopied(false), 1500) } catch { setError(true) } }
  return <div className="ui-code"><code>{value}</code><button type="button" onClick={copy} aria-label={copied ? 'Copied' : 'Copy to clipboard'}>{copied ? '✓' : 'Copy'}</button>{error && <span role="status">Copy failed</span>}</div>
}
