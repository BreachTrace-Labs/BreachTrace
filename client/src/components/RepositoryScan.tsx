import { useEffect, useRef, useState } from 'react'
import { realClient as api } from '@/api/client'
import { Button } from '@/components/ui/button'

type Scan = { scan_id: string; status: string; error?: string; result?: {
  repo_url: string; branch: string;
  revision: string; files_scanned: number; duration_s: number; finding_count: number;
  complete: boolean; stopped_reason?: string; skipped: Record<string, number>; archive_skipped: Record<string, number>;
  findings: { path: string; line_number: number; line_end?: number; credential_type: string; credential_hint: string; fingerprint: string; detection_method?: string; confidence?: string | null }[];
} }

export default function RepositoryScan({ repoUrl, onRepoUrlChange, trigger = 0 }: { repoUrl: string; onRepoUrlChange: (url: string) => void; trigger?: number }) {
  const [scan, setScan] = useState<Scan | null>(null)
  const [error, setError] = useState('')
  const [starting, setStarting] = useState(false)
  const lastTrigger = useRef(0)
  const pollTimer = useRef<ReturnType<typeof setTimeout> | null>(null)
  const alive = useRef(true)
  const busy = useRef(false)
  useEffect(() => { alive.current = true; return () => { alive.current = false; if (pollTimer.current) clearTimeout(pollTimer.current) } }, [])

  async function start() {
    if (busy.current || !repoUrl.trim()) return
    busy.current = true
    setStarting(true); setError(''); setScan(null)
    try {
      const { data } = await api.post<Scan>('/repositories/scan', { repo_url: repoUrl.trim() })
      if (alive.current) { setScan(data); void poll(data.scan_id) }
    } catch {
      busy.current = false
      if (alive.current) setError('Cannot start scan. Use a GitHub repository URL and connect to the local backend. Another scan may already be running.')
    }
    finally { if (alive.current) setStarting(false) }
  }
  async function poll(id: string) {
    try {
      const { data } = await api.get<Scan>(`/repositories/scans/${id}`)
      if (!alive.current) return
      setScan(data)
      if (['queued', 'scanning'].includes(data.status)) pollTimer.current = setTimeout(() => { void poll(id) }, 2000)
      else busy.current = false
    } catch {
      busy.current = false
      if (alive.current) {
        setError('Cannot retrieve scan status. The backend may have restarted; completed evidence is saved on the server.')
        setScan(previous => previous ? { ...previous, status: 'status-unavailable' } : null)
      }
    }
  }
  useEffect(() => {
    if (trigger > lastTrigger.current) { lastTrigger.current = trigger; void start() }
    // A trigger represents a successfully connected repository. Editing the URL
    // must not start another download by itself.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [trigger])
  const running = starting || (scan && ['queued', 'scanning'].includes(scan.status))
  return <section className="border rounded p-6 space-y-4">
    <h2 className="font-semibold">Scan existing codebase</h2>
    <p className="text-sm">Paste a GitHub repository URL to check its current codebase for exposed credentials. No webhook or new commit is required. Private repositories require GitHub access configured on the backend.</p>
    <form onSubmit={event => { event.preventDefault(); void start() }} className="space-y-2">
      <label htmlFor="scan-repository-url" className="block text-sm font-medium">Repository URL</label>
      <div className="flex flex-col sm:flex-row gap-2">
        <input id="scan-repository-url" type="url" required disabled={!!running} value={repoUrl}
          onChange={event => onRepoUrlChange(event.target.value)} placeholder="https://github.com/owner/repository"
          className="min-w-0 flex-1 border rounded px-3 py-2 text-sm bg-transparent" />
        <Button type="submit" disabled={!repoUrl.trim() || !!running}>{running ? 'Scanning…' : 'Scan repository'}</Button>
      </div>
    </form>
    <p className="text-xs text-[var(--color-muted-foreground)]">Scans the default branch’s current text files, subject to size limits and exclusions. Git history, submodules and binaries are excluded.</p>
    {error && <p role="alert">{error}</p>}
    {scan && <div role="status" className="space-y-2 text-sm">
      <p>Scan {scan.scan_id}: {scan.status}</p>
      {scan.error && <p>{scan.error}</p>}
      {scan.result && <>
        <p className="font-semibold">{scan.result.finding_count === 0 ? 'No credential candidates found in scanned files.' : `${scan.result.finding_count} potential credential exposure${scan.result.finding_count === 1 ? '' : 's'} found.`}</p>
        <p className="break-all">{scan.result.repo_url} · branch {scan.result.branch}</p>
        <p>{scan.result.files_scanned.toLocaleString()} text files · {scan.result.finding_count} candidates · {scan.result.duration_s.toFixed(2)} seconds of scanning</p>
        <p className="break-all">Revision: {scan.result.revision}</p>
        {!scan.result.complete && <p>Partial scan: {scan.result.stopped_reason ?? 'some files or decoding steps could not be completed'}.</p>}
        <p>Skipped: {JSON.stringify({ ...scan.result.skipped, ...scan.result.archive_skipped })}</p>
        <p>Findings are unverified. A public identifier or test fixture can match a rule. Snapshot detection does not establish the first exposure time and does not start cloud forensics.</p>
        <div className="max-h-96 overflow-auto space-y-2">{scan.result.findings.map(f => <div key={f.fingerprint} className="border-t pt-2 break-all">
          <a className="font-mono underline" target="_blank" rel="noopener noreferrer"
            href={`${scan.result!.repo_url}/blob/${scan.result!.revision}/${f.path.split('/').map(encodeURIComponent).join('/')}#L${f.line_number}`}>
            {f.path}:{f.line_number}
          </a><p>{f.credential_type} · {f.credential_hint}</p>
          {f.detection_method && <p className="text-xs text-[var(--color-muted-foreground)]">{f.detection_method}{f.confidence ? ` · ${f.confidence} confidence` : ''} · validity not verified{f.line_end && f.line_end > f.line_number ? ` · spans lines ${f.line_number}–${f.line_end}` : ''}</p>}
        </div>)}</div>
      </>}
    </div>}
  </section>
}
