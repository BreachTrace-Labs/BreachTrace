import { useEffect, useState } from 'react'
import { realClient, USE_MOCK } from '@/api/client'
import { useProjects } from '@/context/ProjectContext'
import { Button } from '@/components/ui/button'
import GCPGroundTruth from '@/components/GCPGroundTruth'

type RecordEvent = { event_id: string; timestamp: string; api_action: string; success: boolean; error_code: string | null; affected_resource: string | null; source_ip: string | null; impact_category: string | null }
type Result = { mode: string; evidence_source?: 'imported_json' | 'live_collection'; scenario_id: string; start_utc: string; end_utc: string; record_count: number; input_record_count?: number; duplicate_record_count?: number; successful_count: number; failed_count: number; categories: Record<string, number>; methods: Record<string, number>; correlation: { group_count: number; ungrouped_record_count: number }; events: RecordEvent[]; limitations: string }
type Job = { id: string; status: 'queued' | 'running' | 'complete' | 'failed'; scenario_id: string; error: string | null; result: Result | null }
const input = 'mt-1 w-full rounded-md border bg-background p-2 text-sm'

export default function GCPHistoricalResearch() {
  const { selected } = useProjects()
  const [project, setProject] = useState(''); const [principal, setPrincipal] = useState('')
  const [scenario, setScenario] = useState('GCP-RECON-01'); const [start, setStart] = useState(''); const [end, setEnd] = useState('')
  const [file, setFile] = useState<File | null>(null)
  const [job, setJob] = useState<Job | null>(null); const [error, setError] = useState(''); const [busy, setBusy] = useState(false)
  const selectedId = selected?.id
  const jobStatus = job?.status
  const jobId = job?.id
  useEffect(() => {
    setJob(null); setError(''); setFile(null)
    if (!selectedId || USE_MOCK) return
    let active = true
    const load = () => realClient.get<Job | null>('/research/gcp-historical/latest', {params: {project_id: selectedId}})
      .then(({data}) => { if (active) setJob(data) }).catch(() => { if (active) setError('Could not load historical research status.') })
    void load()
    return () => { active = false }
  }, [selectedId])
  useEffect(() => {
    if (!selectedId || !jobId || !jobStatus || !['queued', 'running'].includes(jobStatus)) return
    let active = true
    const timer = window.setInterval(() => {
      void realClient.get<Job>(`/research/gcp-historical/${jobId}`)
        .then(({data}) => { if (active) setJob(data) }).catch(() => { if (active) setError('Could not refresh historical research status.') })
    }, 4000)
    return () => { active = false; window.clearInterval(timer) }
  }, [selectedId, jobId, jobStatus])
  async function submit(event: React.FormEvent) {
    event.preventDefault()
    if (!selectedId) return
    setBusy(true); setError('')
    try {
      const { data } = await realClient.post<Job>('/research/gcp-historical', {
        project_id: selectedId, gcp_project_id: project.trim(), principal_email: principal.trim(), scenario_id: scenario.trim(),
        start_utc: new Date(`${start}Z`).toISOString(), end_utc: new Date(`${end}Z`).toISOString(),
      })
      setJob(data)
    } catch (err) {
      const detail = (err as {response?: {data?: {detail?: unknown}}}).response?.data?.detail
      setError(typeof detail === 'string' ? detail : 'Could not start the query. Check the UTC range and GCP reader.')
    } finally { setBusy(false) }
  }
  async function importEvidence() {
    if (!selectedId || !file) return
    setBusy(true); setError('')
    try {
      const form = new FormData()
      form.set('project_id', selectedId); form.set('gcp_project_id', project.trim()); form.set('principal_email', principal.trim())
      form.set('scenario_id', scenario.trim()); form.set('start_utc', new Date(`${start}Z`).toISOString()); form.set('end_utc', new Date(`${end}Z`).toISOString())
      form.set('evidence', file)
      const { data } = await realClient.post<Job>('/research/gcp-historical/import', form)
      setJob(data)
    } catch (err) {
      const detail = (err as {response?: {data?: {detail?: unknown}}}).response?.data?.detail
      setError(typeof detail === 'string' ? detail : 'Could not import the JSON file. Check the project, principal and UTC range.')
    } finally { setBusy(false) }
  }
  const result = job?.result
  return <section className="space-y-4 rounded-md border bg-card p-5" aria-label="Historical GCP research">
    <div><h2 className="font-semibold">Historical GCP research</h2><p className="mt-1 text-sm text-muted-foreground">Read Cloud Audit Logs for a known service account and UTC window. Results are research evidence, not a credential-leak incident or a ground-truth evaluation.</p></div>
    {USE_MOCK ? <p className="text-sm text-muted-foreground">Connect to the backend to query a project reader.</p> : !selectedId ? <p className="text-sm text-muted-foreground">Select a project with a verified GCP wallet reader.</p> : <form className="space-y-3" onSubmit={event => void submit(event)}>
      <p className="text-sm text-muted-foreground">BreachTrace project: <strong>{selected?.name}</strong>. Live collection requires a verified wallet reader for the specified GCP project. JSON import does not contact GCP.</p>
      <div className="grid gap-3 sm:grid-cols-2">
        <label className="text-sm">GCP project ID<input className={input} required value={project} onChange={event => setProject(event.target.value)} /></label>
        <label className="text-sm">Service-account email<input className={input} required type="email" value={principal} onChange={event => setPrincipal(event.target.value)} /></label>
        <label className="text-sm">Scenario identifier<input className={input} required pattern="GCP-[A-Z0-9-]{2,72}" value={scenario} onChange={event => setScenario(event.target.value.toUpperCase())} /></label>
        <span className="text-sm text-muted-foreground self-end">Maximum 90 days and 2,000 records read, including duplicates. The query fails rather than silently truncating.</span>
        <label className="text-sm">Start (UTC)<input className={input} type="datetime-local" step="1" required value={start} onChange={event => setStart(event.target.value)} /></label>
        <label className="text-sm">End (UTC)<input className={input} type="datetime-local" step="1" required value={end} onChange={event => setEnd(event.target.value)} /></label>
      </div>
      <div className="flex flex-wrap items-end gap-3"><Button type="submit" loading={busy} disabled={job?.status === 'queued' || job?.status === 'running'}>Collect historical logs</Button><label className="text-sm">Cloud Audit Logs JSON<input key={selectedId} className="mt-1 block max-w-full text-sm" type="file" accept=".json,application/json" onChange={event => setFile(event.target.files?.[0] ?? null)} /></label><Button type="button" variant="outline" disabled={!file || busy || job?.status === 'queued' || job?.status === 'running'} onClick={() => void importEvidence()}>Import JSON</Button></div>
      <p className="text-xs text-muted-foreground">Import a UTF-8 JSON array (up to 5 MB and 2,000 records). Each record must match the project, principal and UTC window above.</p>
    </form>}
    {error && <p role="alert" className="text-sm text-destructive">{error}</p>}
    {job && <div role="status" className="space-y-2 border-t pt-3 text-sm"><p><strong>{job.scenario_id}</strong> · {job.status === 'complete' ? job.result?.evidence_source === 'imported_json' ? 'JSON import complete' : 'Collection complete' : job.status === 'failed' ? 'Collection failed' : 'Collection in progress'}</p>{job.error && <p className="text-destructive">{job.error}</p>}
      {result && <><p>{result.record_count} stored records · {result.successful_count} successful · {result.failed_count} failed · {result.correlation.group_count} related groups · {result.correlation.ungrouped_record_count} ungrouped</p><p className="text-muted-foreground">{result.limitations} Missing records do not prove that no activity occurred.</p>
        {result.evidence_source === 'imported_json' && <p className="text-muted-foreground">Imported file: {result.input_record_count} input records, {result.duplicate_record_count} exact duplicates removed. File provenance has not been independently verified.</p>}
        <p className="text-muted-foreground">{new Date(result.start_utc).toISOString()} to {new Date(result.end_utc).toISOString()}</p>
        <p>Methods: {Object.entries(result.methods).map(([name, count]) => `${name} (${count})`).join(', ') || 'none returned'}</p>
        <details><summary className="cursor-pointer font-medium">View collected records</summary><ul className="mt-2 max-h-80 space-y-2 overflow-y-auto">{result.events.slice(0, 100).map(item => <li key={item.event_id} className="border-t pt-2"><span className="font-mono break-all">{item.api_action}</span> · {item.success ? 'Succeeded' : item.error_code === '7' ? 'Denied' : 'Failed'}<span className="block text-xs text-muted-foreground">{new Date(item.timestamp).toISOString()} · {item.impact_category === 'resource_abuse' ? 'Resource change' : item.impact_category?.replaceAll('_', ' ') ?? 'Unclassified'}{item.source_ip ? ` · IP ${item.source_ip}` : ''}{item.affected_resource ? ` · ${item.affected_resource}` : ''}</span></li>)}</ul>{result.events.length > 100 && <p className="mt-2 text-xs text-muted-foreground">Showing 100 of {result.events.length} records. The complete result remains available through the research API.</p>}</details>
        <GCPGroundTruth evidenceId={job.id} />
      </>}
    </div>}
  </section>
}
