import { useCallback, useEffect, useState } from 'react'
import { realClient, USE_MOCK } from '@/api/client'
import { Button } from '@/components/ui/button'

type Summary = { n: number; valid_json_rate: number | null; grounding_pass_rate: number | null; mean_fact_coverage: number | null; median_latency_s: number | null; failures: number }
type Result = { scope: string; fixture_sha256: string; prompt_version: string; deterministic_baseline: Summary; models: Record<string, { digest: string | null; summary: Summary }> }
type Job = { id: string; status: string; result: Result | null; error: string | null; created_at: string }
type Model = { name: string; size: number | null }
const pct = (n: number | null) => n == null ? '—' : `${(n * 100).toFixed(0)}%`
const seconds = (n: number | null) => n == null ? '—' : `${n.toFixed(2)} s`

export default function ModelBenchmark() {
  const [models, setModels] = useState<Model[]>([]); const [selected, setSelected] = useState<string[]>([]); const [cases, setCases] = useState(4)
  const [job, setJob] = useState<Job | null>(null); const [error, setError] = useState(''); const [busy, setBusy] = useState(false)
  const loadModels = useCallback(async () => { try { const { data } = await realClient.get<{models: Model[]}>('/research/model-benchmark/models'); setModels(data.models); setError('') } catch { setError('Local Ollama is unavailable. Start Ollama and install models before comparing.') } }, [])
  const loadJob = useCallback(async () => { try { const {data} = await realClient.get<Job | null>('/research/model-benchmark/latest'); setJob(data) } catch { setError('Could not load model comparison results from the local backend.') } }, [])
  useEffect(() => { if (!USE_MOCK) { void loadModels(); void loadJob() } }, [loadModels, loadJob])
  useEffect(() => { if (job?.status !== 'queued' && job?.status !== 'running') return; const timer = window.setInterval(() => void loadJob(), 3000); return () => window.clearInterval(timer) }, [job?.status, loadJob])
  if (USE_MOCK) return null
  async function start() {
    setBusy(true); setError('')
    try { await realClient.post('/research/model-benchmark', { models: selected, cases, seed: 20261103 }); await loadJob() }
    catch (err) { const detail = (err as { response?: { data?: { detail?: unknown } } }).response?.data?.detail; setError(typeof detail === 'string' ? detail : 'Could not start the comparison.') } finally { setBusy(false) }
  }
  function download() { if (!job?.result) return; const url = URL.createObjectURL(new Blob([JSON.stringify(job.result, null, 2)], {type:'application/json'})); const link = document.createElement('a'); link.href = url; link.download = 'breachtrace-model-comparison.json'; link.click(); URL.revokeObjectURL(url) }
  const running = job?.status === 'queued' || job?.status === 'running'
  const rows = job?.result ? [['Deterministic template', job.result.deterministic_baseline] as const, ...Object.entries(job.result.models).map(([name, value]) => [name, value.summary] as const)] : []
  return <section className="border bg-card p-5 space-y-4"><div><h2 className="text-lg font-semibold">Local report model comparison</h2><p className="text-sm text-muted-foreground">Compare installed Ollama models using identical synthetic incident facts. No model downloads or cloud calls are made.</p></div>
    <div className="flex flex-wrap gap-2"><Button variant="outline" size="sm" onClick={() => void loadModels()}>Refresh installed models</Button><label className="text-sm">Cases per model <input className="w-16 rounded border bg-transparent p-1" type="number" min={1} max={12} value={cases} onChange={e => setCases(Number(e.target.value))}/></label></div>
    {models.length > 0 ? <fieldset className="space-y-1"><legend className="text-sm font-medium">Select up to four models</legend>{models.map(model => <label className="flex items-center gap-2 text-sm" key={model.name}><input type="checkbox" checked={selected.includes(model.name)} disabled={!selected.includes(model.name) && selected.length >= 4} onChange={e => setSelected(prev => e.target.checked ? [...prev, model.name] : prev.filter(name => name !== model.name))}/>{model.name}{model.size ? ` · ${(model.size / 1e9).toFixed(1)} GB file` : ''}</label>)}</fieldset> : <p className="text-sm text-muted-foreground">No installed models available.</p>}
    <Button onClick={() => void start()} disabled={busy || running || !selected.length || !Number.isInteger(cases) || cases < 1 || cases > 12}>Run comparison</Button>
    {error && <p role="alert" className="text-sm text-red-500">{error}</p>}{job && <p role="status" className="text-sm">Comparison: {job.status}{running && ' · This may take several minutes.'}{job.error && ` · ${job.error}`}</p>}
    {rows.length > 0 && <><div className="overflow-x-auto"><table className="w-full text-sm text-left"><thead><tr><th>Model</th><th>Cases</th><th>Valid sections</th><th>Validation pass</th><th>Fact coverage</th><th>Median</th><th>Failures</th></tr></thead><tbody>{rows.map(([name, row]) => <tr key={name}><td>{name}</td><td>{row.n}</td><td>{pct(row.valid_json_rate)}</td><td>{pct(row.grounding_pass_rate)}</td><td>{pct(row.mean_fact_coverage)}</td><td>{seconds(row.median_latency_s)}</td><td>{row.failures}</td></tr>)}</tbody></table></div><p className="text-xs text-muted-foreground">Synthetic benchmark. Validation and fact coverage are proxies, not measured factual accuracy; timing includes loading. Results do not evaluate retrieval or RAG answers.</p><Button variant="outline" size="sm" onClick={download}>Download results JSON</Button></>}
  </section>
}
