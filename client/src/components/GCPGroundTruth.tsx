import { useEffect, useState } from 'react'
import { realClient } from '@/api/client'
import { Button } from '@/components/ui/button'

type Comparison = { compared: number; correct: number; accuracy: number | null; confusion: {expected: string; actual: string; count: number}[] }
type Evaluation = { id: string; result: { unit: 'commands' | 'audit_records'; csv_row_count: number; evidence_record_count: number; command_count: number | null; matched_record_count?: number | null; missing_record_count?: number; ambiguous_record_count?: number; classification: Comparison | null; outcome: Comparison | null; limitations: string[] } }
const input = 'mt-1 w-full rounded-md border bg-background p-2 text-sm'

function Metric({ name, value }: { name: string; value: Comparison | null }) {
  if (!value || value.compared === 0) return <p>{name}: not measured.</p>
  return <div><p>{name}: {value.correct}/{value.compared} matched labels agree ({Math.round((value.accuracy ?? 0) * 1000) / 10}%).</p><ul className="ml-4 list-disc text-xs text-muted-foreground">{value.confusion.map(item => <li key={`${item.expected}-${item.actual}`}>Expected {item.expected}, observed {item.actual}: {item.count}</li>)}</ul></div>
}

export default function GCPGroundTruth({ evidenceId }: { evidenceId: string }) {
  const [unit, setUnit] = useState<'commands' | 'audit_records'>('commands')
  const [command, setCommand] = useState('command'); const [recordId, setRecordId] = useState('insert_id')
  const [category, setCategory] = useState(''); const [outcome, setOutcome] = useState('')
  const [csv, setCsv] = useState<File | null>(null); const [busy, setBusy] = useState(false)
  const [evaluation, setEvaluation] = useState<Evaluation | null>(null); const [error, setError] = useState('')
  useEffect(() => {
    let active = true
    setEvaluation(null); setCsv(null); setError('')
    realClient.get<Evaluation | null>(`/research/gcp-historical/${evidenceId}/evaluation/latest`)
      .then(({data}) => { if (active) setEvaluation(data) })
      .catch(() => { if (active) setError('Could not load the previous comparison.') })
    return () => { active = false }
  }, [evidenceId])
  async function compare(event: React.FormEvent) {
    event.preventDefault()
    if (!csv) return
    setBusy(true); setError('')
    try {
      const data = new FormData(); data.set('unit', unit); data.set('ground_truth', csv)
      if (unit === 'commands') data.set('command_column', command.trim())
      else { data.set('record_id_column', recordId.trim()); if (category.trim()) data.set('category_column', category.trim()); if (outcome.trim()) data.set('outcome_column', outcome.trim()) }
      const response = await realClient.post<Evaluation>(`/research/gcp-historical/${evidenceId}/evaluate`, data)
      setEvaluation(response.data)
    } catch (err) {
      const detail = (err as { response?: { data?: { detail?: unknown } } }).response?.data?.detail
      setError(typeof detail === 'string' ? detail : 'Could not compare this CSV. Check the row type and selected column names.')
    } finally { setBusy(false) }
  }
  const result = evaluation?.result
  return <section className="mt-4 space-y-3 border-t pt-4" aria-label="GCP ground-truth comparison">
    <div><h3 className="font-semibold">Compare ground-truth CSV</h3><p className="mt-1 text-sm text-muted-foreground">Choose what each CSV row represents and enter the exact column names. Labels are independent of the audit records.</p></div>
    <form className="space-y-3" onSubmit={event => void compare(event)}>
      <div className="grid gap-3 sm:grid-cols-2"><label className="text-sm">Each row represents<select className={input} value={unit} onChange={event => setUnit(event.target.value as typeof unit)}><option value="commands">One command</option><option value="audit_records">One audit record</option></select></label>
        {unit === 'commands' ? <label className="text-sm">Command column name<input className={input} required value={command} onChange={event => setCommand(event.target.value)} /></label> : <><label className="text-sm">Provider insert ID column<input className={input} required value={recordId} onChange={event => setRecordId(event.target.value)} /></label><label className="text-sm">Expected category column (optional)<input className={input} value={category} onChange={event => setCategory(event.target.value)} /></label><label className="text-sm">Expected outcome column (optional)<input className={input} value={outcome} onChange={event => setOutcome(event.target.value)} /></label></>}
      </div>
      <p className="text-xs text-muted-foreground">{unit === 'commands' ? 'Counts CSV rows as labelled commands; it does not infer which logs belong to a command.' : 'Records match only when an insert ID uniquely identifies one stored audit record. Supply at least one label column. Outcomes: success, failed, denied or not_found; categories use BreachTrace category IDs.'}</p>
      <div className="flex flex-wrap items-end gap-3"><label className="text-sm">Ground-truth CSV<input key={evidenceId} className="mt-1 block max-w-full text-sm" type="file" required accept=".csv,text/csv" onChange={event => setCsv(event.target.files?.[0] ?? null)} /></label><Button type="submit" variant="outline" loading={busy} disabled={!csv || (unit === 'audit_records' && !category.trim() && !outcome.trim())}>Compare CSV</Button></div>
      <p className="text-xs text-muted-foreground">Maximum 1 MB and 2,000 rows. CSV contents are not saved; the comparison and file digest are retained.</p>
    </form>
    {error && <p role="alert" className="text-sm text-destructive">{error}</p>}
    {result && <div role="status" className="space-y-2 rounded-md border p-3 text-sm"><p><strong>Comparison result</strong> · {result.csv_row_count} CSV rows · {result.evidence_record_count} stored audit records</p>
      {result.unit === 'commands' ? <p>{result.command_count} operator-labelled command rows. No command-to-record matches were inferred.</p> : <><p>{result.matched_record_count} uniquely matched · {result.missing_record_count} not found · {result.ambiguous_record_count} ambiguous</p><Metric name="Classification agreement" value={result.classification}/><Metric name="Outcome agreement" value={result.outcome}/></>}
      {result.limitations.map(item => <p className="text-xs text-muted-foreground" key={item}>{item}</p>)}
    </div>}
  </section>
}
