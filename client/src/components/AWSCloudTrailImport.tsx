import { useState } from 'react'
import { realClient } from '@/api/client'
import { Button } from '@/components/ui/button'

type Preview = { format: string; total_records: number; matched_records: number; already_present: number; duplicate_records: number; missing_key_records: number; other_key_records: number; success_count: number; failed_count: number; distinct_operations: number; first_event: string | null; last_event: string | null; more_pages_indicated: boolean; verification: string; added_records?: number }

export default function AWSCloudTrailImport({ incidentId, onImported }: { incidentId: string; onImported: () => Promise<void> }) {
  const [file, setFile] = useState<File | null>(null)
  const [preview, setPreview] = useState<Preview | null>(null)
  const [error, setError] = useState('')
  const [notice, setNotice] = useState('')
  const [busy, setBusy] = useState(false)
  async function send(onlyPreview: boolean) {
    if (!file) return
    setBusy(true); setError(''); setNotice('')
    try {
      const { data } = await realClient.post<Preview>(`/incidents/${incidentId}/aws-evidence?preview=${onlyPreview}`, file, { headers: { 'Content-Type': 'application/octet-stream' } })
      setPreview(data)
      if (!onlyPreview) { setNotice(`Imported ${data.added_records ?? 0} new records.`); await onImported() }
    } catch (err) {
      const detail = (err as { response?: { data?: { detail?: unknown } } }).response?.data?.detail
      setError(typeof detail === 'string' ? detail : 'Could not process the evidence file.')
    } finally { setBusy(false) }
  }
  return <section className="rounded-sm border bg-card p-5 space-y-3" aria-label="Import AWS evidence">
    <h2 className="font-semibold">Import CloudTrail evidence</h2>
    <p className="text-sm text-muted-foreground">Choose a CloudTrail Records or LookupEvents JSON file, optionally compressed as .gz. Only records matching this incident’s access key are imported. Uploaded evidence is not independently verified.</p>
    <input type="file" accept=".json,.gz,application/json,application/gzip" onChange={event => { setFile(event.target.files?.[0] ?? null); setPreview(null); setNotice(''); setError('') }} />
    <div className="flex gap-2"><Button variant="outline" disabled={!file || busy} onClick={() => void send(true)}>Preview</Button><Button disabled={!file || !preview || !preview.matched_records || busy || !!notice} onClick={() => void send(false)}>Import records</Button></div>
    {preview && <div className="space-y-1 text-sm"><p>{preview.format}: {preview.matched_records} matching of {preview.total_records} records · {preview.success_count} successful · {preview.failed_count} failed · {preview.distinct_operations} distinct operations · {preview.already_present} already present · {preview.duplicate_records} duplicates in file · {preview.missing_key_records} without key ID · {preview.other_key_records} other keys.</p>{preview.first_event && preview.last_event && <p>Matching records: {new Date(preview.first_event).toLocaleString()} – {new Date(preview.last_event).toLocaleString()}</p>}{preview.more_pages_indicated && <p role="alert">The file indicates more LookupEvents pages exist. Import the other pages for a more complete view.</p>}<p>{preview.verification}</p></div>}
    {error && <p role="alert" className="text-sm text-destructive">{error}</p>}{notice && <p role="status" className="text-sm">{notice}</p>}
  </section>
}
