import { useState } from 'react'
import { Search as SearchIcon, Loader2 } from 'lucide-react'
import client from '@/api/client'
import type { SearchResult } from '@/types'
import SearchResults from '@/components/SearchResults'
import { Button } from '@/components/ui/button'

const EXAMPLES = [
  'Sarvam incidents',
  'Claude incidents',
  'what happened at 2026-10-01T14:23:30Z',
  'critical incidents this week',
  'stripe incidents in the last 7 days',
  'how do I rotate a Twilio auth token',
  'why is there no timeline for a GitHub token',
  'what does CreateAccessKey mean',
  'when do I need to notify under GDPR',
]

export default function Search() {
  const [question, setQuestion] = useState('')
  const [result, setResult] = useState<SearchResult | null>(null)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)

  async function run(q: string) {
    const trimmed = q.trim()
    if (trimmed.length < 2) return
    setQuestion(trimmed)
    setLoading(true)
    setError(null)
    setResult(null)
    try {
      const { data } = await client.post<SearchResult>('/assistant/search', { question: trimmed })
      setResult(data)
    } catch {
      setError('Search failed. Is the backend running?')
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="mx-auto max-w-3xl px-6 py-10 space-y-6">
      <div className="space-y-1">
        <h1 className="text-xl font-bold tracking-tight">Search</h1>
        <p className="text-sm" style={{ color: 'var(--color-muted-foreground)' }}>
          Search forensic timelines, long reports and response guidance. For exact event times,
          include an ISO timestamp with a zone, such as 2026-10-01T14:23:30Z. Search retrieves evidence locally.
        </p>
      </div>

      <p className="text-sm border rounded p-3" role="note">
        Report prose quality depends on your selected model. Verify conclusions against cited events.
        Missing logs do not prove no activity. Cloud report generation sends fact sheets to the provider selected in Settings.
      </p>

      <form
        onSubmit={(e) => {
          e.preventDefault()
          void run(question)
        }}
        className="flex gap-2"
      >
        <div className="relative flex-1">
          <SearchIcon
            size={15}
            className="absolute left-3 top-1/2 -translate-y-1/2"
            style={{ color: 'var(--color-muted-foreground)' }}
          />
          <input
            value={question}
            onChange={(e) => setQuestion(e.target.value)}
            placeholder="e.g. stripe incidents this week"
            maxLength={500}
            className="w-full h-10 pl-9 pr-3 text-sm border rounded-sm bg-transparent outline-none focus:ring-2"
            style={{ borderColor: 'var(--color-border)' }}
            aria-label="Search question"
          />
        </div>
        <Button type="submit" disabled={loading || question.trim().length < 2}>
          {loading ? <Loader2 size={15} className="animate-spin" /> : 'Search'}
        </Button>
      </form>

      {!result && !loading && (
        <div className="flex flex-wrap gap-2">
          {EXAMPLES.map((q) => (
            <button
              key={q}
              type="button"
              onClick={() => void run(q)}
              className="text-xs border rounded-full px-2.5 py-1 hover:bg-[var(--color-secondary)]"
              style={{ borderColor: 'var(--color-border)' }}
            >
              {q}
            </button>
          ))}
        </div>
      )}

      {error && <p className="text-sm" style={{ color: 'var(--color-sev-critical)' }}>{error}</p>}

      {result && !loading && (
        <SearchResults result={result} onSuggestion={(q) => void run(q)} />
      )}
    </div>
  )
}
