import { useCallback, useEffect, useRef, useState } from 'react'
import { Search as SearchIcon, X } from 'lucide-react'
import client from '@/api/client'
import type { SearchResult } from '@/types'
import SearchResults from '@/components/SearchResults'
import { Button } from '@/components/ui/button'
import './search.css'

const EXAMPLES = ['Sarvam incidents', 'critical incidents this week', 'stripe incidents in the last 7 days', 'how do I rotate a Twilio auth token', 'why is there no timeline for a GitHub token']
export default function Search() {
  const [question, setQuestion] = useState(''); const [result, setResult] = useState<SearchResult | null>(null); const [loading, setLoading] = useState(false); const [error, setError] = useState(''); const [answering, setAnswering] = useState(false); const sequence = useRef(0); const input = useRef<HTMLInputElement>(null)
  const run = useCallback(async (query: string, generate = false) => {
    const trimmed = query.trim(); const request = ++sequence.current
    if (trimmed.length < 2) { setResult(null); setLoading(false); setAnswering(false); setError(''); return }
    setLoading(true); setAnswering(generate); setError('')
    try { const { data } = await client.post<SearchResult>('/assistant/search', { question: trimmed, generate_answer: generate }, { timeout: generate ? 310_000 : 30_000 }); if (sequence.current === request) setResult(data) }
    catch { if (sequence.current === request) { setResult(null); setError('Search is unavailable. Check the backend connection and try again.') } }
    finally { if (sequence.current === request) { setLoading(false); setAnswering(false) } }
  }, [])
  useEffect(() => { const requests = sequence; const timer = window.setTimeout(() => void run(question), 300); return () => { window.clearTimeout(timer); requests.current++ } }, [question, run])
  useEffect(() => { const focus = () => input.current?.focus(); window.addEventListener('bt-focus-search', focus); return () => window.removeEventListener('bt-focus-search', focus) }, [])
  const choose = (q: string) => { sequence.current++; setResult(null); setError(''); if (q === question) void run(q); else setQuestion(q); input.current?.focus() }
  return <div className="search-page"><header><h1>Search</h1><p>Search incidents, timelines, reports and response guidance across the organisation.</p></header><div className="search-bar"><SearchIcon size={18}/><input ref={input} autoFocus aria-label="Search incidents, events and reports" placeholder="Search incidents, events, reports..." maxLength={500} value={question} onChange={e => { sequence.current++; setResult(null); setLoading(false); setAnswering(false); setError(''); setQuestion(e.target.value) }}/>{question && <button type="button" aria-label="Clear search" onClick={() => { sequence.current++; setResult(null); setLoading(false); setAnswering(false); setError(''); setQuestion(''); input.current?.focus() }}><X size={16}/></button>}<kbd>⌘K</kbd></div>
    <p className="search-note">Retrieval runs locally. Exact event times can be searched using an ISO timestamp with a time zone. Review conclusions against the cited evidence; missing logs do not prove no activity.</p>
    <div className="search-answer-action"><Button variant="outline" loading={answering} disabled={question.trim().length < 2 || loading} onClick={() => void run(question, true)}>Generate an evidence-based answer</Button><p>When a cloud model is selected, your question and matching passages are sent to that provider.</p></div>
    {error && <p role="alert" className="search-error">{error}</p>}{loading && <p role="status" className="search-loading">{answering ? 'Generating answer…' : 'Searching…'}</p>}{!question.trim() && <div className="search-examples"><p>Try a search</p>{EXAMPLES.map(example => <button key={example} type="button" onClick={() => choose(example)}>{example}</button>)}</div>}{result && !loading && <SearchResults result={result} onSuggestion={choose}/>}</div>
}
