import { Link } from 'react-router-dom'
import { BookOpen, FileSearch, Lightbulb } from 'lucide-react'
import type { SearchPassage, SearchResult } from '@/types'
import SeverityBadge from '@/components/SeverityBadge'
import { derivePlatform, PLATFORM_META } from '@/lib/platform'
import { isSyntheticIncident } from '@/lib/incidentPresentation'
import SyntheticNotice from '@/components/SyntheticNotice'

/**
 * Renders a retrieval-only search result: matching incidents, then verbatim
 * passages with the best-matching sentence highlighted. Nothing here is
 * generated text; every passage links to its source.
 */

function Highlighted({ passage }: { passage: SearchPassage }) {
  const at = passage.text.indexOf(passage.highlight)
  if (!passage.highlight || at < 0 || passage.highlight === passage.text) {
    return <p className="text-sm leading-relaxed">{passage.text}</p>
  }
  return (
    <p className="text-sm leading-relaxed" style={{ color: 'var(--color-muted-foreground)' }}>
      {passage.text.slice(0, at)}
      <mark
        className="rounded-sm px-0.5"
        style={{
          backgroundColor: 'color-mix(in srgb, var(--color-primary) 18%, transparent)',
          color: 'var(--color-foreground)',
        }}
      >
        {passage.highlight}
      </mark>
      {passage.text.slice(at + passage.highlight.length)}
    </p>
  )
}

function PassageCard({ passage }: { passage: SearchPassage }) {
  const isIncident = passage.source_type === 'incident'
  return (
    <div className="border rounded-sm p-4 space-y-2" style={{ borderColor: 'var(--color-border)' }}>
      <div className="flex items-start gap-2">
        {isIncident ? (
          <FileSearch size={14} className="mt-0.5 shrink-0" />
        ) : (
          <BookOpen size={14} className="mt-0.5 shrink-0" />
        )}
        <div className="min-w-0 flex-1">
          {isIncident ? (
            <Link
              to={`/incident/${passage.source_id}`}
              className="text-sm font-semibold hover:underline break-words"
            >
              {passage.title}
            </Link>
          ) : (
            <p className="text-sm font-semibold break-words">{passage.title}</p>
          )}
          <p
            className="text-[10px] uppercase tracking-wider"
            style={{ color: 'var(--color-muted-foreground)' }}
          >
            {isIncident ? 'From an incident report' : 'Knowledge base'}
          </p>
        </div>
      </div>
      <Highlighted passage={passage} />
    </div>
  )
}

export default function SearchResults({
  result,
  onSuggestion,
  showIncidents = true,
}: {
  result: SearchResult
  onSuggestion?: (question: string) => void
  showIncidents?: boolean
}) {
  const { incidents, passages, suggestions } = result
  const nothing = incidents.length === 0 && passages.length === 0

  return (
    <div className="space-y-5">
      {result.disclaimer && <p role="note" className="text-xs text-muted-foreground">{result.disclaimer}</p>}
      {showIncidents && incidents.length > 0 && (
        <div className="space-y-2">
          <p
            className="text-[11px] font-semibold uppercase tracking-wider"
            style={{ color: 'var(--color-muted-foreground)' }}
          >
            {incidents.length} matching incident{incidents.length === 1 ? '' : 's'}
          </p>
          <div className="border rounded-sm divide-y" style={{ borderColor: 'var(--color-border)' }}>
            {incidents.map((inc) => {
              const platform = derivePlatform(inc)
              return (
                <Link
                  key={inc.incident_id}
                  to={`/incident/${inc.incident_id}`}
                  className="flex flex-wrap items-center gap-x-3 gap-y-1 px-4 py-3 text-sm hover:bg-[var(--color-secondary)]"
                  style={{ borderColor: 'var(--color-border)' }}
                >
                  <span className="font-semibold" style={{ color: PLATFORM_META[platform].color }}>
                    {PLATFORM_META[platform].label}
                  </span>
                  <span className="font-mono text-xs">{inc.credential_hint}</span>
                  {isSyntheticIncident(inc) && <SyntheticNotice compact />}
                  <span
                    className="text-xs truncate max-w-[16rem]"
                    style={{ color: 'var(--color-muted-foreground)' }}
                  >
                    {inc.repo_url}
                  </span>
                  <span className="ml-auto flex items-center gap-2">
                    {inc.exposure_start && (
                      <span className="text-xs" style={{ color: 'var(--color-muted-foreground)' }}>
                        {new Date(inc.exposure_start).toLocaleString()}
                      </span>
                    )}
                    {inc.overall_severity && <SeverityBadge severity={inc.overall_severity} showIcon={false} />}
                  </span>
                </Link>
              )
            })}
          </div>
        </div>
      )}

      {passages.length > 0 && (
        <div className="space-y-2">
          {result.truncated && <p className="text-sm">More events match this interval. Narrow the time range to inspect them.</p>}
          {showIncidents && incidents.length > 0 && (
            <p
              className="text-[11px] font-semibold uppercase tracking-wider"
              style={{ color: 'var(--color-muted-foreground)' }}
            >
              Related passages
            </p>
          )}
          {passages.map((p) => (
            <PassageCard key={p.id} passage={p} />
          ))}
        </div>
      )}

      {nothing && (
        <div className="space-y-3">
          <p className="text-sm" style={{ color: 'var(--color-muted-foreground)' }}>
            No confident match. BreachTrace only shows passages that answer the question, rather than
            guessing.
          </p>
          {suggestions.length > 0 && onSuggestion && (
            <div className="flex flex-wrap items-center gap-2">
              <Lightbulb size={13} style={{ color: 'var(--color-muted-foreground)' }} />
              {suggestions.map((s) => (
                <button
                  key={s}
                  type="button"
                  onClick={() => onSuggestion(s)}
                  className="text-xs border rounded-full px-2.5 py-1 hover:bg-[var(--color-secondary)]"
                  style={{ borderColor: 'var(--color-border)' }}
                >
                  {s}
                </button>
              ))}
            </div>
          )}
        </div>
      )}
    </div>
  )
}
