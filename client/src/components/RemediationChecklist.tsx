import { useState } from 'react'
import { Card, CardHeader, CardTitle, CardContent } from '@/components/ui/card'
import { CheckSquare, Square } from 'lucide-react'

interface Props {
  steps: string[]
}

/* Strips the leading checkbox char that the pipeline includes in the raw text */
function cleanStep(raw: string): string {
  return raw
    .replace(/^[☐☑]\s*/, '')  // remove ☐ / ☑ prefix
    .trim()
}

/* Renders inline **bold** and *emphasis* (Gemini uses both) */
function renderInline(text: string): React.ReactNode {
  const parts = text.split(/(\*\*[^*]+\*\*|\*[^*\n]+\*)/g)
  return (
    <>
      {parts.map((part, i) => {
        if (part.startsWith('**') && part.endsWith('**') && part.length > 4) {
          return <strong key={i} className="font-semibold">{part.slice(2, -2)}</strong>
        }
        if (part.startsWith('*') && part.endsWith('*') && part.length > 2) {
          return <strong key={i} className="font-semibold">{part.slice(1, -1)}</strong>
        }
        return part || null
      })}
    </>
  )
}

const RemediationChecklist: React.FC<Props> = ({ steps }) => {
  const [checked, setChecked] = useState<Set<number>>(new Set())

  const toggle = (i: number) =>
    setChecked(prev => {
      const next = new Set(prev)
      next.has(i) ? next.delete(i) : next.add(i)
      return next
    })

  const doneCount = checked.size

  return (
    <Card>
      <CardHeader className="pb-3">
        <CardTitle className="flex items-center gap-2 text-sm">
          Remediation Checklist
          {steps.length > 0 && (
            <span
              className="ml-auto text-xs font-mono px-1.5 py-0.5 rounded"
              style={{ backgroundColor: 'var(--color-muted)', color: 'var(--color-muted-foreground)' }}
            >
              {doneCount}/{steps.length}
            </span>
          )}
        </CardTitle>
      </CardHeader>
      <CardContent>
        {steps.length === 0 ? (
          <p className="text-sm" style={{ color: 'var(--color-muted-foreground)' }}>
            Awaiting report generation
          </p>
        ) : (
          <>
            {/* Progress bar */}
            {steps.length > 1 && (
              <div
                className="h-1 rounded-full overflow-hidden mb-4"
                style={{ backgroundColor: 'var(--color-muted)' }}
              >
                <div
                  className="h-full rounded-full transition-all duration-300"
                  style={{
                    width: `${(doneCount / steps.length) * 100}%`,
                    backgroundColor: 'var(--color-sev-low)',
                  }}
                />
              </div>
            )}

            <ul className="space-y-2.5">
              {steps.map((raw, i) => {
                const text = cleanStep(raw)
                const done = checked.has(i)
                return (
                  <li
                    key={i}
                    className="flex items-start gap-3 cursor-pointer"
                    onClick={() => toggle(i)}
                  >
                    <span
                      className="mt-0.5 shrink-0 transition-colors"
                      style={{ color: done ? 'var(--color-sev-low)' : 'var(--color-muted-foreground)' }}
                    >
                      {done ? <CheckSquare size={15} strokeWidth={2} /> : <Square size={15} strokeWidth={2} />}
                    </span>
                    <span
                      className="text-sm leading-snug transition-colors"
                      style={{
                        color: done ? 'var(--color-muted-foreground)' : 'var(--color-foreground)',
                        textDecoration: done ? 'line-through' : 'none',
                      }}
                    >
                      {renderInline(text)}
                    </span>
                  </li>
                )
              })}
            </ul>
          </>
        )}
      </CardContent>
    </Card>
  )
}

export default RemediationChecklist
