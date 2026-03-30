import { useState } from 'react'
import { Card, CardHeader, CardTitle, CardContent } from '@/components/ui/card'
import { CheckSquare, Square } from 'lucide-react'

interface Props {
  steps: string[]
}

const RemediationChecklist: React.FC<Props> = ({ steps }) => {
  const [checked, setChecked] = useState<Set<number>>(new Set())

  const toggle = (i: number) =>
    setChecked((prev) => {
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
          <ul className="space-y-2">
            {steps.map((step, i) => (
              <li
                key={i}
                className="flex items-start gap-3 cursor-pointer group"
                onClick={() => toggle(i)}
              >
                <span
                  className="mt-0.5 shrink-0 transition-colors"
                  style={{
                    color: checked.has(i)
                      ? 'var(--color-sev-low)'
                      : 'var(--color-muted-foreground)',
                  }}
                >
                  {checked.has(i) ? (
                    <CheckSquare size={15} strokeWidth={2} />
                  ) : (
                    <Square size={15} strokeWidth={2} />
                  )}
                </span>
                <span
                  className="text-sm leading-snug transition-colors"
                  style={{
                    color: checked.has(i)
                      ? 'var(--color-muted-foreground)'
                      : 'var(--color-foreground)',
                    textDecoration: checked.has(i) ? 'line-through' : 'none',
                  }}
                >
                  {step}
                </span>
              </li>
            ))}
          </ul>
        )}
      </CardContent>
    </Card>
  )
}

export default RemediationChecklist
