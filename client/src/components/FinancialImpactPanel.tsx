import { Banknote, TrendingDown } from 'lucide-react'
import { Card, CardHeader, CardTitle, CardContent } from '@/components/ui/card'
import { PLATFORM_META, derivePlatform, type Platform } from '@/lib/platform'
import type { FinancialImpactLine, IncidentRecord } from '@/types'

/**
 * What the leak cost.
 *
 * The panel's whole job is keeping two very different numbers apart. Stripe
 * lines are money that demonstrably moved — a real amount, in a real currency,
 * on a real transaction. Every other platform is an order-of-magnitude estimate
 * from public list prices. Presenting them with equal confidence would either
 * overstate a cloud estimate or understate an actual loss, so `actual` splits
 * the panel in two and the footnote says which is which.
 */

interface Props {
  incident: IncidentRecord
}

const UNIT_SUFFIX: Record<NonNullable<FinancialImpactLine['unit']>, string> = {
  hour: '/hr',
  day: '/day',
  month: '/mo',
}

/**
 * Render an amount in its own currency.
 *
 * Intl handles the symbol, placement and grouping per currency, which is why
 * the ISO code is carried as data rather than baked into the backend string —
 * `1,240.00 USD` is not what a reader expects to see for a charge.
 */
function formatCurrency(amount: number, currency: string): string {
  try {
    return new Intl.NumberFormat(undefined, {
      style: 'currency',
      currency,
      maximumFractionDigits: 2,
    }).format(amount)
  } catch {
    // Unknown/invalid ISO code — never let a formatting failure hide the figure.
    return `${amount.toFixed(2)} ${currency}`
  }
}

/** Sum actual-money lines of one kind, grouped by currency. */
function totalsByCurrency(
  lines: FinancialImpactLine[],
  kind: FinancialImpactLine['kind'],
): { currency: string; total: number; count: number }[] {
  const acc = new Map<string, { total: number; count: number }>()

  for (const line of lines) {
    if (!line.actual || line.kind !== kind || line.amount === null) continue
    const currency = line.currency ?? 'USD'
    const entry = acc.get(currency) ?? { total: 0, count: 0 }
    entry.total += line.amount
    entry.count += line.quantity ?? 1
    acc.set(currency, entry)
  }

  return [...acc.entries()]
    .map(([currency, v]) => ({ currency, ...v }))
    .sort((a, b) => b.total - a.total)
}

function ActualFigure({
  label,
  entries,
  color,
}: {
  label: string
  entries: { currency: string; total: number; count: number }[]
  color: string
}) {
  if (entries.length === 0) return null

  return (
    <div>
      <p
        className="text-[10px] font-semibold uppercase tracking-wider"
        style={{ color: 'var(--color-muted-foreground)' }}
      >
        {label}
      </p>
      {entries.map(({ currency, total, count }) => (
        <div key={currency} className="flex items-baseline gap-2 mt-1">
          <span
            className="text-2xl font-bold font-mono tracking-tight tabular-nums"
            style={{ color }}
          >
            {formatCurrency(total, currency)}
          </span>
          <span className="text-[11px]" style={{ color: 'var(--color-muted-foreground)' }}>
            {count} transaction{count === 1 ? '' : 's'}
          </span>
        </div>
      ))}
    </div>
  )
}

const FinancialImpactPanel: React.FC<Props> = ({ incident }) => {
  const lines = incident.financial_impact_lines ?? []
  const fallback = incident.estimated_financial_impact

  // Nothing to show at all — render nothing rather than an empty card.
  if (lines.length === 0 && !fallback) return null

  // Older backend: structured lines absent, but the string is still stored.
  if (lines.length === 0 && fallback) {
    if (fallback === 'No financial impact detected') return null
    return (
      <Card>
        <CardHeader className="pb-3">
          <CardTitle className="flex items-center gap-2 text-sm">
            <Banknote size={14} strokeWidth={2} />
            Financial Impact
          </CardTitle>
        </CardHeader>
        <CardContent>
          <p className="text-sm font-mono" style={{ color: 'var(--color-foreground)' }}>
            {fallback}
          </p>
        </CardContent>
      </Card>
    )
  }

  const charged = totalsByCurrency(lines, 'charge')
  const refunded = totalsByCurrency(lines, 'refund')
  const paidOut = totalsByCurrency(lines, 'payout')
  const estimates = lines.filter(l => !l.actual)
  const hasActual = charged.length > 0 || refunded.length > 0 || paidOut.length > 0

  // Group estimates by platform so a multi-vendor leak reads as separate bills.
  const byPlatform = new Map<Platform, FinancialImpactLine[]>()
  for (const line of estimates) {
    const platform = derivePlatform({ platform: line.platform })
    byPlatform.set(platform, [...(byPlatform.get(platform) ?? []), line])
  }

  return (
    <Card>
      <CardHeader className="pb-3">
        <CardTitle className="flex items-center gap-2 text-sm">
          <Banknote size={14} strokeWidth={2} />
          Financial Impact
          {hasActual && (
            <span
              className="ml-auto text-[10px] font-bold uppercase tracking-wider px-1.5 py-0.5 rounded"
              style={{
                backgroundColor: 'color-mix(in srgb, var(--color-sev-critical) 15%, transparent)',
                color: 'var(--color-sev-critical)',
              }}
            >
              Money moved
            </span>
          )}
        </CardTitle>
      </CardHeader>

      <CardContent className="space-y-4">
        {/* Actual money first — it is the only figure here that is not a guess. */}
        {hasActual && (
          <div className="space-y-3">
            <ActualFigure
              label="Charged"
              entries={charged}
              color="var(--color-sev-critical)"
            />
            {/* Charges and refunds are never netted: the scorer treats them as
                different harms, and the panel must not contradict it. */}
            <ActualFigure
              label="Refunded"
              entries={refunded}
              color="var(--color-sev-high)"
            />
            {/* Payouts move the balance to a bank account — the attack that
                follows a changed payout destination. */}
            <ActualFigure
              label="Paid out"
              entries={paidOut}
              color="var(--color-sev-critical)"
            />
          </div>
        )}

        {estimates.length > 0 && (
          <div className={hasActual ? 'pt-3 border-t' : ''} style={hasActual ? { borderColor: 'var(--color-border)' } : undefined}>
            <p
              className="flex items-center gap-1.5 text-[10px] font-semibold uppercase tracking-wider mb-2"
              style={{ color: 'var(--color-muted-foreground)' }}
            >
              <TrendingDown size={11} strokeWidth={2} />
              Estimated running cost
            </p>

            <div className="space-y-2.5">
              {[...byPlatform.entries()].map(([platform, platformLines]) => (
                <div key={platform}>
                  <p
                    className="text-[10px] font-semibold uppercase tracking-wider"
                    style={{ color: PLATFORM_META[platform].color }}
                  >
                    {PLATFORM_META[platform].label}
                  </p>
                  {platformLines.map((line, i) => (
                    <div
                      key={`${line.kind}-${i}`}
                      className="flex items-baseline justify-between gap-3 mt-0.5"
                    >
                      <span
                        className="text-xs truncate"
                        style={{ color: 'var(--color-muted-foreground)' }}
                        title={line.text}
                      >
                        {line.label}
                        {line.quantity !== null && line.quantity > 1 && ` ×${line.quantity}`}
                      </span>
                      <span
                        className="text-xs font-mono tabular-nums shrink-0"
                        style={{ color: 'var(--color-foreground)' }}
                      >
                        {line.amount !== null
                          ? formatCurrency(line.amount, line.currency ?? 'USD')
                          : '—'}
                        {line.unit && (
                          <span style={{ color: 'var(--color-muted-foreground)' }}>
                            {UNIT_SUFFIX[line.unit]}
                          </span>
                        )}
                      </span>
                    </div>
                  ))}
                </div>
              ))}
            </div>
          </div>
        )}

        {/* Provenance. Without this the two sections read as equally certain. */}
        <p
          className="text-[10px] leading-relaxed pt-1"
          style={{ color: 'var(--color-muted-foreground)' }}
        >
          {hasActual && 'Charged and refunded figures are amounts actually transacted. '}
          {estimates.length > 0 &&
            'Running costs are order-of-magnitude estimates from public list prices, not billing figures, and accrue until the resources are shut down.'}
        </p>
      </CardContent>
    </Card>
  )
}

export default FinancialImpactPanel
