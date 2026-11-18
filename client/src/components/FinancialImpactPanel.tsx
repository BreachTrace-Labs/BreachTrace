import { Banknote, Info } from 'lucide-react'
import { Card, CardHeader, CardTitle, CardContent } from '@/components/ui/card'
import type { FinancialImpactLine, IncidentRecord } from '@/types'

type Props = { incident: IncidentRecord; scope: 'window' | 'history' }
const labels: Record<string, string> = { charge: 'Charged', refund: 'Refunded', payout: 'Paid out', messaging: 'Messaging and calls' }
const countLabels: Record<string, [string, string]> = { charge: ['transaction', 'transactions'], refund: ['refund', 'refunds'], payout: ['payout', 'payouts'] }
const units: Record<string, string> = { hour: '/hr', day: '/day', month: '/month' }
function money(amount: number, currency: string | null) {
  if (!currency) return amount.toFixed(2)
  try { return new Intl.NumberFormat(undefined, { style: 'currency', currency, maximumFractionDigits: 2 }).format(amount) }
  catch { return `${amount.toFixed(2)} ${currency}` }
}
function Figure({ line }: { line: FinancialImpactLine }) {
  const title = labels[line.kind] ?? line.label
  const count = line.quantity != null && countLabels[line.kind] ? `${line.quantity} ${countLabels[line.kind][line.quantity === 1 ? 0 : 1]}` : null
  return <div className="finance-row"><div><strong>{title}</strong><span>{line.actual ? 'Provider reported' : 'Estimate'}{count ? ` · ${count}` : ''}</span></div><div className="finance-value">{line.amount != null ? <>{money(line.amount, line.currency)}{line.unit && <small>{units[line.unit]}</small>}</> : <span>{line.text}</span>}</div></div>
}
export default function FinancialImpactPanel({ incident, scope }: Props) {
  const lines = scope === 'history' ? incident.financial_history_lines : incident.financial_impact_lines
  const isLegacy = incident.financial_impact_lines === undefined
  const fallback = isLegacy && scope === 'window' ? incident.estimated_financial_impact : null
  const unavailable = lines === undefined && !fallback
  const collecting = ['detecting', 'collecting', 'classifying', 'scoring', 'reporting'].includes(incident.status)
  const failed = incident.status === 'error' || incident.collection_status === 'error'
  return <Card className="forensic-card"><CardHeader className="forensic-card-header"><div className="forensic-card-heading"><span className="forensic-icon"><Banknote size={17}/></span><div><CardTitle>Financial activity</CardTitle><p>{scope === 'window' ? 'Exposure window' : 'All collected history'}</p></div></div></CardHeader><CardContent className="forensic-card-content">
    {fallback && fallback !== 'No financial impact detected' ? <div className="forensic-empty"><Info size={18}/><div><strong>Previous report summary</strong><p>{fallback}</p><p>Its time range cannot be verified here. Update the backend for a current breakdown.</p></div></div> : unavailable ? <div className="forensic-empty"><Info size={18}/><div><strong>Breakdown unavailable</strong><p>Update the backend to calculate financial activity for this time range.</p></div></div> : !lines?.length ? <div className="forensic-empty"><Banknote size={18}/><div><strong>{collecting ? 'Collection in progress' : failed ? 'Financial activity unavailable' : 'No financial activity found'}</strong><p>{collecting ? 'Financial activity will update as collection completes.' : failed ? 'Collection failed, so financial activity could not be assessed.' : 'No amounts were calculated from events in this range. This does not establish that no financial activity occurred.'}</p></div></div> : <><div className="finance-rows">{lines.map((line,index) => <Figure key={`${line.platform}-${line.kind}-${line.currency}-${index}`} line={line}/>)}</div><p className="finance-explanation">{scope === 'history' ? 'All history includes events outside the exposure window; these are context only. ' : ''}Provider-reported amounts reflect account activity, not proof of use by this credential or a financial loss. Estimates are not billing figures.</p></>}
  </CardContent></Card>
}
