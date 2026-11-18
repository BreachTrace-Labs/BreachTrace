import { Link } from 'react-router-dom'
import { ShieldCheck, ArrowRight } from 'lucide-react'
import { complianceFrameworks } from '@/data/compliance'
import { USE_MOCK } from '@/api/client'
import type { IncidentRecord } from '@/types'

export default function ComplianceReview({ incident }: { incident: IncidentRecord }) {
  const flags = incident.compliance_review_flags ?? (USE_MOCK && incident.credential_type ? [{ id: 'owasp-nhi2', reason: 'A synthetic credential candidate is shown. Review whether it represents a non-human identity secret.' }] : null)
  return <section className="compliance-review" aria-labelledby="compliance-review-title"><div className="compliance-review-heading"><div><span className="compliance-review-icon"><ShieldCheck size={18}/></span><div><h2 id="compliance-review-title">Regulatory & framework review</h2><p>Potential relevance based on this incident’s evidence</p></div></div><Link to="/regulations">How flags work <ArrowRight size={15}/></Link></div>
    <p className="compliance-review-caveat">Review signals are not proof that a framework applies, a breach occurred, or a control failed.{USE_MOCK ? ' Preview data is synthetic.' : ''}</p>
    {!flags ? <p className="compliance-review-empty">Review signals are unavailable from this backend. Restart or update it to load the assessment.</p> : flags.length === 0 ? <p className="compliance-review-empty">No review signals were identified from the available evidence. This does not establish that no obligations apply.</p> : <div className="compliance-review-flags">{flags.map(flag => { const framework = complianceFrameworks.find(item => item.id === flag.id); return <article key={flag.id}><div><span>REVIEW</span><Link to={`/regulations#${flag.id}`}>{framework?.label ?? 'Framework review'} <ArrowRight size={13}/></Link></div><p>{flag.reason}</p></article> })}</div>}
  </section>
}
