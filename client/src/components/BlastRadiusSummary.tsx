import { Activity, ChevronDown, ShieldAlert } from 'lucide-react'
import type { IncidentRecord } from '../types'
import { PLATFORM_META, type Platform } from '@/lib/platform'
import { Card, CardHeader, CardTitle, CardContent } from '@/components/ui/card'
import SeverityBadge from './SeverityBadge'
import { USE_MOCK } from '@/api/client'
import { previewBlastRadius } from '@/lib/forensicEvidence'

const messages = {
  unavailable: 'Activity has not been assessed for this finding.',
  collecting: 'Collection is in progress. This assessment may change.',
  error: 'Collection failed. Available activity may be incomplete.',
  no_observed_activity: 'No activity was observed in the available collection.',
  observed: 'Activity recorded during the exposure window.',
}

export default function BlastRadiusSummary({ incident }: { incident: IncidentRecord }) {
  const assessment = incident.dynamic_blast_radius ?? (USE_MOCK ? previewBlastRadius(incident) : null)
  return <Card className="forensic-card"><CardHeader className="forensic-card-header"><div className="forensic-card-heading"><span className="forensic-icon"><Activity size={17}/></span><div><CardTitle>Dynamic blast radius</CardTitle><p>Based on exposure-window events</p></div></div><SeverityBadge severity={assessment?.severity ?? null} /></CardHeader><CardContent className="forensic-card-content">
    {!assessment ? <div className="forensic-empty"><ShieldAlert size={18}/><div><strong>Assessment unavailable</strong><p>Restart or update the backend, then reload this incident.</p></div></div> : <>
      {(assessment.event_count > 0 || assessment.status !== 'no_observed_activity') && <p className="forensic-status">{messages[assessment.status]}{USE_MOCK && ' Synthetic preview data.'}</p>}
      {assessment.event_count > 0 ? <><div className="forensic-metrics" aria-label="Blast radius totals"><div><strong>{assessment.successful_count}</strong><span>Successful</span></div><div><strong>{assessment.failed_count}</strong><span>Failed</span></div><div><strong>{assessment.resource_count}</strong><span>Named resources</span></div></div>
        {assessment.platforms.map(platform => <section key={platform.platform} className="forensic-platform"><div className="forensic-platform-title"><strong>{PLATFORM_META[platform.platform as Platform]?.label ?? platform.platform}</strong><span>{platform.event_count} {platform.event_count === 1 ? 'event' : 'events'}</span></div>
          {platform.categories.length > 0 && <div className="forensic-tags">{platform.categories.map(item => <span key={item.category}>{item.category.replace(/_/g, ' ')} <b>{item.count}</b></span>)}</div>}
          {platform.actions.length > 0 && <details className="forensic-details"><summary>View successful actions <ChevronDown size={15}/></summary><ul>{platform.actions.map(action => <li key={action.action}><span>{action.action}</span><b>{action.count}</b></li>)}</ul></details>}
        </section>)}
        {assessment.last_observed_at && <p className="forensic-meta">Latest recorded event · {new Date(assessment.last_observed_at).toLocaleString()}</p>}
      </> : <div className="forensic-empty"><ShieldAlert size={18}/><div><strong>{assessment.status === 'no_observed_activity' ? 'No activity observed' : 'No activity to summarise'}</strong><p>{assessment.status === 'no_observed_activity' ? 'Available logs do not establish that no activity occurred.' : 'The assessment will update when eligible events are available.'}</p></div></div>}
      <details className="forensic-details forensic-notes"><summary>How to interpret this <ChevronDown size={15}/></summary><p>The window starts at the estimated commit exposure time and ends at the recorded end, if present; an end does not independently confirm revocation. The score uses successful classified events, not a complete list of permissions. Failed events are counted separately. Account or identity activity may not be attributable to this key. Provider collection may require a refresh; this view can differ from the last generated report.</p></details>
    </>}
  </CardContent></Card>
}
