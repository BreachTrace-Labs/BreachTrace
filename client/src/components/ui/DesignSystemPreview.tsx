import { useState } from 'react'
import { Button } from './button'
import { Badge } from './badge'
import { Input } from './input'
import { Modal, SlideOver } from './overlay'
import { Spinner } from './spinner'
import { EmptyState } from './empty-state'
import { CodeBlock } from './code-block'
import { ProviderIcon } from './provider-icon'
import { Tabs } from './tabs'
import { useToast } from './toast'
import { Card, CardContent, CardHeader, CardTitle } from './card'
import { Tooltip, TooltipContent, TooltipTrigger } from './tooltip'
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from './table'
import SeverityBadge from '../SeverityBadge'

export default function DesignSystemPreview() {
  const [modal, setModal] = useState(false); const [side, setSide] = useState(false); const [tab, setTab] = useState('one'); const { toast } = useToast()
  return <main className="ui-preview"><h1>Design system preview</h1><p>Local component states for review.</p>
    <Card><CardHeader><CardTitle>Buttons and badges</CardTitle></CardHeader><CardContent><div className="ui-preview-row">{(['primary', 'secondary', 'ghost', 'danger'] as const).map(v => <Button key={v} variant={v}>{v}</Button>)}<Button loading>Loading</Button><Button disabled>Disabled</Button></div><div className="ui-preview-row">{(['critical', 'high', 'medium', 'low', 'neutral', 'success', 'warning'] as const).map(v => <Badge key={v} variant={v}>{v}</Badge>)}<SeverityBadge severity="HIGH" showIcon={false}/></div></CardContent></Card>
    <Card><CardHeader><CardTitle>Fields and feedback</CardTitle></CardHeader><CardContent><div className="ui-preview-grid"><Input label="Repository" hint="A GitHub URL" placeholder="https://github.com/owner/repo"/><Input label="Email" error="Enter a valid email" defaultValue="invalid"/></div><div className="ui-preview-row"><Spinner size="sm"/><Spinner/><Button onClick={() => toast('Changes saved', 'success')}>Success toast</Button><Button onClick={() => toast('Could not save changes', 'error')}>Error toast</Button><Tooltip delayDuration={300}><TooltipTrigger asChild><Button variant="outline">Hover for tooltip</Button></TooltipTrigger><TooltipContent sideOffset={10}>More information</TooltipContent></Tooltip></div></CardContent></Card>
    <Card><CardHeader><CardTitle>Data and navigation</CardTitle></CardHeader><CardContent><Tabs label="Example tabs" value={tab} onChange={setTab} items={[{value:'one',label:'Overview'},{value:'two',label:'Details'}]}/><p>Selected: {tab}</p><div className="ui-preview-row">{['aws','gcp','azure','stripe','twilio'].map(p => <ProviderIcon key={p} provider={p}/>)}</div><CodeBlock value="AKIA••••••••WXYZ"/><Table><TableHeader><TableRow><TableHead>Provider</TableHead><TableHead>Status</TableHead></TableRow></TableHeader><TableBody><TableRow><TableCell>AWS</TableCell><TableCell>Connected</TableCell></TableRow></TableBody></Table></CardContent></Card>
    <Card><CardContent><EmptyState title="No incidents yet" description="New findings will appear here." action={<Button>Run a scan</Button>}/><div className="ui-preview-row"><Button onClick={() => setModal(true)}>Open modal</Button><Button onClick={() => setSide(true)}>Open slide-over</Button></div></CardContent></Card>
    <Modal open={modal} title="Example modal" onClose={() => setModal(false)} footer={<Button onClick={() => setModal(false)}>Done</Button>}><p>Dialog content.</p></Modal><SlideOver open={side} title="Example slide-over" onClose={() => setSide(false)} footer={<Button onClick={() => setSide(false)}>Done</Button>}><Input label="Name"/></SlideOver>
  </main>
}
