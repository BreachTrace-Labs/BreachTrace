import './system.css'
const names: Record<string, string> = { aws: 'AWS', gcp: 'GCP', azure: 'Azure', stripe: 'Stripe', twilio: 'Twilio' }
export function ProviderIcon({ provider }: { provider: string }) { const key = provider.toLowerCase(); return <span className="ui-provider"><span className={`ui-provider-dot ui-provider-dot--${names[key] ? key : 'other'}`}/>{names[key] ?? provider}</span> }
