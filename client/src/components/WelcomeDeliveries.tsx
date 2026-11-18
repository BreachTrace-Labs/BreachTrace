import { useCallback, useEffect, useState } from 'react'
import { realClient } from '@/api/client'
import { Button } from '@/components/ui/button'

type Delivery = { id: string; user_id: string; status: string; outcome: string | null; attempts: number; max_attempts: number; last_error: string | null; can_retry: boolean }

export default function WelcomeDeliveries() {
  const [items, setItems] = useState<Delivery[]>([])
  const [error, setError] = useState('')
  const load = useCallback(async () => {
    try { const { data } = await realClient.get<Delivery[]>('/org/notification-deliveries'); setItems(data); setError('') }
    catch { setError('Could not load welcome email delivery status.') }
  }, [])
  useEffect(() => { void load(); const timer = window.setInterval(() => { void load() }, 5000); return () => window.clearInterval(timer) }, [load])
  async function retry(id: string) {
    try { await realClient.post(`/org/notification-deliveries/${id}/retry`); await load() }
    catch { setError('Could not retry the welcome email. It may have expired.') }
  }
  return <section className="rounded-lg border bg-card p-5 space-y-3"><h2 className="font-semibold">Welcome email deliveries</h2>
    {error && <p role="alert" className="text-sm text-red-500">{error}</p>}
    {!items.length && <p className="text-sm text-muted-foreground">No welcome emails queued.</p>}
    {items.map(item => <div key={item.id} className="border rounded p-3 text-sm space-y-1">
      <div className="flex flex-wrap gap-2 justify-between"><span>User {item.user_id} · {item.status === 'complete' ? item.outcome ?? 'complete' : item.status} · Attempt {item.attempts}/{item.max_attempts}</span>
        {item.can_retry && <Button size="sm" variant="outline" onClick={() => void retry(item.id)}>Retry</Button>}</div>
      {item.last_error && <p className="text-xs text-muted-foreground">{item.last_error}</p>}
    </div>)}
  </section>
}
