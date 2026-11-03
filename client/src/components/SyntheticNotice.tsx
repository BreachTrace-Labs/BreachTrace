import { FlaskConical } from 'lucide-react'

export default function SyntheticNotice({ compact = false }: { compact?: boolean }) {
  if (compact) return <span className="inline-flex items-center gap-1 rounded border px-1.5 py-0.5 text-[10px] font-semibold text-muted-foreground"><FlaskConical size={10} />Synthetic demo</span>
  return <div role="note" className="flex items-start gap-3 rounded border border-sky-500/30 bg-sky-500/10 p-4 text-sm">
    <FlaskConical size={18} className="mt-0.5 shrink-0" />
    <div><p className="font-semibold">Synthetic demo data</p><p className="mt-1 text-muted-foreground">These examples use fabricated credentials. No valid key, provider usage or real breach is represented. Demo data is for UI testing, not research measurements.</p></div>
  </div>
}
