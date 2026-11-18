import { useRef } from 'react'
import './system.css'
export function Tabs({ items, value, onChange, label }: { items: { value: string; label: string }[]; value: string; onChange: (value: string) => void; label: string }) {
  const refs = useRef<(HTMLButtonElement | null)[]>([])
  return <div className="ui-tabs" role="tablist" aria-label={label}>{items.map((item, index) => <button key={item.value} ref={el => { refs.current[index] = el }} role="tab" aria-selected={value === item.value} tabIndex={value === item.value ? 0 : -1} onClick={() => onChange(item.value)} onKeyDown={e => { if (e.key !== 'ArrowRight' && e.key !== 'ArrowLeft') return; e.preventDefault(); const next = (index + (e.key === 'ArrowRight' ? 1 : -1) + items.length) % items.length; onChange(items[next].value); refs.current[next]?.focus() }}>{item.label}</button>)}</div>
}
