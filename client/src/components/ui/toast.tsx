import { createContext, useCallback, useContext, useEffect, useRef, useState, type ReactNode } from 'react'
import './system.css'
type Variant = 'success' | 'error' | 'warning' | 'info'
type Toast = { id: number; message: string; variant: Variant }
type Context = { toast: (message: string, variant?: Variant) => void }
const ToastContext = createContext<Context | null>(null)
export function ToastProvider({ children }: { children: ReactNode }) {
  const [items, setItems] = useState<Toast[]>([]); const counter = useRef(0); const timers = useRef(new Map<number, ReturnType<typeof setTimeout>>())
  const dismiss = useCallback((id: number) => { clearTimeout(timers.current.get(id)); timers.current.delete(id); setItems(current => current.filter(item => item.id !== id)) }, [])
  const toast = useCallback((message: string, variant: Variant = 'info') => { const id = ++counter.current; setItems(current => [...current, { id, message, variant }].slice(-4)); timers.current.set(id, setTimeout(() => dismiss(id), 4000)) }, [dismiss])
  useEffect(() => { const active = timers.current; return () => { active.forEach(clearTimeout); active.clear() } }, [])
  return <ToastContext.Provider value={{ toast }}>{children}<div className="ui-toasts" aria-live="polite">{items.map(item => <div key={item.id} className={`ui-toast ui-toast--${item.variant}`}><span>{item.message}</span><button type="button" aria-label="Dismiss notification" onClick={() => dismiss(item.id)}>×</button></div>)}</div></ToastContext.Provider>
}
// The provider and hook share a private context.
// eslint-disable-next-line react-refresh/only-export-components
export function useToast() { const context = useContext(ToastContext); if (!context) throw new Error('useToast requires ToastProvider'); return context }
