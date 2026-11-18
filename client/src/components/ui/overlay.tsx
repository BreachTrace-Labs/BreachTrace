import { useEffect, useId, useRef, type ReactNode } from 'react'
import { createPortal } from 'react-dom'
import './system.css'

type Props = { open: boolean; title: string; onClose: () => void; preventClose?: boolean; children: ReactNode; footer?: ReactNode }
function Overlay({ open, title, onClose, preventClose, children, footer, side }: Props & { side?: boolean }) {
  const titleId = useId(); const panel = useRef<HTMLElement>(null)
  const closeRef = useRef(onClose); const preventCloseRef = useRef(preventClose)
  useEffect(() => { closeRef.current = onClose; preventCloseRef.current = preventClose }, [onClose, preventClose])
  useEffect(() => {
    if (!open) return
    const previous = document.activeElement as HTMLElement | null
    panel.current?.focus()
    const key = (e: KeyboardEvent) => {
      if (e.key === 'Escape' && !preventCloseRef.current) closeRef.current()
      if (e.key !== 'Tab') return
      const items = panel.current?.querySelectorAll<HTMLElement>('button:not(:disabled), input:not(:disabled), select:not(:disabled), textarea:not(:disabled), a[href], [tabindex]:not([tabindex="-1"])')
      if (!items?.length) { e.preventDefault(); return }
      const first = items[0], last = items[items.length - 1]
      if (e.shiftKey && (document.activeElement === first || document.activeElement === panel.current)) { e.preventDefault(); last.focus() }
      else if (!e.shiftKey && document.activeElement === last) { e.preventDefault(); first.focus() }
    }
    document.addEventListener('keydown', key)
    return () => { document.removeEventListener('keydown', key); previous?.focus() }
  }, [open])
  if (!open) return null
  return createPortal(<div className={`ui-overlay${side ? ' ui-overlay--side' : ''}`} onMouseDown={e => { if (e.target === e.currentTarget && !preventClose) onClose() }}><section ref={panel} tabIndex={-1} role="dialog" aria-modal="true" aria-labelledby={titleId} className="ui-dialog"><header className="ui-dialog-header"><h2 id={titleId}>{title}</h2><button type="button" aria-label="Close" onClick={onClose} disabled={preventClose}>×</button></header><div className="ui-dialog-body">{children}</div>{footer && <footer className="ui-dialog-footer">{footer}</footer>}</section></div>, document.body)
}
export function Modal(props: Props) { return <Overlay {...props}/> }
export function SlideOver(props: Props) { return <Overlay {...props} side/> }
