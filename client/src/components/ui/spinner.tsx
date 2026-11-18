import type { SVGProps } from 'react'
import './system.css'

export function Spinner({ size = 'md', ...props }: SVGProps<SVGSVGElement> & { size?: 'sm' | 'md' }) {
  return <svg className={`ui-spinner ui-spinner--${size}`} viewBox="0 0 24 24" role="status" aria-label="Loading" {...props}><circle cx="12" cy="12" r="9" fill="none" stroke="currentColor" strokeWidth="3" opacity="0.25"/><path d="M12 3a9 9 0 0 1 9 9" fill="none" stroke="currentColor" strokeWidth="3" strokeLinecap="round"/></svg>
}
