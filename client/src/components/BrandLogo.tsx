import { useId, type SVGProps } from 'react'
import './brand-logo.css'

/** Shared mark: the scan continues through the open right edge to the detection dot. */
export function BrandMark(props: SVGProps<SVGSVGElement>) {
  const shieldClip = useId()
  const shieldGradient = useId()
  return <svg viewBox="0 0 64 56" fill="none" aria-hidden="true" focusable="false" {...props}>
    <defs><linearGradient id={shieldGradient} x1="11" y1="5" x2="47" y2="50" gradientUnits="userSpaceOnUse"><stop stopColor="#a3b7ff" /><stop offset=".48" stopColor="#5b7fff" /><stop offset="1" stopColor="#3656c9" /></linearGradient><mask id={shieldClip}><path d="M47 22V12L29 5 11 12v12c0 12 7 20 18 26 10-5 16-12 18-20" fill="none" stroke="white" strokeWidth="3.5" strokeLinejoin="round" /></mask></defs>
    <path d="M47 22V12L29 5 11 12v12c0 12 7 20 18 26 10-5 16-12 18-20" transform="translate(1 1.4)" stroke="#28429e" strokeWidth="4" strokeLinejoin="round" />
    <path d="M47 22V12L29 5 11 12v12c0 12 7 20 18 26 10-5 16-12 18-20" stroke={`url(#${shieldGradient})`} strokeWidth="3.5" strokeLinejoin="round" />
    <g mask={`url(#${shieldClip})`}><path className="brand-logo__shine" d="M-24 0h7L-3 56h-7z" fill="white" /></g>
    <path d="M2 26h51" stroke="currentColor" strokeWidth="3" strokeLinecap="round" />
    <circle className="brand-logo__glow" cx="56" cy="26" r="6" fill="currentColor" />
    <circle className="brand-logo__dot" cx="56" cy="26" r="4" fill="#fff" stroke="currentColor" strokeWidth="3" />
  </svg>
}

export function BrandLogo({ variant = 'horizontal', className = '' }: { variant?: 'horizontal' | 'stacked' | 'mark'; className?: string }) {
  return <span className={`brand-logo brand-logo--${variant} ${className}`} role="img" aria-label="BreachTrace">
    <BrandMark className="brand-logo__mark" />
    {variant !== 'mark' && <span className="brand-logo__wordmark"><span>Breach</span><strong>Trace</strong></span>}
  </span>
}
