import { useId, forwardRef, type InputHTMLAttributes, type ReactNode } from 'react'
import './system.css'

type Props = Omit<InputHTMLAttributes<HTMLInputElement>, 'prefix'> & { label: string; hint?: string; error?: string; prefix?: ReactNode; suffix?: ReactNode }
export const Input = forwardRef<HTMLInputElement, Props>(function Input({ label, hint, error, prefix, suffix, id, ...props }, ref) {
  const generated = useId(); const fieldId = id ?? generated; const messageId = `${fieldId}-message`
  return <div className="ui-field"><label htmlFor={fieldId}>{label}</label><div className={`ui-input-wrap${error ? ' ui-input-wrap--error' : ''}`}>{prefix && <span>{prefix}</span>}<input ref={ref} id={fieldId} aria-invalid={!!error} aria-describedby={error || hint ? messageId : undefined} {...props}/>{suffix && <span>{suffix}</span>}</div>{(error || hint) && <div id={messageId} className={error ? 'ui-error' : 'ui-hint'}>{error || hint}</div>}</div>
})
