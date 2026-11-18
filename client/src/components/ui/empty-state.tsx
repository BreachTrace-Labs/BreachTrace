import type { ReactNode } from 'react'
import './system.css'
export function EmptyState({ icon, title, description, action }: { icon?: ReactNode; title: string; description: ReactNode; action?: ReactNode }) { return <div className="ui-empty">{icon}<h3>{title}</h3><p>{description}</p>{action}</div> }
