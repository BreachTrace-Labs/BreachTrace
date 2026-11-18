import { useEffect } from 'react'
import { Link, useLocation } from 'react-router-dom'
import { ArrowLeft, ArrowUpRight, Moon, Sun } from 'lucide-react'
import { BrandLogo } from '@/components/BrandLogo'
import { complianceFrameworks } from '@/data/compliance'
import { useTheme } from '@/lib/theme'
import './regulations.css'

export default function Regulations() {
  const { theme, toggle } = useTheme()
  const { hash } = useLocation()
  useEffect(() => { if (hash) document.getElementById(hash.slice(1))?.scrollIntoView() }, [hash])
  const themeLabel = theme === 'dark' ? 'Switch to light theme' : 'Switch to dark theme'
  return <div className="regulations"><header className="regulations-header"><div><Link to="/" aria-label="BreachTrace home"><BrandLogo /></Link><button type="button" onClick={toggle} aria-label={themeLabel} title={themeLabel}>{theme === 'dark' ? <Sun size={18}/> : <Moon size={18}/>}</button></div></header><main className="regulations-main"><Link to="/" className="regulations-back"><ArrowLeft size={15}/> Back to BreachTrace</Link><p className="regulations-kicker">INCIDENT REVIEW / FRAMEWORKS</p><h1>Regulations and<br/><span>security frameworks.</span></h1><p className="regulations-intro">BreachTrace highlights possible connections between incident evidence and selected regulations or security frameworks. These are prompts for review, not compliance determinations or proof that a law applies.</p><div className="regulations-note"><strong>How to use these signals</strong><p>A candidate may be invalid. Resource names, event classifications and provider logs can be incomplete or ambiguous. Confirm scope and facts with the responsible security, privacy or compliance team.</p></div><section className="regulations-list" aria-label="Frameworks referenced by incident review">{complianceFrameworks.map(item => <article id={item.id} key={item.id}><div className="regulations-item-heading"><div><span>{item.kind}</span><h2>{item.label}</h2><p>{item.title}</p></div><a href={item.url} target="_blank" rel="noopener noreferrer" aria-label={`Read official ${item.label} source (opens in a new tab)`}>Official source <ArrowUpRight size={15}/></a></div><p>{item.description}</p><div className="regulations-trigger"><strong>When BreachTrace suggests review</strong><p>{item.trigger}</p></div></article>)}</section><p className="regulations-bottom">This page describes selected review signals; it does not certify compliance or cover all requirements of these frameworks.</p></main></div>
}
