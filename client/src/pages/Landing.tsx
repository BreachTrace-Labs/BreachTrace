import { useCallback, useEffect, useRef, useState, type CSSProperties, type KeyboardEvent, type MouseEvent } from 'react'
import { Link } from 'react-router-dom'
import { AnimatePresence, motion, useInView, useReducedMotion } from 'framer-motion'
import { gsap } from 'gsap'
import { ScrollTrigger } from 'gsap/ScrollTrigger'
import Lenis from 'lenis'
import { Activity, ArrowDown, ArrowRight, ArrowUpRight, CheckCircle2, ChevronDown, Crosshair, FileText, Fingerprint, KeyRound, Layers3, LockKeyhole, Menu, Moon, Radar, Search, Shield, ShieldCheck, Sun, Users, X } from 'lucide-react'
import { LANDING } from './landing-content'
import { useAuth } from '@/context/AuthContext'
import { useTheme } from '@/lib/theme'
import { BrandLogo } from '@/components/BrandLogo'
import './landing.css'

gsap.registerPlugin(ScrollTrigger)
const ENTER = [0.22, 1, 0.36, 1] as const
const groups = {
  Platform: [{ title: 'Capabilities', links: ['Detect exposure', 'Investigate activity', 'Coordinate response'] }, { title: 'Tools & integrations', links: ['Repository scans', 'Provider activity', 'Incident reports'] }],
  Solutions: [{ title: 'By problem', links: ['Exposed credentials', 'Incident investigation', 'Response workflows'] }, { title: 'By team', links: ['Developers', 'Security teams', 'Incident responders'] }],
  Resources: [{ title: 'Explore', links: ['Product overview', 'Investigation workflow', 'Frequently asked questions'] }, { title: 'Learn', links: ['Getting started', 'Incident reports', 'Provider coverage'] }],
  About: [{ title: 'BreachTrace', links: ['Our approach', 'Detection workflows', 'Forensic tiers'] }, { title: 'In the app', links: ['Incident monitor', 'Search', 'Connect a repository'] }],
} as const
const menuNames = ['Platform', 'Solutions', 'Workflow', 'Resources', 'About'] as const
type MenuName = keyof typeof groups
const featureRows = [
  { id: 'detect', tab: 'Detect', audience: 'DEVELOPERS', title: 'Find the signal in your code.', text: 'Bring exposed credentials into focus with clear context and a starting point for investigation.', bullets: ['Review the affected repository', 'Identify the credential family', 'Understand the exposure window'], icon: Search },
  { id: 'remediate', tab: 'Investigate', audience: 'SECURITY TEAMS', title: 'Turn context into a response.', text: 'Bring investigation details and the people responding together in one shared workflow.', bullets: ['Follow available activity', 'Assign an incident owner', 'Record response decisions'], icon: Crosshair },
  { id: 'prevent', tab: 'Respond', audience: 'PROJECT TEAMS', title: 'Build a clearer picture over time.', text: 'Use investigation findings to understand patterns and inform the next conversation.', bullets: ['Review incident history', 'Keep a record of decisions', 'Share a grounded summary'], icon: ShieldCheck },
] as const
const menuDestinations: Record<string, string> = {
  'Detect exposure': '#detect', 'Investigate activity': '#remediate', 'Coordinate response': '#prevent',
  'Repository scans': '/connect', 'Provider activity': '#integrations', 'Incident reports': '#resources',
  'Exposed credentials': '#detect', 'Incident investigation': '#remediate', 'Response workflows': '#pipeline',
  'Developers': '#detect', 'Security teams': '#remediate', 'Incident responders': '#prevent',
  'Product overview': '#platform', 'Investigation workflow': '#pipeline', 'Frequently asked questions': '#faq',
  'Getting started': '#get-started', 'Provider coverage': '#integrations', 'Our approach': '#platform',
  'Detection workflows': '#detect', 'Forensic tiers': '#insights', 'Incident monitor': '/dashboard',
  'Search': '/search', 'Connect a repository': '/connect',
}
const faqItems = [
  { q: 'Where do I start?', a: 'Create a project and scan a GitHub repository’s current default branch, or register a webhook to monitor future pushes.' },
  { q: 'What context can I review?', a: 'Incidents include a masked credential hint, repository and commit details, an exposure window, and available provider activity.' },
  { q: 'How do teams coordinate?', a: 'Project members can review incidents and document dismissals. Security leads and admins can assign incidents and review their audit history.' },
  { q: 'Which systems are supported?', a: 'BreachTrace detects multiple credential families and has collectors for AWS, Google Cloud, Azure, Stripe, and Twilio. Collection depends on provider access and available evidence.' },
  { q: 'Does scanning a repository create an incident?', a: 'A snapshot scan reports candidates separately. Monitor incidents are created when a qualifying credential is found in a new signed GitHub push.' },
]
const pipeline = [{ label: 'Detect', desc: 'Find exposed credentials', icon: Radar }, { label: 'Investigate', desc: 'Collect available evidence', icon: Fingerprint }, { label: 'Respond', desc: 'Assign and review the incident', icon: KeyRound }, { label: 'Document', desc: 'Record the outcome', icon: ShieldCheck }]

function Reveal({ children, className = '', delay = 0 }: { children: React.ReactNode; className?: string; delay?: number }) {
  const reduced = useReducedMotion()
  return <motion.div className={className} initial={reduced ? false : { opacity: 0, y: 24 }} whileInView={{ opacity: 1, y: 0 }} viewport={{ once: true, margin: '-10% 0px -10% 0px' }} transition={{ duration: .7, delay, ease: ENTER }}>{children}</motion.div>
}
function ArrowLink({ href, children }: { href: string; children: React.ReactNode }) { return <a className="lp-text-link" href={href}>{children}<ArrowRight size={16} aria-hidden="true" /></a> }
function Brand() { return <a href="#top" className="lp-brand" aria-label={`${LANDING.product} home`}><BrandLogo /></a> }

function Header() {
  const { user } = useAuth()
  const { theme, toggle } = useTheme()
  const [open, setOpen] = useState<MenuName | null>(null)
  const [drawer, setDrawer] = useState(false)
  const [scrolled, setScrolled] = useState(false)
  const [hidden, setHidden] = useState(false)
  const closeTimer = useRef<number | undefined>(undefined)
  useEffect(() => {
    let previous = window.scrollY
    const onScroll = () => { const current = window.scrollY; setScrolled(current > 40); setHidden(current > 180 && current > previous + 3); previous = current }
    window.addEventListener('scroll', onScroll, { passive: true })
    return () => { window.removeEventListener('scroll', onScroll); window.clearTimeout(closeTimer.current) }
  }, [])
  useEffect(() => {
    const onKey = (event: globalThis.KeyboardEvent) => { if (event.key === 'Escape') { setOpen(null); setDrawer(false) } }
    document.addEventListener('keydown', onKey)
    return () => document.removeEventListener('keydown', onKey)
  }, [])
  function openMenu(name: MenuName) { window.clearTimeout(closeTimer.current); setOpen(name) }
  function closeMenu() { closeTimer.current = window.setTimeout(() => setOpen(null), 150) }
  function navKeys(event: KeyboardEvent<HTMLElement>) {
    if (event.key !== 'ArrowRight' && event.key !== 'ArrowLeft') return
    const items = Array.from(event.currentTarget.querySelectorAll<HTMLElement>('[data-menu-trigger]'))
    const index = items.indexOf(document.activeElement as HTMLElement)
    if (index < 0) return
    event.preventDefault()
    items[(index + (event.key === 'ArrowRight' ? 1 : -1) + items.length) % items.length].focus()
  }
  function menuKeys(event: KeyboardEvent<HTMLElement>) {
    if (event.key === 'Escape') {
      event.preventDefault()
      const trigger = document.querySelector<HTMLElement>('[data-menu-trigger][aria-expanded="true"]')
      setOpen(null)
      trigger?.focus()
      return
    }
    if (!['ArrowDown', 'ArrowUp', 'Home', 'End'].includes(event.key)) return
    const links = Array.from(event.currentTarget.querySelectorAll<HTMLAnchorElement>('a[href]'))
    if (!links.length) return
    event.preventDefault()
    const index = links.indexOf(document.activeElement as HTMLAnchorElement)
    const next = event.key === 'Home' ? 0 : event.key === 'End' ? links.length - 1 : (index + (event.key === 'ArrowDown' ? 1 : -1) + links.length) % links.length
    links[next].focus()
  }
  return <header className={`lp-header ${scrolled ? 'is-scrolled' : ''} ${hidden && !drawer && !open ? 'is-hidden' : ''}`} onMouseLeave={closeMenu}>
    <div className="lp-promo"><a href="#platform"><span><i /> {LANDING.program}</span> Explore the platform <ArrowRight size={13} /></a></div>
    <div className="lp-nav-inner"><Brand /><nav className="lp-desktop-nav" aria-label="Main navigation" onKeyDown={navKeys}>{menuNames.map(name => name === 'Workflow' ? <a key={name} href="#pipeline">{name}</a> : <div key={name} onMouseEnter={() => openMenu(name)}><button data-menu-trigger type="button" aria-expanded={open === name} aria-controls={`mega-${name}`} onClick={() => setOpen(open === name ? null : name)}>{name}<ChevronDown className={open === name ? 'turned' : ''} size={15} /></button></div>)}</nav>
      <div className="lp-header-actions"><button type="button" className="lp-theme-toggle" onClick={toggle} aria-label={theme === 'dark' ? 'Switch to light theme' : 'Switch to dark theme'} title={theme === 'dark' ? 'Switch to light theme' : 'Switch to dark theme'}>{theme === 'dark' ? <Sun size={18}/> : <Moon size={18}/>}</button><Link to={user ? "/dashboard" : "/login"}>{user ? "Dashboard" : "Sign in"}</Link><Link className="lp-nav-button" to="/dashboard">{LANDING.primaryCta}<ArrowRight size={14} /></Link></div><button className="lp-menu-button" aria-label={drawer ? 'Close navigation' : 'Open navigation'} aria-expanded={drawer} aria-controls="mobile-navigation" onClick={() => { setDrawer(!drawer); setOpen(null) }}>{drawer ? <X size={23} /> : <Menu size={23} />}</button>
    </div>
    <AnimatePresence>{open && !drawer && <motion.div id={`mega-${open}`} className="lp-mega" onKeyDown={menuKeys} onMouseEnter={() => window.clearTimeout(closeTimer.current)} onMouseLeave={closeMenu} initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }} exit={{ opacity: 0, y: 8 }} transition={{ duration: .18 }}><div className="lp-mega-inner">{groups[open].map(group => <div className="lp-mega-group" key={group.title}><strong>{group.title}</strong>{group.links.map((link, i) => <motion.a key={link} href={menuDestinations[link] ?? "#resources"} onClick={() => setOpen(null)} initial={{ opacity: 0, y: 4 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: i * .02 }}><span>{link}</span><ArrowUpRight size={14} /></motion.a>)}</div>)}<a className="lp-mega-feature" href="#pipeline" onClick={() => setOpen(null)}><span>FEATURED GUIDE</span><strong>From signal to response</strong><p>See how detection becomes an investigation.</p><small>Explore the overview <ArrowRight size={14} /></small></a><div className="lp-mega-tour"><Layers3 size={26} /><strong>See it in action</strong><span>Follow the investigation workflow.</span><a href="#platform" onClick={() => setOpen(null)}>Explore <ArrowRight size={13} /></a></div></div></motion.div>}</AnimatePresence>
    {drawer && <div className="lp-mobile-drawer" id="mobile-navigation"><nav aria-label="Mobile navigation">{menuNames.map(name => name === 'Workflow' ? <a key={name} href="#pipeline" onClick={() => setDrawer(false)}>Workflow</a> : <div className="lp-mobile-section" key={name}><button aria-expanded={open === name} onClick={() => setOpen(open === name ? null : name)}>{name}<ChevronDown className={open === name ? 'turned' : ''} size={17} /></button>{open === name && <div className="lp-mobile-links">{groups[name].flatMap(group => group.links).map(link => <a href={menuDestinations[link] ?? "#resources"} key={link} onClick={() => { setDrawer(false); setOpen(null) }}>{link}</a>)}</div>}</div>)}<Link to={user ? "/dashboard" : "/login"} onClick={() => setDrawer(false)}>{user ? "Dashboard" : "Sign in"}</Link><Link className="lp-button lp-button-primary" to="/dashboard" onClick={() => setDrawer(false)}>{LANDING.primaryCta}<ArrowRight size={15} /></Link></nav></div>}
  </header>
}

function Perimeter() {
  const nodes = [[155,100],[290,78],[424,118],[110,200],[242,177],[368,215],[480,215],[150,300],[290,280],[429,300]]
  return <div className="lp-orbit-wrap" aria-label="Illustrative animated network diagram"><svg viewBox="0 0 590 390" role="img" aria-labelledby="orbit-title"><title id="orbit-title">Illustrative perimeter with connected nodes</title><defs><radialGradient id="orbit-glow"><stop stopColor="var(--lp-accent)" stopOpacity=".26"/><stop offset="1" stopColor="var(--lp-accent)" stopOpacity="0"/></radialGradient><linearGradient id="orbit-line"><stop stopColor="#ababab" stopOpacity=".05"/><stop offset=".5" stopColor="#bcbcbc" stopOpacity=".8"/><stop offset="1" stopColor="#ababab" stopOpacity=".05"/></linearGradient></defs><ellipse cx="295" cy="210" rx="285" ry="180" fill="url(#orbit-glow)"/><ellipse className="lp-orbit-ring" cx="295" cy="195" rx="238" ry="151" fill="none" stroke="url(#orbit-line)"/><ellipse cx="295" cy="195" rx="190" ry="118" fill="none" stroke="#979797" strokeOpacity=".16" strokeDasharray="3 7"/><path className="lp-network-path" d="M155 100 L242 177 L290 78 L368 215 L424 118 M110 200 L242 177 L150 300 L290 280 L368 215 L480 215 M242 177 L290 280 L429 300 L368 215" fill="none" stroke="#a8a8a8" strokeOpacity=".43"/>{nodes.map(([x,y], index) => <g className={`lp-orbit-node ${index === 6 ? 'compromised' : ''}`} key={`${x}-${y}`} style={{ animationDelay: `${index * .18}s` }}><circle cx={x} cy={y} r="10" fill="#999999" opacity=".12"/><circle cx={x} cy={y} r="4" fill={index === 6 ? '#ff866e' : '#bfbfbf'} />{index === 6 && <circle className="lp-node-ripple" cx={x} cy={y} r="10" fill="none" stroke="#ff866e" />}</g>)}<circle cx="295" cy="195" r="33" fill="#1e1e1e" stroke="#848484" strokeOpacity=".7"/><path d="M295 174 l17 7 v12 c0 13 -7 20 -17 24 -10 -4 -17 -11 -17 -24 v-12z" fill="none" stroke="#e2e2e2" strokeWidth="2"/><path d="M288 195 l5 5 10 -11" fill="none" stroke="#b0b0b0" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"/></svg><div className="lp-orbit-label lp-orbit-label-a"><i /> CREDENTIAL DETECTED</div><div className="lp-orbit-label lp-orbit-label-b">INVESTIGATION IN PROGRESS</div></div>
}
function Counter({ value, suffix = '' }: { value: number; suffix?: string }) {
  const ref = useRef<HTMLSpanElement>(null); const visible = useInView(ref, { once: true, margin: '-10%' }); const reduced = useReducedMotion(); const [number, setNumber] = useState(0)
  useEffect(() => { if (!visible) return; if (reduced) { const id = requestAnimationFrame(() => setNumber(value)); return () => cancelAnimationFrame(id) } let frame = 0; const start = performance.now(); const tick = (now: number) => { const t = Math.min((now - start) / 1600, 1); setNumber(value * (1 - Math.pow(2, -10 * t))); if (t < 1) frame = requestAnimationFrame(tick); else setNumber(value) }; frame = requestAnimationFrame(tick); return () => cancelAnimationFrame(frame) }, [visible, value, reduced])
  return <span ref={ref}>{Number.isInteger(value) ? Math.round(number) : number.toFixed(1)}<em>{suffix}</em></span>
}
function glow(event: MouseEvent<HTMLElement>) { if (!window.matchMedia('(hover: hover) and (pointer: fine)').matches) return; const rect = event.currentTarget.getBoundingClientRect(); event.currentTarget.style.setProperty('--mouse-x', `${event.clientX - rect.left}px`); event.currentTarget.style.setProperty('--mouse-y', `${event.clientY - rect.top}px`) }
function Mockup({ index }: { index: number }) { return <div className="lp-mock"><div className="lp-mock-top"><div className="lp-mock-mark"><Shield size={12} /></div><span>BREACHTRACE</span><ChevronDown size={12}/><span className="lp-mock-crumb"> / &nbsp; {featureRows[index].tab} &nbsp; / &nbsp; Overview</span><span className="lp-mock-demo">EXAMPLE DATA</span></div><div className="lp-mock-body"><div className="lp-mock-sidebar"><span><Activity size={13}/> Overview</span><span className="active"><Layers3 size={13}/> Incidents</span><span><Users size={13}/> Teams</span><span><FileText size={13}/> Reports</span></div><div className="lp-mock-content"><div className="lp-mock-title"><div><span>WORKSPACE / INCIDENTS</span><h4>{index === 0 ? 'Detected signals' : index === 1 ? 'Investigation queue' : 'Response overview'}</h4></div><b>Monitor</b></div><div className="lp-mock-filters"><span>All incidents</span><span>Open</span><span>Assigned</span><i>•••</i></div><div className="lp-mock-table"><div className="lp-mock-row lp-mock-table-head"><span>INCIDENT</span><span>PRIORITY</span><span>OWNER</span><span>STATUS</span></div>{['Credential exposure','Suspicious activity','Repository signal','Investigation review'].map((row, n) => <motion.div className="lp-mock-row" key={row} initial={{ opacity: 0, x: 12 }} whileInView={{ opacity: 1, x: 0 }} viewport={{ once: true }} transition={{ duration: .45, delay: n * .06 }}><span><i className={`lp-table-icon type-${n}`}><KeyRound size={12}/></i><strong>{row}<small>INC-00{n+1}</small></strong></span><span><b className={`lp-severity sev-${n}`}>{n === 0 ? 'HIGH' : n === 1 ? 'MEDIUM' : 'LOW'}</b></span><span><i className={`lp-mock-avatar type-${n}`}>{['A','M','S','J'][n]}</i></span><span><b className="lp-mock-status" aria-label="Example status"><span className="lp-status-open">Open</span><span className="lp-status-resolved">Resolved</span></b></span></motion.div>)}</div></div></div></div> }

function FeatureSection() {
  const [active, setActive] = useState('detect'); const [faq, setFaq] = useState<number | null>(0)
  useEffect(() => { const elements = featureRows.map(row => document.getElementById(row.id)).filter((item): item is HTMLElement => Boolean(item)); const observer = new IntersectionObserver(entries => entries.forEach(entry => { if (entry.isIntersecting) setActive(entry.target.id) }), { rootMargin: '-25% 0px -55% 0px' }); elements.forEach(element => observer.observe(element)); return () => observer.disconnect() }, [])
  return <section className="lp-platform-section lp-section" id="platform"><Reveal className="lp-center"><div className="lp-eyebrow"><Layers3 size={15}/> {LANDING.product} PLATFORM</div><h2>The credential<br/><span>security platform.</span></h2><p className="lp-section-intro">Find exposed credentials, review available evidence, and keep your team aligned on the response.</p><div className="lp-platform-tabs" aria-label="Platform sections">{featureRows.map(row => <a href={`#${row.id}`} className={active === row.id ? 'active' : ''} onClick={() => setActive(row.id)} key={row.id}>{active === row.id && <motion.span layoutId="active-platform-tab" className="lp-tab-bg" transition={{ type: 'spring', stiffness: 400, damping: 35 }}/>}<span>{row.tab}</span></a>)}</div></Reveal>
    <div className="lp-feature-rows">{featureRows.map((row,index) => <article className={`lp-feature-row ${index % 2 ? 'reverse' : ''}`} id={row.id} key={row.id}><Reveal className="lp-feature-copy"><div className="lp-mini-kicker"><row.icon size={15}/> {row.audience}</div><h3>{row.title}</h3><p>{row.text}</p><ul>{row.bullets.map(text => <li key={text}><ArrowRight size={15}/>{text}</li>)}</ul><ArrowLink href="#final-cta">Explore {row.tab.toLowerCase()}</ArrowLink></Reveal><Reveal className="lp-feature-art" delay={.12}><div className="lp-feature-glow"/><Mockup index={index}/></Reveal></article>)}</div>
    <Reveal className="lp-faq"><div id="faq"><div className="lp-kicker"><span/> EXPLORE THE DETAILS</div><h3>Built for the<br/>questions that follow.</h3></div><div className="lp-accordion">{faqItems.map((item,index) => <div className="lp-accordion-item" key={item.q}><button id={`faq-button-${index}`} aria-expanded={faq === index} aria-controls={`faq-panel-${index}`} onClick={() => setFaq(faq === index ? null : index)}>{item.q}<ChevronDown size={18} className={faq === index ? 'turned' : ''}/></button><div id={`faq-panel-${index}`} role="region" aria-labelledby={`faq-button-${index}`} className={`lp-accordion-body ${faq === index ? 'open' : ''}`}><div><p>{item.a}</p></div></div></div>)}</div></Reveal>
  </section>
}
function ExploreApp() { return <section className="lp-newsletter lp-shell" id="get-started"><div><div className="lp-newsletter-icon"><ShieldCheck size={20}/></div><div><h2>Ready to investigate?</h2><p>Connect a repository or review your existing incidents.</p></div></div><Link className="lp-button lp-button-primary" to="/dashboard">Open BreachTrace <ArrowRight size={16}/></Link></section> }

export default function Landing() {
  const root = useRef<HTMLDivElement>(null); const reduced = useReducedMotion(); const { theme } = useTheme()
  const [scrambled, setScrambled] = useState<number | null>(null)
  const clearScramble = useRef<number | undefined>(undefined)
  const pointerFrame = useRef<number | null>(null)
  const hoverIncident = useCallback((index: number) => { if (reduced) return; setScrambled(index); window.clearTimeout(clearScramble.current); clearScramble.current = window.setTimeout(() => setScrambled(null), 200) }, [reduced])
  useEffect(() => () => { window.clearTimeout(clearScramble.current); if (pointerFrame.current !== null) cancelAnimationFrame(pointerFrame.current) }, [])
  useEffect(() => {
    if (reduced) return
    const lenis = new Lenis({ duration: 1.1, smoothWheel: true, anchors: true })
    const scroll = () => {
      ScrollTrigger.update()
      const hero = root.current?.querySelector<HTMLElement>('.lp-hero')
      if (hero && window.matchMedia('(hover: hover) and (pointer: fine)').matches) hero.style.setProperty('--lp-scroll-offset', `${Math.min(window.scrollY * .2, 140)}px`)
    }
    lenis.on('scroll', scroll)
    const tick = (time: number) => lenis.raf(time * 1000); gsap.ticker.add(tick); gsap.ticker.lagSmoothing(0)
    const context = gsap.context(() => {
      const media = gsap.matchMedia()
      media.add('(min-width: 481px)', () => { gsap.fromTo('.lp-pipeline-progress', { scaleX: 0 }, { scaleX: 1, ease: 'none', scrollTrigger: { trigger: '.lp-pipeline-track', start: 'top 80%', end: 'bottom 30%', scrub: true } }) })
      media.add('(max-width: 480px)', () => { gsap.fromTo('.lp-pipeline-progress', { scaleY: 0 }, { scaleY: 1, ease: 'none', scrollTrigger: { trigger: '.lp-pipeline-track', start: 'top 80%', end: 'bottom 30%', scrub: true } }) })
      gsap.utils.toArray<HTMLElement>('.lp-pipeline-step').forEach((step, index) => ScrollTrigger.create({ trigger: step, start: `top ${80 - index * 4}%`, toggleClass: 'is-lit' }))
      gsap.utils.toArray<HTMLElement>('.lp-vault-chip').forEach((chip, index) => gsap.to(chip, { xPercent: index % 2 ? -105 : 105, yPercent: index < 2 ? 65 : -65, scale: .65, opacity: .2, ease: 'none', scrollTrigger: { trigger: '.lp-vault-visual', start: 'top 80%', end: 'bottom 35%', scrub: true } }))
      gsap.to('.lp-vault-center', { scale: 1.12, boxShadow: '0 0 80px rgba(148,148,148,.55)', ease: 'none', scrollTrigger: { trigger: '.lp-vault-visual', start: 'top 55%', end: 'bottom 35%', scrub: true } })
    }, root)
    return () => { context.revert(); lenis.off('scroll', scroll); gsap.ticker.remove(tick); lenis.destroy() }
  }, [reduced])
  const pointer = (event: MouseEvent<HTMLElement>) => { if (reduced || pointerFrame.current !== null || !window.matchMedia('(hover: hover) and (pointer: fine)').matches) return; const el = event.currentTarget; const rect = el.getBoundingClientRect(); const x = event.clientX - rect.left; const y = event.clientY - rect.top; pointerFrame.current = requestAnimationFrame(() => { el.style.setProperty('--mouse-x', `${x}px`); el.style.setProperty('--mouse-y', `${y}px`); el.style.setProperty('--lp-parallax-x', `${(x / rect.width - .5) * 24}px`); el.style.setProperty('--lp-parallax-y', `${(y / rect.height - .5) * 24}px`); pointerFrame.current = null }) }
  return <div ref={root} className="landing-page" data-theme={theme} id="top" style={{ '--lp-accent': LANDING.accent } as CSSProperties}><Header/><main>
    <section className="lp-hero" onMouseMove={pointer}><div className="lp-hero-grid"/><div className="lp-hero-glow"/><div className="lp-hero-content"><motion.div initial={reduced ? false : { opacity: 0, y: 24 }} animate={{ opacity: 1, y: 0 }} transition={{ duration: .7, ease: ENTER }}><a className="lp-eyebrow" href="#platform"><span className="lp-pulse-dot"/> CREDENTIAL EXPOSURE & FORENSICS <ArrowRight size={14}/></a></motion.div><h1><motion.span initial={reduced ? false : { opacity: 0, y: 24 }} animate={{ opacity: 1, y: 0 }} transition={{ duration: .7, delay: .08, ease: ENTER }}>{LANDING.hookFirst}</motion.span><motion.span className="lp-gradient-text" initial={reduced ? false : { opacity: 0, y: 24 }} animate={{ opacity: 1, y: 0 }} transition={{ duration: .7, delay: .16, ease: ENTER }}>{LANDING.hookSecond}</motion.span></h1><motion.p className="lp-hero-subtitle" initial={reduced ? false : { opacity: 0, y: 24 }} animate={{ opacity: 1, y: 0 }} transition={{ duration: .7, delay: .24, ease: ENTER }}>{LANDING.valueProp}</motion.p><motion.div className="lp-hero-actions" initial={reduced ? false : { opacity: 0, y: 24 }} animate={{ opacity: 1, y: 0 }} transition={{ duration: .7, delay: .32, ease: ENTER }}><Link className="lp-button lp-button-primary" to="/dashboard">{LANDING.primaryCta}<ArrowRight size={16}/></Link><a className="lp-button lp-button-outline" href="#platform">{LANDING.secondaryCta}<ArrowDown size={16}/></a></motion.div><motion.div className="lp-proof" initial={reduced ? false : { opacity: 0, y: 24 }} animate={{ opacity: 1, y: 0 }} transition={{ duration: .7, delay: .4, ease: ENTER }}>{LANDING.proof}</motion.div></div><motion.div initial={reduced ? false : { opacity: 0, y: 24 }} animate={{ opacity: 1, y: 0 }} transition={{ duration: .7, delay: .48, ease: ENTER }}><Perimeter/></motion.div></section>
    <section className="lp-trust lp-shell"><Reveal><p>{LANDING.trustCaption}</p><div className="lp-logo-mask"><div className="lp-logo-track">{[0,1].map(copy => <div key={copy} aria-hidden={copy === 1} className="lp-logo-group">{LANDING.logos.map((logo,index) => <span key={logo}><i>{['◆','✦','◈','▰','◉','◇','✳'][index]}</i>{logo}</span>)}</div>)}</div></div></Reveal></section>
    <section className="lp-incidents lp-section" id="incidents"><Reveal className="lp-center"><div className="lp-kicker center"><span/> INVESTIGATION WORKFLOWS</div><h2>Every investigation<br/><span>starts with a signal.</span></h2><p className="lp-section-intro">From a credential match to a documented response, keep the evidence in context.</p><ArrowLink href="#resources">Explore investigation features</ArrowLink></Reveal><div className="lp-ticker-mask"><div className="lp-incident-ticker">{[0,1].map(copy => <div className="lp-ticker-group" aria-hidden={copy === 1} key={copy}>{LANDING.incidents.map((incident,index) => <motion.div className="lp-ticker-card" key={incident} viewport={{ once: true }} onViewportEnter={() => hoverIncident(index)} onMouseEnter={() => hoverIncident(index)}><span><span className="lp-ticker-icon"><Shield size={17}/></span><b>{scrambled === index ? '[#%&@!]' : incident}</b></span><small>EXAMPLE WORKFLOW <ArrowUpRight size={14}/></small></motion.div>)}</div>)}</div></div></section>
    <section className="lp-stats lp-shell" id="insights"><Reveal className="lp-stats-intro"><div className="lp-kicker"><span/> THE BIGGER PICTURE</div><h2>Understand<br/><span>what matters.</span></h2><p>A detected credential is the starting point. BreachTrace brings the exposure, available activity, and your team’s response together.</p></Reveal><div className="lp-stats-grid">{LANDING.stats.map((stat,index) => <Reveal key={stat.source} delay={index*.12}><article className="lp-stat-card" onMouseMove={glow}><div className="lp-stat-number"><Counter value={stat.value} suffix={stat.suffix}/></div><p>{stat.description}</p><small>{stat.source}</small></article></Reveal>)}</div></section>
    <FeatureSection/>
    <section className="lp-pipeline lp-section" id="pipeline"><Reveal className="lp-center"><div className="lp-kicker center"><span/> YOUR RESPONSE WORKFLOW</div><h2>From the first signal<br/><span>to a confident response.</span></h2><p className="lp-section-intro">Move from an exposed credential to the evidence and decisions that matter.</p></Reveal><div className="lp-pipeline-track"><div className="lp-pipeline-line"><div className="lp-pipeline-progress"/><i/></div>{pipeline.map((step,index) => <Reveal key={step.label} delay={index*.1}><div className="lp-pipeline-step"><span className="lp-step-icon"><step.icon size={23}/></span><small>0{index+1} / STEP</small><h3>{step.label}</h3><p>{step.desc}</p></div></Reveal>)}</div><div className="lp-pipeline-metrics"><div>Snapshot<p>Scan a repository’s current default branch</p></div><div>Webhook<p>Monitor future signed GitHub pushes</p></div></div></section>
    <section className="lp-vault lp-section" id="vault"><Reveal className="lp-vault-copy"><div className="lp-kicker"><span/> BEYOND THE OBVIOUS</div><h2>See what’s outside<br/><span>the perimeter.</span></h2><p>Investigate credential candidates found in repositories and review available provider activity after a qualifying exposure.</p><ArrowLink href="#integrations">Explore your workflow</ArrowLink></Reveal><Reveal className="lp-vault-visual"><div className="lp-vault-ring ring-one"/><div className="lp-vault-ring ring-two"/><div className="lp-vault-ring ring-three"/><div className="lp-vault-center"><LockKeyhole size={33}/></div>{['GITHUB', 'CLOUD', 'STRIPE', 'TWILIO'].map((chip,index) => <div key={chip} className={`lp-vault-chip chip-${index}`}><span><KeyRound size={13}/>{chip}</span></div>)}</Reveal></section>
    <section className="lp-customers lp-section" id="customers"><Reveal className="lp-center"><div className="lp-kicker center"><span/> BUILT FOR YOUR WORKFLOW</div><h2>From the first signal<br/><span>to a shared response.</span></h2><p className="lp-section-intro">A clear path for the people finding, investigating, and responding to credential exposure.</p></Reveal><div className="lp-quotes">{LANDING.highlights.map((item,index) => <Reveal key={item.title} delay={index*.1}><article className="lp-quote" onMouseMove={glow}><div className="lp-quote-mark"><ShieldCheck size={27}/></div><h3>{item.title}</h3><p>{item.description}</p><b>{item.label}</b></article></Reveal>)}</div><div className="lp-center lp-after-cards"><ArrowLink href="#resources">Explore the workflow</ArrowLink></div></section>
    <section className="lp-compliance lp-section" id="compliance"><Reveal className="lp-center"><div className="lp-kicker center"><span/> SECURITY & COLLABORATION</div><h2>Make room for<br/><span>better practices.</span></h2><p className="lp-section-intro">Controls and workflows that help teams manage an investigation.</p></Reveal><div className="lp-compliance-grid">{LANDING.capabilities.map((framework,index) => <Reveal key={framework} delay={index*.05}><span><CheckCircle2 size={17}/>{framework}</span></Reveal>)}</div><div className="lp-center"><ArrowLink href="#resources">Explore resources</ArrowLink></div></section>
    <section className="lp-integrations lp-section" id="integrations"><Reveal className="lp-center"><div className="lp-kicker center"><span/> CONNECT YOUR WORKFLOW</div><h2>Bring your stack<br/><span>into the picture.</span></h2><p className="lp-section-intro">Supported providers, repository connections, and optional report model choices. Availability depends on configuration and access.</p></Reveal><div className="lp-tools-grid">{LANDING.tools.map((tool,index) => <Reveal key={tool} delay={Math.abs((index % 10) - 4.5)*.025}><div className="lp-tool" title={tool}><span>{['◇','▣','⌘','◉','⬡','✳','◈','▦','◎','◆'][index%10]}</span><small>{tool}</small></div></Reveal>)}</div><div className="lp-center"><ArrowLink href="#final-cta">Explore the platform</ArrowLink></div></section>
    <section className="lp-final lp-section" id="final-cta"><div className="lp-final-glow"/><Reveal className="lp-center"><div className="lp-kicker center"><span/> THE NEXT STEP IS YOURS</div><h2>See the signal.<br/><span>Shape the response.</span></h2><p className="lp-section-intro">Connect your repository and follow the evidence from exposure to response.</p></Reveal><div className="lp-final-columns" id="get-started-options">{[{title:'Ready to evaluate',copy:'Open the monitor to review your projects and incidents.',button:LANDING.primaryCta,kind:'primary',to:'/dashboard'},{title:'Want to explore',copy:'See how detection, forensics, and reporting fit together.',button:LANDING.secondaryCta,kind:'outline',to:'#platform'},{title:'Just looking',copy:'Learn what happens at each stage of an investigation.',button:'Explore the workflow',kind:'ghost',to:'#resources'}].map((item,index) => <Reveal key={item.title} delay={index*.1}><article><span>0{index+1}</span><h3>{item.title}</h3><p>{item.copy}</p><a href={item.to} className={`lp-button lp-button-${item.kind}`}>{item.button}<ArrowRight size={15}/></a></article></Reveal>)}</div></section>
    <section className="lp-resources lp-section" id="resources"><Reveal><div className="lp-resource-head"><div><div className="lp-kicker"><span/> KEEP EXPLORING</div><h2>Go a little deeper.</h2></div><ArrowLink href="#get-started">Open BreachTrace</ArrowLink></div></Reveal><div className="lp-resource-grid">{[{type:'DETECTION',title:'Scan your repository',href:'/connect'}, {type:'INVESTIGATION',title:'Review incident evidence',href:'/'}, {type:'SEARCH',title:'Search stored findings',href:'/search'}].map((resource,index) => <Reveal key={resource.type} delay={index*.1}><a className={`lp-resource-card resource-${index}`} href={resource.href}><div className="lp-resource-art"><div className="lp-resource-orbit"/><FileText size={30}/><span>{LANDING.product}</span><strong>{resource.title}</strong></div><div className="lp-resource-info"><small>{resource.type}</small><h3>{resource.title}</h3><ArrowUpRight size={19}/></div></a></Reveal>)}</div></section>
    <ExploreApp/>
  </main><footer className="lp-footer"><div className="lp-footer-inner lp-shell"><div className="lp-footer-brand"><Brand/><p>Credential exposure detection and forensics for your team.</p></div><div className="lp-footer-columns">{[{title:'Platform',links:[{label:'Detect',href:'#detect'},{label:'Investigate',href:'#remediate'},{label:'Respond',href:'#prevent'}]},{title:'Explore',links:[{label:'How it works',href:'#pipeline'},{label:'Provider coverage',href:'#integrations'},{label:'Frequently asked questions',href:'#faq'}]},{title:'In the app',links:[{label:'Monitor',href:'/'},{label:'Connect',href:'/connect'},{label:'Search',href:'/search'}]}].map(group => <div key={group.title}><strong>{group.title}</strong>{group.links.map(link => <a href={link.href} key={link.label}>{link.label}</a>)}</div>)}</div></div><div className="lp-footer-bottom lp-shell"><span>© {new Date().getFullYear()} {LANDING.product}</span><span>Credential exposure &amp; forensics</span></div><div className="lp-footer-wordmark" aria-hidden="true">{LANDING.product}</div></footer></div>
}
