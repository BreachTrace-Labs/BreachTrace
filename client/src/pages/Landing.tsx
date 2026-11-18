import { useEffect, useRef, useState, type CSSProperties, type KeyboardEvent, type MouseEvent } from 'react'
import { Link } from 'react-router-dom'
import { AnimatePresence, motion, useInView, useReducedMotion } from 'framer-motion'
import { gsap } from 'gsap'
import { ScrollTrigger } from 'gsap/ScrollTrigger'
import Lenis from 'lenis'
import { ArrowDown, ArrowRight, ArrowUpRight, CheckCircle2, ChevronDown, Crosshair, FileText, Fingerprint, KeyRound, Layers3, LockKeyhole, Menu, Moon, Radar, Search, ShieldCheck, Sun, X } from 'lucide-react'
import { LANDING } from './landing-content'
import { useAuth } from '@/context/AuthContext'
import { useTheme } from '@/lib/theme'
import { BrandLogo } from '@/components/BrandLogo'
import './landing.css'

gsap.registerPlugin(ScrollTrigger)
const ENTER = [0.22, 1, 0.36, 1] as const
const groups = {
  Platform: [{ title: 'Capabilities', links: ['Detection', 'Investigation', 'Response'] }, { title: 'Product details', links: ['Forensic coverage', 'Security and collaboration', 'Providers and models'] }],
  Resources: [{ title: 'Learn', links: ['How it works', 'Frequently asked questions', 'Regulations and frameworks'] }, { title: 'In the app', links: ['Incident monitor', 'Repository scans', 'Evidence search'] }],
} as const
const menuNames = ['Platform', 'Workflow', 'Resources'] as const
type MenuName = keyof typeof groups
const featureRows = [
  { id: 'detect', tab: 'Detect', audience: 'REPOSITORY SCANNING', title: 'Find credential candidates in code.', text: 'Scan the current default branch or use signed GitHub push webhooks to detect new exposures.', bullets: ['Snapshot findings stay separate from incidents', 'Webhook findings include repository and commit context', 'Detected patterns are not proof of a valid credential'], icon: Search },
  { id: 'remediate', tab: 'Investigate', audience: 'FORENSIC EVIDENCE', title: 'Review the evidence available.', text: 'For supported credentials, configured provider readers can collect available activity. Coverage depends on access, logging and retention.', bullets: ['Review available events and exposure timing', 'Distinguish account activity from per-key attribution', 'Detection-only findings disclose their collection limits'], icon: Crosshair },
  { id: 'prevent', tab: 'Respond', audience: 'INCIDENT RESPONSE', title: 'Coordinate the next steps.', text: 'Project members can review findings and document dismissals; administrators and security leads can assign incidents.', bullets: ['Record a dismissal and reason', 'Review an incident report and remediation steps', 'Download a PDF report'], icon: ShieldCheck },
] as const
const menuDestinations: Record<string, string> = {
  'Detection': '#detect', 'Investigation': '#remediate', 'Response': '#prevent',
  'Forensic coverage': '#forensic-tiers', 'Security and collaboration': '#compliance', 'Providers and models': '#integrations',
  'How it works': '#pipeline', 'Frequently asked questions': '#faq', 'Getting started': '#get-started', 'Regulations and frameworks': '/regulations',
  'Incident monitor': '/dashboard', 'Repository scans': '/connect', 'Evidence search': '/search',
}
const faqItems = [
  { q: 'Where do I start?', a: 'Create a project and scan a GitHub repository’s current default branch, or register a webhook to monitor future pushes.' },
  { q: 'What context can I review?', a: 'Incidents include a masked credential hint, repository and commit details, an exposure window, and available provider activity.' },
  { q: 'How do teams coordinate?', a: 'Project members can review incidents and document dismissals. Security leads and admins can assign incidents; administrators can review the organisation audit log.' },
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
    <AnimatePresence>{open && !drawer && <motion.div id={`mega-${open}`} className="lp-mega" onKeyDown={menuKeys} onMouseEnter={() => window.clearTimeout(closeTimer.current)} onMouseLeave={closeMenu} initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }} exit={{ opacity: 0, y: 8 }} transition={{ duration: .18 }}><div className="lp-mega-inner">{groups[open].map(group => <div className="lp-mega-group" key={group.title}><strong>{group.title}</strong>{group.links.map((link, i) => <motion.a key={link} href={menuDestinations[link] } onClick={() => setOpen(null)} initial={{ opacity: 0, y: 4 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: i * .02 }}><span>{link}</span><ArrowUpRight size={14} /></motion.a>)}</div>)}<a className="lp-mega-feature" href="#pipeline" onClick={() => setOpen(null)}><span>WORKFLOW</span><strong>From signal to response</strong><p>See how detection becomes an investigation.</p><small>View the workflow <ArrowRight size={14} /></small></a><div className="lp-mega-tour"><Layers3 size={26} /><strong>Understand coverage</strong><span>Learn when provider evidence is available.</span><a href="#forensic-tiers" onClick={() => setOpen(null)}>Explore <ArrowRight size={13} /></a></div></div></motion.div>}</AnimatePresence>
    {drawer && <div className="lp-mobile-drawer" id="mobile-navigation"><nav aria-label="Mobile navigation">{menuNames.map(name => name === 'Workflow' ? <a key={name} href="#pipeline" onClick={() => setDrawer(false)}>Workflow</a> : <div className="lp-mobile-section" key={name}><button aria-expanded={open === name} onClick={() => setOpen(open === name ? null : name)}>{name}<ChevronDown className={open === name ? 'turned' : ''} size={17} /></button>{open === name && <div className="lp-mobile-links">{groups[name].flatMap(group => group.links).map(link => <a href={menuDestinations[link] } key={link} onClick={() => { setDrawer(false); setOpen(null) }}>{link}</a>)}</div>}</div>)}<Link to={user ? "/dashboard" : "/login"} onClick={() => setDrawer(false)}>{user ? "Dashboard" : "Sign in"}</Link><Link className="lp-button lp-button-primary" to="/dashboard" onClick={() => setDrawer(false)}>{LANDING.primaryCta}<ArrowRight size={15} /></Link></nav></div>}
  </header>
}

function InvestigationOverview() {
  return <div className="lp-investigation" aria-label="BreachTrace investigation workflow">
    <div className="lp-investigation-header"><span><Fingerprint size={16}/> INVESTIGATION OVERVIEW</span><span>HOW IT WORKS</span></div>
    <div className="lp-investigation-body"><div className="lp-investigation-intro"><span className="lp-investigation-icon"><ShieldCheck size={26}/></span><div><strong>From exposure to evidence</strong><p>A structured path for reviewing credential exposure.</p></div></div>
      <div className="lp-investigation-steps"><div><span>01</span><strong>Detect</strong><small>Scan a snapshot or monitor signed pushes.</small></div><div><span>02</span><strong>Investigate</strong><small>Review provider activity when available.</small></div><div><span>03</span><strong>Respond</strong><small>Document decisions and remediation.</small></div></div>
      <p className="lp-investigation-note">A detected pattern alone does not confirm a valid key or a breach.</p>
    </div></div>
}
function Counter({ value, suffix = '' }: { value: number; suffix?: string }) {
  const ref = useRef<HTMLSpanElement>(null); const visible = useInView(ref, { once: true, margin: '-10%' }); const reduced = useReducedMotion(); const [number, setNumber] = useState(0)
  useEffect(() => { if (!visible) return; if (reduced) { const id = requestAnimationFrame(() => setNumber(value)); return () => cancelAnimationFrame(id) } let frame = 0; const start = performance.now(); const tick = (now: number) => { const t = Math.min((now - start) / 1600, 1); setNumber(value * (1 - Math.pow(2, -10 * t))); if (t < 1) frame = requestAnimationFrame(tick); else setNumber(value) }; frame = requestAnimationFrame(tick); return () => cancelAnimationFrame(frame) }, [visible, value, reduced])
  return <span ref={ref}>{Number.isInteger(value) ? Math.round(number) : number.toFixed(1)}<em>{suffix}</em></span>
}
function glow(event: MouseEvent<HTMLElement>) { if (!window.matchMedia('(hover: hover) and (pointer: fine)').matches) return; const rect = event.currentTarget.getBoundingClientRect(); event.currentTarget.style.setProperty('--mouse-x', `${event.clientX - rect.left}px`); event.currentTarget.style.setProperty('--mouse-y', `${event.clientY - rect.top}px`) }
function CapabilityDetail({ index }: { index: number }) {
  const details = [
    { title: 'Two detection paths', items: [['Snapshot scan', 'Checks the current default branch and reports candidates in Connect.'], ['Push webhook', 'Checks qualifying signed GitHub pushes and creates monitor incidents.'], ['Scope', 'Snapshot scans do not inspect Git history or start provider collection.']] },
    { title: 'Evidence and its limits', items: [['Supported collection', 'Provider readers query available activity for supported credential types.'], ['Detection only', 'Other credential types show the exposure without assessed activity or severity.'], ['Review context', 'Access, retention and logging determine which events can be retrieved.']] },
    { title: 'A documented response', items: [['Incident detail', 'Review evidence, remediation steps and report content.'], ['Collaboration', 'Assign an owner or document a dismissal with a reason.'], ['Export', 'Download the incident report as a PDF.']] },
  ][index]
  return <div className="lp-capability-detail"><span>WHAT IS AVAILABLE</span><h4>{details.title}</h4>{details.items.map(([title, text]) => <div key={title}><CheckCircle2 size={17}/><p><strong>{title}</strong><small>{text}</small></p></div>)}</div>
}

function FeatureSection() {
  const [active, setActive] = useState('detect'); const [faq, setFaq] = useState<number | null>(0)
  useEffect(() => { const elements = featureRows.map(row => document.getElementById(row.id)).filter((item): item is HTMLElement => Boolean(item)); const observer = new IntersectionObserver(entries => entries.forEach(entry => { if (entry.isIntersecting) setActive(entry.target.id) }), { rootMargin: '-25% 0px -55% 0px' }); elements.forEach(element => observer.observe(element)); return () => observer.disconnect() }, [])
  return <section className="lp-platform-section lp-section" id="platform"><Reveal className="lp-center"><div className="lp-eyebrow"><Layers3 size={15}/> {LANDING.product} PLATFORM</div><h2>The credential<br/><span>security platform.</span></h2><p className="lp-section-intro">Find exposed credentials, review available evidence, and keep your team aligned on the response.</p><div className="lp-platform-tabs" aria-label="Platform sections">{featureRows.map(row => <a href={`#${row.id}`} className={active === row.id ? 'active' : ''} onClick={() => setActive(row.id)} key={row.id}>{active === row.id && <motion.span layoutId="active-platform-tab" className="lp-tab-bg" transition={{ type: 'spring', stiffness: 400, damping: 35 }}/>}<span>{row.tab}</span></a>)}</div></Reveal>
    <div className="lp-feature-rows">{featureRows.map((row,index) => <article className={`lp-feature-row ${index % 2 ? 'reverse' : ''}`} id={row.id} key={row.id}><Reveal className="lp-feature-copy"><div className="lp-mini-kicker"><row.icon size={15}/> {row.audience}</div><h3>{row.title}</h3><p>{row.text}</p><ul>{row.bullets.map(text => <li key={text}><ArrowRight size={15}/>{text}</li>)}</ul><ArrowLink href={index === 0 ? "/connect" : index === 1 ? "#forensic-tiers" : "/dashboard"}>{index === 0 ? "Open repository scanning" : index === 1 ? "Read about forensic coverage" : "Open incident monitor"}</ArrowLink></Reveal><Reveal className="lp-feature-art" delay={.12}><div className="lp-feature-glow"/><CapabilityDetail index={index}/></Reveal></article>)}</div>
    <Reveal className="lp-faq"><div id="faq"><div className="lp-kicker"><span/> EXPLORE THE DETAILS</div><h3>Built for the<br/>questions that follow.</h3></div><div className="lp-accordion">{faqItems.map((item,index) => <div className="lp-accordion-item" key={item.q}><button id={`faq-button-${index}`} aria-expanded={faq === index} aria-controls={`faq-panel-${index}`} onClick={() => setFaq(faq === index ? null : index)}>{item.q}<ChevronDown size={18} className={faq === index ? 'turned' : ''}/></button><div id={`faq-panel-${index}`} role="region" aria-labelledby={`faq-button-${index}`} className={`lp-accordion-body ${faq === index ? 'open' : ''}`}><div><p>{item.a}</p></div></div></div>)}</div></Reveal>
  </section>
}
function ExploreApp() { return <section className="lp-newsletter lp-shell" id="get-started"><div><div className="lp-newsletter-icon"><ShieldCheck size={20}/></div><div><h2>Ready to investigate?</h2><p>Open the monitor to review incidents. Administrators and security leads can also scan repositories in Connect.</p></div></div><Link className="lp-button lp-button-primary" to="/dashboard">Open BreachTrace <ArrowRight size={16}/></Link></section> }

export default function Landing() {
  const root = useRef<HTMLDivElement>(null); const reduced = useReducedMotion(); const { theme } = useTheme()
  const pointerFrame = useRef<number | null>(null)
  useEffect(() => () => { if (pointerFrame.current !== null) cancelAnimationFrame(pointerFrame.current) }, [])
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
    <section className="lp-hero" onMouseMove={pointer}><div className="lp-hero-grid"/><div className="lp-hero-glow"/><div className="lp-hero-content"><motion.div initial={reduced ? false : { opacity: 0, y: 24 }} animate={{ opacity: 1, y: 0 }} transition={{ duration: .7, ease: ENTER }}><a className="lp-eyebrow" href="#platform"><span className="lp-pulse-dot"/> CREDENTIAL EXPOSURE & FORENSICS <ArrowRight size={14}/></a></motion.div><h1><motion.span initial={reduced ? false : { opacity: 0, y: 24 }} animate={{ opacity: 1, y: 0 }} transition={{ duration: .7, delay: .08, ease: ENTER }}>{LANDING.hookFirst}</motion.span><motion.span className="lp-gradient-text" initial={reduced ? false : { opacity: 0, y: 24 }} animate={{ opacity: 1, y: 0 }} transition={{ duration: .7, delay: .16, ease: ENTER }}>{LANDING.hookSecond}</motion.span></h1><motion.p className="lp-hero-subtitle" initial={reduced ? false : { opacity: 0, y: 24 }} animate={{ opacity: 1, y: 0 }} transition={{ duration: .7, delay: .24, ease: ENTER }}>{LANDING.valueProp}</motion.p><motion.div className="lp-hero-actions" initial={reduced ? false : { opacity: 0, y: 24 }} animate={{ opacity: 1, y: 0 }} transition={{ duration: .7, delay: .32, ease: ENTER }}><Link className="lp-button lp-button-primary" to="/dashboard">{LANDING.primaryCta}<ArrowRight size={16}/></Link><a className="lp-button lp-button-outline" href="#platform">{LANDING.secondaryCta}<ArrowDown size={16}/></a></motion.div><motion.div className="lp-proof" initial={reduced ? false : { opacity: 0, y: 24 }} animate={{ opacity: 1, y: 0 }} transition={{ duration: .7, delay: .4, ease: ENTER }}>{LANDING.proof}</motion.div></div><motion.div initial={reduced ? false : { opacity: 0, y: 24 }} animate={{ opacity: 1, y: 0 }} transition={{ duration: .7, delay: .48, ease: ENTER }}><InvestigationOverview/></motion.div></section>
    <section className="lp-trust lp-shell"><Reveal><p>{LANDING.trustCaption}</p><div className="lp-logo-mask"><div className="lp-logo-track">{[0,1].map(copy => <div key={copy} aria-hidden={copy === 1} className="lp-logo-group">{LANDING.logos.map(logo => <span key={logo}>{logo}</span>)}</div>)}</div></div></Reveal></section>
    <section className="lp-stats lp-shell" id="insights"><Reveal className="lp-stats-intro"><div className="lp-kicker"><span/> THE BIGGER PICTURE</div><h2>Understand<br/><span>what matters.</span></h2><p>A detected credential candidate is the starting point. BreachTrace brings the exposure, available activity, and your team’s response together.</p></Reveal><div className="lp-stats-grid">{LANDING.stats.map((stat,index) => <Reveal key={stat.source} delay={index*.12}><article className="lp-stat-card" onMouseMove={glow}><div className="lp-stat-number"><Counter value={stat.value} suffix={stat.suffix}/></div><p>{stat.description}</p><small>{stat.source}</small></article></Reveal>)}</div></section>
    <FeatureSection/>
    <section className="lp-pipeline lp-section" id="pipeline"><Reveal className="lp-center"><div className="lp-kicker center"><span/> YOUR RESPONSE WORKFLOW</div><h2>From the first signal<br/><span>to a confident response.</span></h2><p className="lp-section-intro">Move from an exposed credential to the evidence and decisions that matter.</p></Reveal><div className="lp-pipeline-track"><div className="lp-pipeline-line"><div className="lp-pipeline-progress"/><i/></div>{pipeline.map((step,index) => <Reveal key={step.label} delay={index*.1}><div className="lp-pipeline-step"><span className="lp-step-icon"><step.icon size={23}/></span><small>0{index+1} / STEP</small><h3>{step.label}</h3><p>{step.desc}</p></div></Reveal>)}</div><div className="lp-pipeline-metrics"><div>Snapshot<p>Scan a repository’s current default branch</p></div><div>Webhook<p>Monitor future signed GitHub pushes</p></div></div></section>
    <section className="lp-vault lp-section" id="forensic-tiers"><Reveal className="lp-vault-copy"><div className="lp-kicker"><span/> BEYOND THE OBVIOUS</div><h2>Know what evidence<br/><span>can be collected.</span></h2><p>Supported credentials can use configured provider readers to retrieve available activity. Detection-only findings show exposure context without claiming activity or severity. Provider access, retention and logging limit coverage.</p><p><strong>Activity collection:</strong> AWS access keys, Google Cloud service accounts, Azure service principals, Stripe keys and Twilio credentials when required identifiers and access are available.</p><p><strong>Detection only:</strong> AI, GitHub, Slack, npm, SendGrid, Hugging Face and database credentials; unsupported or incomplete credentials also remain detection only.</p><ArrowLink href="#integrations">See supported providers</ArrowLink></Reveal><Reveal className="lp-vault-visual"><div className="lp-vault-ring ring-one"/><div className="lp-vault-ring ring-two"/><div className="lp-vault-ring ring-three"/><div className="lp-vault-center"><LockKeyhole size={33}/></div>{['GITHUB', 'CLOUD', 'STRIPE', 'TWILIO'].map((chip,index) => <div key={chip} className={`lp-vault-chip chip-${index}`}><span><KeyRound size={13}/>{chip}</span></div>)}</Reveal></section>
    <section className="lp-customers lp-section" id="customers"><Reveal className="lp-center"><div className="lp-kicker center"><span/> BUILT FOR YOUR WORKFLOW</div><h2>From the first signal<br/><span>to a shared response.</span></h2><p className="lp-section-intro">A clear path for the people finding, investigating, and responding to credential exposure.</p></Reveal><div className="lp-quotes">{LANDING.highlights.map((item,index) => <Reveal key={item.title} delay={index*.1}><article className="lp-quote" onMouseMove={glow}><div className="lp-quote-mark"><ShieldCheck size={27}/></div><h3>{item.title}</h3><p>{item.description}</p><b>{item.label}</b></article></Reveal>)}</div><div className="lp-center lp-after-cards"><ArrowLink href="#pipeline">Explore the workflow</ArrowLink></div></section>
    <section className="lp-compliance lp-section" id="compliance"><Reveal className="lp-center"><div className="lp-kicker center"><span/> SECURITY & COLLABORATION</div><h2>Make room for<br/><span>better practices.</span></h2><p className="lp-section-intro">Controls and workflows help teams manage an investigation. Incident review signals highlight potentially relevant regulations and frameworks; applicability requires review.</p></Reveal><div className="lp-compliance-grid">{LANDING.capabilities.map((framework,index) => <Reveal key={framework} delay={index*.05}><span><CheckCircle2 size={17}/>{framework}</span></Reveal>)}</div><div className="lp-center"><ArrowLink href="/regulations">Explore regulations and frameworks</ArrowLink></div></section>
    <section className="lp-integrations lp-section" id="integrations"><Reveal className="lp-center"><div className="lp-kicker center"><span/> CONNECT YOUR WORKFLOW</div><h2>Bring your stack<br/><span>into the picture.</span></h2><p className="lp-section-intro">Repository connection, activity collection and report models serve different purposes. Availability depends on configuration and access.</p></Reveal><div className="lp-provider-groups"><article><h3>Repository</h3><p>GitHub snapshot scanning and signed push webhooks.</p><strong>GitHub</strong></article><article><h3>Activity collection</h3><p>Provider readers require access and are subject to available logs and retention.</p><strong>AWS · Google Cloud · Azure · Stripe · Twilio</strong></article><article><h3>Optional report models</h3><p>Deterministic reports are available without a model. Optional models require separate configuration; cloud providers receive the incident fact sheet.</p><strong>OpenAI · Anthropic · Gemini · Ollama · Local GGUF</strong></article></div><div className="lp-center"><ArrowLink href="/settings">Configure report models</ArrowLink></div></section>
    <section className="lp-final lp-section" id="final-cta"><div className="lp-final-glow"/><Reveal className="lp-center"><div className="lp-kicker center"><span/> THE NEXT STEP IS YOURS</div><h2>See the signal.<br/><span>Shape the response.</span></h2><p className="lp-section-intro">Connect your repository and follow the evidence from exposure to response.</p></Reveal><div className="lp-final-columns" id="get-started-options">{[{title:'Ready to evaluate',copy:'Open the monitor to review your projects and incidents.',button:LANDING.primaryCta,kind:'primary',to:'/dashboard'},{title:'Want to explore',copy:'See how detection, forensics, and reporting fit together.',button:LANDING.secondaryCta,kind:'outline',to:'#platform'},{title:'Just looking',copy:'Learn what happens at each stage of an investigation.',button:'Explore the workflow',kind:'ghost',to:'#pipeline'}].map((item,index) => <Reveal key={item.title} delay={index*.1}><article><span>0{index+1}</span><h3>{item.title}</h3><p>{item.copy}</p><a href={item.to} className={`lp-button lp-button-${item.kind}`}>{item.button}<ArrowRight size={15}/></a></article></Reveal>)}</div></section>
    <section className="lp-resources lp-section" id="resources"><Reveal><div className="lp-resource-head"><div><div className="lp-kicker"><span/> KEEP EXPLORING</div><h2>Go a little deeper.</h2></div><ArrowLink href="/dashboard">Open BreachTrace</ArrowLink></div></Reveal><div className="lp-resource-grid">{[{type:'DETECTION',title:'Scan your repository',href:'/connect'}, {type:'INVESTIGATION',title:'Review incident evidence',href:'/dashboard'}, {type:'SEARCH',title:'Search stored findings',href:'/search'}].map((resource,index) => <Reveal key={resource.type} delay={index*.1}><a className={`lp-resource-card resource-${index}`} href={resource.href}><div className="lp-resource-art"><div className="lp-resource-orbit"/><FileText size={30}/><span>{LANDING.product}</span><strong>{resource.title}</strong></div><div className="lp-resource-info"><small>{resource.type}</small><h3>{resource.title}</h3><ArrowUpRight size={19}/></div></a></Reveal>)}</div></section>
    <ExploreApp/>
  </main><footer className="lp-footer"><div className="lp-footer-inner lp-shell"><div className="lp-footer-brand"><Brand/><p>Credential exposure detection and forensics for your team.</p></div><div className="lp-footer-columns">{[{title:'Platform',links:[{label:'Detect',href:'#detect'},{label:'Investigate',href:'#remediate'},{label:'Respond',href:'#prevent'}]},{title:'Explore',links:[{label:'How it works',href:'#pipeline'},{label:'Provider coverage',href:'#integrations'},{label:'Frequently asked questions',href:'#faq'}]},{title:'In the app',links:[{label:'Monitor',href:'/dashboard'},{label:'Connect',href:'/connect'},{label:'Search',href:'/search'}]}].map(group => <div key={group.title}><strong>{group.title}</strong>{group.links.map(link => <a href={link.href} key={link.label}>{link.label}</a>)}</div>)}</div></div><div className="lp-footer-bottom lp-shell"><span>© {new Date().getFullYear()} {LANDING.product}</span><span>Credential exposure &amp; forensics</span></div><div className="lp-footer-wordmark" aria-hidden="true">{LANDING.product}</div></footer></div>
}
