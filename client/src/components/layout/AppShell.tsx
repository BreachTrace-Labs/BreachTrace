import { useEffect } from 'react'
import * as DropdownMenu from '@radix-ui/react-dropdown-menu'
import { Link, NavLink, useLocation, useNavigate } from 'react-router-dom'
import { Activity, Bell, ChevronDown, FlaskConical, Link2, LogOut, Moon, Search, Settings, Sun, Users } from 'lucide-react'
import { USE_MOCK } from '@/api/client'
import { BrandLogo } from '@/components/BrandLogo'
import { useAuth } from '@/context/AuthContext'
import { useProjects } from '@/context/ProjectContext'
import { useTheme } from '@/lib/theme'
import './app-shell.css'

const nav = [
  { to: '/dashboard', label: 'Dashboard', icon: Activity },
  { to: '/connect', label: 'Connect', icon: Link2 },
  { to: '/search', label: 'Search', icon: Search },
  { to: '/research', label: 'Research', icon: FlaskConical },
  { to: '/settings', label: 'Settings', icon: Settings },
  { to: '/admin', label: 'Admin', icon: Users },
]
function AccountMenu() {
  const { user, logout } = useAuth()
  const navigate = useNavigate()
  const signOut = async () => {
    try { await logout() } catch { /* The local session is cleared even if server logout fails. */ }
    navigate('/', { replace: true })
  }
  const initials = (user?.full_name || 'User').split(/\s+/).filter(Boolean).slice(0, 2).map(s => s[0]).join('').toUpperCase()
  return <DropdownMenu.Root><DropdownMenu.Trigger className="shell-account" aria-label="Account menu"><span className="shell-avatar">{initials}</span><span className="shell-account-name"><strong>{user?.full_name || 'Account'}</strong><small>{user?.role.replace('_', ' ')}</small></span><ChevronDown size={15}/></DropdownMenu.Trigger><DropdownMenu.Portal><DropdownMenu.Content className="shell-menu" sideOffset={6} align="end"><DropdownMenu.Label className="shell-menu-label">{user?.email || 'Preview session'}</DropdownMenu.Label><DropdownMenu.Item asChild><Link to="/settings">Profile & settings</Link></DropdownMenu.Item><DropdownMenu.Item asChild><Link to="/change-password">Change password</Link></DropdownMenu.Item><DropdownMenu.Item onSelect={() => void signOut()}><LogOut size={15}/> Sign out</DropdownMenu.Item></DropdownMenu.Content></DropdownMenu.Portal></DropdownMenu.Root>
}
export function AppShell({ children }: { children: React.ReactNode }) {
  const { user } = useAuth(); const { projects, selected, select } = useProjects(); const { toggle, theme } = useTheme(); const location = useLocation(); const navigate = useNavigate()
  useEffect(() => { const handle = (event: KeyboardEvent) => { if (!(event.metaKey || event.ctrlKey) || event.key.toLowerCase() !== 'k' || user?.role === 'developer') return; event.preventDefault(); if (location.pathname === '/search') window.dispatchEvent(new Event('bt-focus-search')); else navigate('/search') }; window.addEventListener('keydown', handle); return () => window.removeEventListener('keydown', handle) }, [location.pathname, navigate, user?.role])
  const visible = nav.filter(item => user?.role !== 'developer' || item.to === '/dashboard' || item.to === '/settings')
  const active = (to: string) => to === '/dashboard' ? location.pathname === '/' || location.pathname === '/dashboard' || location.pathname.startsWith('/incident/') || location.pathname.startsWith('/incidents/') : location.pathname.startsWith(to)
  const current = visible.find(item => active(item.to))?.label ?? 'Dashboard'
  return <div className="shell"><aside className="shell-sidebar"><Link to="/" className="shell-logo" aria-label="BreachTrace home"><BrandLogo variant="stacked" /></Link>
    <div className="shell-project"><span className="shell-caption">Project</span>{projects.length > 1 ? <label><span className="sr-only">Current project</span><select value={selected?.id ?? ''} onChange={event => select(event.target.value)}>{projects.map(project => <option key={project.id} value={project.id}>{project.name}</option>)}</select></label> : <strong>{selected?.name ?? (USE_MOCK ? 'Preview workspace' : 'No project selected')}</strong>}{selected && <small>{selected.github_repo_full_name}</small>}{!USE_MOCK && user?.role !== 'developer' && <Link to="/admin">+ New project</Link>}</div>
    <nav className="shell-nav" aria-label="Main navigation">{visible.map(({to,label,icon: Icon}) => <NavLink key={to} to={to} aria-current={active(to) ? 'page' : undefined} className={active(to) ? 'shell-nav-active' : ''}><Icon size={16}/>{label}</NavLink>)}</nav><div className="shell-user"><AccountMenu/></div></aside>
    <div className="shell-main"><header className="shell-topbar"><div className="shell-breadcrumb"><Link to="/">Home</Link> <span>/</span> {current}{location.pathname.startsWith('/incident') && <> <span>/</span> Incident</>}</div><div className="shell-top-actions"><button type="button" onClick={toggle} aria-label={theme === 'dark' ? 'Switch to light theme' : 'Switch to dark theme'}>{theme === 'dark' ? <Sun size={17}/> : <Moon size={17}/>}</button><button type="button" disabled title="Notifications are not available yet" aria-label="Notifications unavailable"><Bell size={17}/></button><AccountMenu/></div></header><main className="shell-content">{USE_MOCK && <p role="note" className="shell-notice">Preview mode · Incidents and research metrics are synthetic. Repository scans and model settings require a running backend.</p>}{!USE_MOCK && selected && user?.role !== 'developer' && <p className="shell-scope">Selected project: {selected.name}. Search, research and snapshot scans cover the whole organisation.</p>}{!USE_MOCK && user?.role === 'org_admin' && projects.length === 0 && <p className="shell-notice">No projects yet. <Link to="/onboarding">Set up your first project →</Link></p>}{children}</main></div></div>
}
