import * as DropdownMenu from '@radix-ui/react-dropdown-menu'
import { NavLink, useLocation } from 'react-router-dom'
import { Activity, ChevronDown, CircleUserRound, FlaskConical, Link2, LogOut, Moon, Search, Settings, ShieldAlert, Sun, Users } from 'lucide-react'
import { useTheme } from '@/lib/theme'
import { Button } from '@/components/ui/button'
import { cn } from '@/lib/utils'
import { USE_MOCK } from '@/api/client'
import { useAuth } from '@/context/AuthContext'
import { useProjects } from '@/context/ProjectContext'

const NAV = [
  { to: '/', label: 'Monitor', icon: Activity, exact: true },
  { to: '/search', label: 'Search', icon: Search, exact: false },
  { to: '/research', label: 'Research', icon: FlaskConical, exact: false },
  { to: '/connect', label: 'Connect', icon: Link2, exact: false },
  { to: '/settings', label: 'Settings', icon: Settings, exact: false },
  { to: '/admin', label: 'Projects & team', icon: Users, exact: false },
]

export function Layout({ children }: { children: React.ReactNode }) {
  const { toggle, theme } = useTheme()
  const location = useLocation()
  const { user, logout } = useAuth()
  const { projects, selected, select } = useProjects()

  return (
    <div className="min-h-screen flex flex-col bg-background text-foreground">
      <header className="sticky top-0 z-50 border-b bg-background">
        <div className="mx-auto max-w-7xl px-4 sm:px-6">
          <div className="flex min-h-14 items-center gap-3 py-2 sm:gap-4">
            <NavLink to="/" className="flex shrink-0 items-center gap-2.5 rounded-md focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring" aria-label="BreachTrace home">
              <span className="flex h-8 w-8 items-center justify-center rounded-md bg-foreground text-background"><ShieldAlert size={16} strokeWidth={2.5} /></span>
              <span className="hidden text-[15px] font-bold tracking-tight min-[380px]:inline">BreachTrace</span>
            </NavLink>

            <div className="ml-auto flex min-w-0 items-center gap-2 sm:gap-3">
              {projects.length > 0 && <label className="flex min-w-0 items-center gap-2 text-xs text-muted-foreground">
                <span className="hidden sm:inline">Project</span>
                <span className="relative min-w-0">
                  <select aria-label="Current project" className="h-9 w-full max-w-[10rem] min-w-0 appearance-none rounded-md border bg-card py-1 pl-3 pr-9 text-sm text-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring sm:max-w-[13rem]" value={selected?.id ?? ''} onChange={event => select(event.target.value)}>
                    {projects.map(project => <option key={project.id} value={project.id}>{project.name}</option>)}
                  </select>
                  <ChevronDown size={15} aria-hidden="true" className="pointer-events-none absolute right-3 top-1/2 -translate-y-1/2 text-muted-foreground" />
                </span>
              </label>}
              <Button variant="ghost" size="icon" onClick={toggle} aria-label={theme === 'dark' ? 'Switch to light theme' : 'Switch to dark theme'} className="h-9 w-9 shrink-0 rounded-md">
                {theme === 'dark' ? <Sun size={17} /> : <Moon size={17} />}
              </Button>
              {!USE_MOCK && <DropdownMenu.Root>
                <DropdownMenu.Trigger asChild>
                  <Button variant="outline" size="sm" className="h-9 max-w-[12rem] shrink-0 rounded-md px-2.5 sm:px-3" aria-label="Account menu">
                    <CircleUserRound size={16} className="shrink-0" />
                    <span className="hidden truncate sm:inline">{user?.full_name || 'Account'}</span>
                    <ChevronDown size={14} className="shrink-0 text-muted-foreground" />
                  </Button>
                </DropdownMenu.Trigger>
                <DropdownMenu.Portal>
                  <DropdownMenu.Content align="end" sideOffset={8} className="z-[60] min-w-52 rounded-lg border bg-card p-1.5 text-card-foreground shadow-lg">
                    <DropdownMenu.Label className="px-2.5 py-2 text-xs font-normal text-muted-foreground"><span className="block truncate font-medium text-foreground">{user?.full_name}</span><span className="block truncate">{user?.email}</span></DropdownMenu.Label>
                    <DropdownMenu.Separator className="my-1 h-px bg-border" />
                    <DropdownMenu.Item asChild><NavLink to="/change-password" className="flex cursor-pointer items-center gap-2 rounded-md px-2.5 py-2 text-sm outline-none focus:bg-muted"><Settings size={15} />Change password</NavLink></DropdownMenu.Item>
                    <DropdownMenu.Item onSelect={() => void logout()} className="flex cursor-pointer items-center gap-2 rounded-md px-2.5 py-2 text-sm outline-none focus:bg-muted"><LogOut size={15} />Sign out</DropdownMenu.Item>
                  </DropdownMenu.Content>
                </DropdownMenu.Portal>
              </DropdownMenu.Root>}
            </div>
          </div>

          <nav aria-label="Main navigation" className="-mx-4 flex items-center gap-1 overflow-x-auto px-4 sm:-mx-6 sm:px-6">
            {NAV.filter(item => user?.role !== 'developer' || item.to === '/admin' || item.to === '/').map(({ to, label, icon: Icon, exact }) => {
              const active = exact ? location.pathname === to || location.pathname === '/dashboard' || location.pathname.startsWith('/incident/') || location.pathname.startsWith('/incidents/') : location.pathname.startsWith(to)
              return <NavLink key={to} to={to} aria-current={active ? 'page' : undefined} className={cn(
                'relative flex shrink-0 items-center gap-2 border-b-2 px-3 py-3 text-sm font-medium transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-inset focus-visible:ring-ring',
                active ? 'border-foreground text-foreground' : 'border-transparent text-muted-foreground hover:text-foreground'
              )}><Icon size={15} aria-hidden="true" />{label}</NavLink>
            })}
          </nav>
        </div>
      </header>

      <main className="flex-1 mx-auto w-full min-w-0 max-w-7xl px-4 sm:px-6 py-8">
        {USE_MOCK && <p role="note" className="mb-6 rounded border p-3 text-sm">Preview mode · All incidents and research metrics shown here are synthetic. Repository scans and model settings require a running backend.</p>}
        {!USE_MOCK && selected && <p role="note" className="mb-4 text-xs text-muted-foreground">Selected project: {selected.name}. Search, research and snapshot scans cover the whole organisation and are available to administrators and security leads.</p>}
        {children}
      </main>

      <footer className="border-t py-4">
        <div className="mx-auto max-w-7xl px-4 sm:px-6 flex flex-wrap gap-2 items-center justify-between">
          <span className="text-xs font-mono text-muted-foreground">BreachTrace — Credential Forensics Platform</span>
          <span className="text-xs text-muted-foreground">Group 03 · KJSCE IT</span>
        </div>
      </footer>
    </div>
  )
}
