import { NavLink, useLocation } from 'react-router-dom'
import { Moon, Sun, Activity, FlaskConical, ShieldAlert, Link2, Search } from 'lucide-react'
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
  { to: '/settings', label: 'Settings', icon: Link2, exact: false },
  { to: '/admin', label: 'Projects & team', icon: Link2, exact: false },
]

export function Layout({ children }: { children: React.ReactNode }) {
  const { toggle, theme } = useTheme()
  const location = useLocation()
  const { user, logout } = useAuth()
  const { projects, selected, select } = useProjects()

  return (
    <div
      className="min-h-screen flex flex-col"
      style={{ backgroundColor: 'var(--color-background)', color: 'var(--color-foreground)' }}
    >
      {/* Top bar */}
      <header
        className="sticky top-0 z-50 border-b"
        style={{
          backgroundColor: 'var(--color-background)',
          borderColor: 'var(--color-border)',
        }}
      >
        <div className="mx-auto max-w-7xl px-4 sm:px-6 min-h-14 py-2 flex flex-wrap items-center gap-x-4 gap-y-2 sm:gap-x-8">
          {/* Logo */}
          <div className="flex items-center gap-2.5 shrink-0">
            <div
              className="w-7 h-7 flex items-center justify-center"
              style={{ backgroundColor: 'var(--color-foreground)', borderRadius: '4px' }}
            >
              <ShieldAlert
                size={15}
                strokeWidth={2.5}
                style={{ color: 'var(--color-background)' }}
              />
            </div>
            <span className="text-[15px] font-bold tracking-tight">BreachTrace</span>
          </div>

          {/* Nav */}
          <nav aria-label="Main navigation" className="order-3 w-full flex flex-wrap items-center gap-1 sm:order-none sm:w-auto">
            {NAV.filter(item => user?.role !== 'developer' || item.to === '/admin').map(({ to, label, exact }) => {
              const active = exact ? location.pathname === to : location.pathname.startsWith(to)
              return (
                <NavLink
                  key={to}
                  to={to}
                  className={cn(
                    'px-3 py-1.5 text-sm font-medium transition-colors rounded',
                    active
                      ? 'text-[var(--color-foreground)]'
                      : 'text-[var(--color-muted-foreground)] hover:text-[var(--color-foreground)]'
                  )}
                >
                  {label}
                </NavLink>
              )
            })}
          </nav>

          {/* Spacer */}
          <div className="flex-1" />

          {projects.length > 0 && <label className="text-xs">Project <select aria-label="Current project" className="border rounded p-1 bg-transparent" value={selected?.id ?? ''} onChange={event => select(event.target.value)}>{projects.map(project => <option key={project.id} value={project.id}>{project.name}</option>)}</select></label>}
          {!USE_MOCK && <><span className="text-sm">{user?.full_name}</span><NavLink to="/change-password" className="text-xs underline">Change password</NavLink><Button variant="outline" size="sm" onClick={() => void logout()}>Sign out</Button></>}

          {/* Theme toggle */}
          <Button
            variant="ghost"
            size="icon"
            onClick={toggle}
            aria-label="Toggle theme"
            className="w-8 h-8"
          >
            {theme === 'dark' ? (
              <Sun size={15} strokeWidth={2} />
            ) : (
              <Moon size={15} strokeWidth={2} />
            )}
          </Button>
        </div>
      </header>

      {/* Main */}
      <main className="flex-1 mx-auto w-full min-w-0 max-w-7xl px-4 sm:px-6 py-8">
        {USE_MOCK && <p role="note" className="mb-6 rounded border p-3 text-sm">Preview mode · All incidents and research metrics shown here are synthetic. Repository scans and model settings require a running backend.</p>}
        {!USE_MOCK && selected && <p role="note" className="mb-4 text-xs text-muted-foreground">Selected project: {selected.name}. Incident and scan filtering by project is not available yet.</p>}
        {children}
      </main>

      {/* Footer */}
      <footer
        className="border-t py-4"
        style={{ borderColor: 'var(--color-border)' }}
      >
        <div className="mx-auto max-w-7xl px-4 sm:px-6 flex flex-wrap gap-2 items-center justify-between">
          <span className="text-xs font-mono" style={{ color: 'var(--color-muted-foreground)' }}>
            BreachTrace — Credential Forensics Platform
          </span>
          <span className="text-xs" style={{ color: 'var(--color-muted-foreground)' }}>
            Group 03 · KJSCE IT
          </span>
        </div>
      </footer>
    </div>
  )
}
