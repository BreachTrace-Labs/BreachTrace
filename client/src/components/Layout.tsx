import { NavLink, useLocation } from 'react-router-dom'
import { Moon, Sun, Activity, FlaskConical, ShieldAlert } from 'lucide-react'
import { useTheme } from '@/lib/theme'
import { Button } from '@/components/ui/button'
import { cn } from '@/lib/utils'

const NAV = [
  { to: '/', label: 'Monitor', icon: Activity, exact: true },
  { to: '/research', label: 'Research', icon: FlaskConical, exact: false },
]

export function Layout({ children }: { children: React.ReactNode }) {
  const { toggle, theme } = useTheme()
  const location = useLocation()

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
        <div className="mx-auto max-w-7xl px-6 h-14 flex items-center gap-8">
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
          <nav className="flex items-center gap-1">
            {NAV.map(({ to, label, exact }) => {
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
      <main className="flex-1 mx-auto w-full max-w-7xl px-6 py-8">{children}</main>

      {/* Footer */}
      <footer
        className="border-t py-4"
        style={{ borderColor: 'var(--color-border)' }}
      >
        <div className="mx-auto max-w-7xl px-6 flex items-center justify-between">
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
