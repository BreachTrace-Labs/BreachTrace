import { lazy, Suspense, useEffect } from 'react'
import { BrowserRouter, Navigate, Route, Routes, matchPath, useLocation } from 'react-router-dom'
import { ThemeProvider, useTheme } from './lib/theme'
import { Moon, Sun } from 'lucide-react'
import { Spinner } from './components/ui/spinner'
import { ToastProvider, useToast } from './components/ui/toast'
import { TooltipProvider } from './components/ui/tooltip'
import { Layout } from './components/Layout'
import { AuthProvider, useAuth } from './context/AuthContext'
import { ProjectProvider, useProjects } from './context/ProjectContext'
import { USE_MOCK } from './api/client'
import { ChangePassword, Login, Setup } from './pages/Auth'
import Admin from './pages/Admin'
import Dashboard from './pages/Dashboard'
import IncidentDetail from './pages/IncidentDetail'
import Research from './pages/Research'
import Connect from './pages/Connect'
import Search from './pages/Search'
import Settings from './pages/Settings'
import Onboarding from './pages/Onboarding'
import NotFound from './pages/NotFound'
import ErrorBoundary from './components/ErrorBoundary'
import GitHubCallback from './pages/GitHubCallback'
const DesignSystemPreview = lazy(() => import('./components/ui/DesignSystemPreview'))
const Landing = lazy(() => import('./pages/Landing'))

function PageTitle() {
  const { pathname } = useLocation()
  const { user } = useAuth()
  useEffect(() => {
    const names: Record<string, string> = { '/': 'BreachTrace', '/dashboard': 'Dashboard', '/login': 'Sign in', '/setup': 'Setup', '/change-password': 'Change password', '/onboarding': 'Onboarding', '/connect': 'Connect', '/search': 'Search', '/settings': 'Settings', '/research': 'Research', '/admin': 'Admin', '/landing': 'BreachTrace', '/design-system': 'Design system' }
    const incident = pathname.match(/^\/incidents?\/([^/]+)$/)
    const title = incident ? `Incident ${incident[1]}` : pathname.startsWith('/admin/projects/') ? 'Project settings' : names[pathname] ?? 'Page not found'
    document.title = title === 'BreachTrace' ? title : `${title} — BreachTrace`
  }, [pathname, user])
  return null
}
function AdminDenied() {
  const { toast } = useToast()
  useEffect(() => { toast("You don't have access to that page.", 'warning') }, [toast])
  return <Navigate to="/dashboard" replace />
}
function ProtectedRoutes() {
  const { user } = useAuth()
  const { projects, loading, error, refresh } = useProjects()
  if (loading) return <main className="ui-session-loading"><Spinner /><span>Loading projects…</span></main>
  if (error) return <main className="ui-session-loading"><span role="alert">{error}</span><button type="button" onClick={() => void refresh()}>Try again</button></main>
  if (!USE_MOCK && user?.role === 'org_admin' && !projects.length && sessionStorage.getItem(`bt_onboarding_skipped_${user.id}`) !== 'true') return <Navigate to="/onboarding" replace />
  if (user?.role === 'developer') return <Layout><Routes><Route path="/dashboard" element={<Dashboard />} /><Route path="/settings" element={<Settings />} /><Route path="/incident/:id" element={<IncidentDetail />} /><Route path="/incidents/:id" element={<IncidentDetail />} /><Route path="/admin" element={<AdminDenied />} /><Route path="/admin/projects/:projectId" element={<AdminDenied />} /><Route path="*" element={<NotFound />} /></Routes></Layout>
  return <Layout><Routes>
    <Route path="/dashboard" element={<Dashboard />} />
    <Route path="/incident/:id" element={<IncidentDetail />} /><Route path="/incidents/:id" element={<IncidentDetail />} />
    <Route path="/research" element={<Research />} /><Route path="/connect" element={<Connect />} />
    <Route path="/search" element={<Search />} /><Route path="/settings" element={<Settings />} />
    <Route path="/admin" element={<Admin />} /><Route path="/admin/projects/:projectId" element={<Admin />} /><Route path="*" element={<NotFound />} />
  </Routes></Layout>
}
function ProtectedApp() {
  const { user, loading } = useAuth()
  const location = useLocation()
  if (loading) return <main className="ui-session-loading"><Spinner /><span>Checking session…</span></main>
  if (!user) { const known = ['/dashboard', '/incident/:id', '/incidents/:id', '/research', '/connect', '/search', '/settings', '/admin', '/admin/projects/:projectId'].some(path => matchPath({ path, end: true }, location.pathname)); return known ? <Navigate to="/login" state={{ from: location.pathname + location.search }} replace /> : <NotFound /> }
  if (user.must_change_password) return <Navigate to="/change-password" replace />
  return <ProjectProvider><ProtectedRoutes /></ProjectProvider>
}
function StandaloneThemeToggle() {
  const { pathname } = useLocation()
  const { theme, toggle } = useTheme()
  if (!['/login', '/setup', '/change-password', '/onboarding', '/auth/github/callback'].includes(pathname)) return null
  const label = theme === 'dark' ? 'Switch to light theme' : 'Switch to dark theme'
  return <button type="button" className="standalone-theme-toggle" onClick={toggle} aria-label={label} title={label}>{theme === 'dark' ? <Sun size={18} /> : <Moon size={18} />}</button>
}
function App() {
  return <ErrorBoundary><ThemeProvider><ToastProvider><TooltipProvider><BrowserRouter><AuthProvider><PageTitle /><StandaloneThemeToggle /><Routes>
    {import.meta.env.DEV && <Route path="/design-system" element={<Suspense fallback={<main>Loading…</main>}><DesignSystemPreview /></Suspense>} />}<Route path="/landing" element={<Navigate to="/" replace />} /><Route path="/" element={<Suspense fallback={<main className="p-8">Loading…</main>}><Landing /></Suspense>} /><Route path="/setup" element={<Setup />} /><Route path="/login" element={<Login />} />
    <Route path="/auth/github/callback" element={<GitHubCallback />} /><Route path="/onboarding" element={<ProjectProvider><Onboarding /></ProjectProvider>} /><Route path="/change-password" element={<ChangePassword />} /><Route path="/*" element={<ProtectedApp />} />
  </Routes></AuthProvider></BrowserRouter></TooltipProvider></ToastProvider></ThemeProvider></ErrorBoundary>
}
export default App
