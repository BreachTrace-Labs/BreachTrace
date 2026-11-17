import { lazy, Suspense } from 'react'
import { BrowserRouter, Navigate, Route, Routes } from 'react-router-dom'
import { ThemeProvider } from './lib/theme'
import { TooltipProvider } from './components/ui/tooltip'
import { Layout } from './components/Layout'
import { AuthProvider, useAuth } from './context/AuthContext'
import { ProjectProvider } from './context/ProjectContext'
import { ChangePassword, Login, Setup } from './pages/Auth'
import Admin from './pages/Admin'
import Dashboard from './pages/Dashboard'
import IncidentDetail from './pages/IncidentDetail'
import Research from './pages/Research'
import Connect from './pages/Connect'
import Search from './pages/Search'
import Settings from './pages/Settings'
const Landing = lazy(() => import('./pages/Landing'))

function ProtectedApp() {
  const { user, loading } = useAuth()
  if (loading) return <main className="p-8">Loading session…</main>
  if (!user) return <Navigate to="/login" replace />
  if (user.must_change_password) return <Navigate to="/change-password" replace />
  if (user.role === 'developer') return <ProjectProvider><Layout><Routes><Route path="/" element={<Dashboard />} /><Route path="/incident/:id" element={<IncidentDetail />} /><Route path="/incidents/:id" element={<IncidentDetail />} /><Route path="/admin" element={<Admin />} /><Route path="*" element={<Navigate to="/" replace />} /></Routes></Layout></ProjectProvider>
  return <ProjectProvider><Layout><Routes>
    <Route path="/" element={<Dashboard />} /><Route path="/dashboard" element={<Dashboard />} />
    <Route path="/incident/:id" element={<IncidentDetail />} /><Route path="/incidents/:id" element={<IncidentDetail />} />
    <Route path="/research" element={<Research />} /><Route path="/connect" element={<Connect />} />
    <Route path="/search" element={<Search />} /><Route path="/settings" element={<Settings />} />
    <Route path="/admin" element={<Admin />} /><Route path="*" element={<Navigate to="/" replace />} />
  </Routes></Layout></ProjectProvider>
}
function App() {
  return <ThemeProvider><TooltipProvider><BrowserRouter><AuthProvider><Routes>
    <Route path="/landing" element={<Suspense fallback={<main className="p-8">Loading…</main>}><Landing /></Suspense>} /><Route path="/setup" element={<Setup />} /><Route path="/login" element={<Login />} />
    <Route path="/change-password" element={<ChangePassword />} /><Route path="/*" element={<ProtectedApp />} />
  </Routes></AuthProvider></BrowserRouter></TooltipProvider></ThemeProvider>
}
export default App
