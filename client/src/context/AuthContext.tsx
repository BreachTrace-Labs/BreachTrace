import { createContext, useCallback, useContext, useEffect, useState } from 'react'
import { realClient, USE_MOCK } from '@/api/client'

export type User = { id: string; email: string; full_name: string; role: 'org_admin' | 'security_lead' | 'developer'; organisation_id: string; must_change_password: boolean }
type Auth = { user: User | null; loading: boolean; login: (email: string, password: string) => Promise<void>; logout: () => Promise<void>; reload: () => Promise<void> }
const AuthContext = createContext<Auth | null>(null)
const mockUser: User = { id: 'preview', email: '', full_name: 'Preview', role: 'org_admin', organisation_id: '', must_change_password: false }

export function AuthProvider({ children }: { children: React.ReactNode }) {
  const [user, setUser] = useState<User | null>(USE_MOCK ? mockUser : null)
  const [loading, setLoading] = useState(!USE_MOCK && !!localStorage.getItem('bt_token'))
  const reload = useCallback(async () => {
    if (USE_MOCK) return
    if (!localStorage.getItem('bt_token')) { setUser(null); setLoading(false); return }
    try { const { data } = await realClient.get<User>('/auth/me'); setUser(data) }
    catch { setUser(null) }
    finally { setLoading(false) }
  }, [])
  useEffect(() => {
    void reload()
    const expired = () => setUser(null)
    window.addEventListener('bt-session-expired', expired)
    return () => window.removeEventListener('bt-session-expired', expired)
  }, [reload])
  const login = async (email: string, password: string) => {
    const { data } = await realClient.post<{ access_token: string; user: User }>('/auth/token', new URLSearchParams({ username: email, password }), { headers: { 'Content-Type': 'application/x-www-form-urlencoded' } })
    localStorage.setItem('bt_token', data.access_token); setUser(data.user)
  }
  const logout = async () => {
    try { if (!USE_MOCK) await realClient.post('/auth/logout') }
    finally { localStorage.removeItem('bt_token'); setUser(null) }
  }
  return <AuthContext.Provider value={{ user, loading, login, logout, reload }}>{children}</AuthContext.Provider>
}

// The provider and its hook intentionally share one context module.
// eslint-disable-next-line react-refresh/only-export-components
export function useAuth() {
  const value = useContext(AuthContext)
  if (!value) throw new Error('AuthProvider missing')
  return value
}
