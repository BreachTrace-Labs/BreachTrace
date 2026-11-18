import { createContext, useCallback, useContext, useEffect, useState } from 'react'
import { realClient, USE_MOCK } from '@/api/client'

export type User = { id: string; email: string; full_name: string; role: 'org_admin' | 'security_lead' | 'developer'; organisation_id: string; must_change_password: boolean; has_password?: boolean }
type Auth = { user: User | null; loading: boolean; login: (email: string, password: string) => Promise<void>; logout: () => Promise<void>; reload: () => Promise<void>; startPreview: () => void; githubLogin: (code: string, verifier: string) => Promise<User> }
const AuthContext = createContext<Auth | null>(null)
const mockUser: User = { id: 'preview', email: '', full_name: 'Preview', role: 'org_admin', organisation_id: '', must_change_password: false }

export function AuthProvider({ children }: { children: React.ReactNode }) {
  const [user, setUser] = useState<User | null>(USE_MOCK && sessionStorage.getItem('bt_preview_signed_out') !== 'true' ? mockUser : null)
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
  const githubLogin = async (code: string, verifier: string) => {
    const { data } = await realClient.post<{ access_token: string; user: User }>('/auth/github/exchange', { code, code_verifier: verifier })
    localStorage.setItem('bt_token', data.access_token); setUser(data.user); return data.user
  }
  const startPreview = () => { if (USE_MOCK) { sessionStorage.removeItem('bt_preview_signed_out'); setUser(mockUser) } }
  const logout = async () => {
    try { if (!USE_MOCK) await realClient.post('/auth/logout') }
    finally { if (USE_MOCK) sessionStorage.setItem('bt_preview_signed_out', 'true'); else localStorage.removeItem('bt_token'); setUser(null) }
  }
  return <AuthContext.Provider value={{ user, loading, login, logout, reload, startPreview, githubLogin }}>{children}</AuthContext.Provider>
}

// The provider and its hook intentionally share one context module.
// eslint-disable-next-line react-refresh/only-export-components
export function useAuth() {
  const value = useContext(AuthContext)
  if (!value) throw new Error('AuthProvider missing')
  return value
}
