import { createContext, useCallback, useContext, useEffect, useRef, useState } from 'react'
import { realClient, USE_MOCK } from '@/api/client'
import { useAuth } from '@/context/AuthContext'

export type Project = { id: string; name: string; github_repo_url: string; github_repo_full_name: string; webhook_registered_at: string | null; webhook_last_verified_at?: string | null; created_at?: string | null; member_count: number; incident_count: number }
type Projects = { projects: Project[]; selected: Project | null; select: (id: string) => void; refresh: () => Promise<void>; error: string; loading: boolean }
const Context = createContext<Projects | null>(null)
export function ProjectProvider({ children }: { children: React.ReactNode }) {
  const { user } = useAuth(); const [projects, setProjects] = useState<Project[]>([]); const [id, setId] = useState(''); const [error, setError] = useState(''); const [loading, setLoading] = useState(true)
  const loadedFor = useRef<string | null>(null)
  const refresh = useCallback(async () => {
    if (!user || user.must_change_password || USE_MOCK) { setProjects([]); setLoading(false); return }
    if (loadedFor.current !== user.id) setLoading(true)
    try { const { data } = await realClient.get<Project[]>('/projects'); setProjects(data); setId(previous => { const saved = sessionStorage.getItem(`bt_project_${user.id}`); return data.some(p => p.id === previous) ? previous : data.some(p => p.id === saved) ? saved! : data[0]?.id ?? '' }); setError(''); loadedFor.current = user.id }
    catch { setError('Could not load projects.') }
    finally { setLoading(false) }
  }, [user])
  useEffect(() => { void Promise.resolve().then(refresh) }, [refresh])
  const select = useCallback((projectId: string) => { setId(projectId); if (user) sessionStorage.setItem(`bt_project_${user.id}`, projectId) }, [user])
  return <Context.Provider value={{ projects, selected: projects.find(p => p.id === id) ?? null, select, refresh, error, loading }}>{children}</Context.Provider>
}
// The provider and its hook intentionally share one context module.
// eslint-disable-next-line react-refresh/only-export-components
export function useProjects() { const value = useContext(Context); if (!value) throw new Error('ProjectProvider missing'); return value }
