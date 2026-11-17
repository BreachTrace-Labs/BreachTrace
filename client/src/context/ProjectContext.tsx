import { createContext, useCallback, useContext, useEffect, useState } from 'react'
import { realClient, USE_MOCK } from '@/api/client'
import { useAuth } from '@/context/AuthContext'

export type Project = { id: string; name: string; github_repo_url: string; github_repo_full_name: string; webhook_registered_at: string | null; member_count: number; incident_count: number }
type Projects = { projects: Project[]; selected: Project | null; select: (id: string) => void; refresh: () => Promise<void>; error: string }
const Context = createContext<Projects | null>(null)
export function ProjectProvider({ children }: { children: React.ReactNode }) {
  const { user } = useAuth(); const [projects, setProjects] = useState<Project[]>([]); const [id, setId] = useState(''); const [error, setError] = useState('')
  const refresh = useCallback(async () => {
    if (!user || user.must_change_password || USE_MOCK) { setProjects([]); return }
    try { const { data } = await realClient.get<Project[]>('/projects'); setProjects(data); setId(previous => data.some(p => p.id === previous) ? previous : data[0]?.id ?? ''); setError('') }
    catch { setProjects([]); setError('Could not load projects.') }
  }, [user])
  useEffect(() => { void Promise.resolve().then(refresh) }, [refresh])
  return <Context.Provider value={{ projects, selected: projects.find(p => p.id === id) ?? null, select: setId, refresh, error }}>{children}</Context.Provider>
}
// The provider and its hook intentionally share one context module.
// eslint-disable-next-line react-refresh/only-export-components
export function useProjects() { const value = useContext(Context); if (!value) throw new Error('ProjectProvider missing'); return value }
