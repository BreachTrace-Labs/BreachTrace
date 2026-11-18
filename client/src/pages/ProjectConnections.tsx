import { USE_MOCK } from '@/api/client'
import { useProjects } from '@/context/ProjectContext'
import ProjectWallet from '@/components/ProjectWallet'

export default function ProjectConnections() {
  const { selected } = useProjects()
  if (USE_MOCK) return <section><h1 className="text-xl font-semibold">Project connections</h1><p className="mt-3 text-sm text-muted-foreground">Provider connections require a live backend and an assigned project.</p></section>
  if (!selected) return <section><h1 className="text-xl font-semibold">Project connections</h1><p className="mt-3 text-sm text-muted-foreground">No project is assigned to your account. Ask an administrator or security lead to add you to a project.</p></section>
  return <ProjectWallet key={selected.id} projectId={selected.id} projectName={selected.name} />
}
