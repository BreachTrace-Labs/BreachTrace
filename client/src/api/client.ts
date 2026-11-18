import axios from 'axios'
import type { SearchResult } from '@/types'
import { AI_LABELS, derivePlatform } from '@/lib/platform'
import { isAIIncident } from '@/lib/incidentPresentation'
import {
  MOCK_EXPERIMENT_RUNS,
  MOCK_INCIDENTS,
  MOCK_PLATFORM_COMPARISON,
  MOCK_STATS,
} from './mockData'

/* ─── mock client ─────────────────────────────────────────────── */

const MOCK_DELAY_MS = 600

function sleep(ms: number) {
  return new Promise((r) => setTimeout(r, ms))
}

// Route patterns → handlers
type MockHandler = (params: { id?: string; offset?: number }) => unknown

const MOCK_ROUTES: Array<{ pattern: RegExp; handler: MockHandler }> = [
  {
    pattern: /^\/incidents\/([^/]+)\/related-credentials$/,
    handler: ({ id, offset = 0 }) => {
      const incident = MOCK_INCIDENTS.find(item => item.incident_id === id)
      if (!incident) throw { response: { status: 404 } }
      const items = incident.commit_hash ? MOCK_INCIDENTS.filter(item => item.incident_id !== id && item.commit_hash === incident.commit_hash && item.project_id === incident.project_id && item.repo_url === incident.repo_url) : []
      return { commit_available: Boolean(incident.commit_hash), total: items.length, offset, items: items.slice(offset, offset + 25) }
    },
  },
  {
    // GET /incidents/:id/timeline  — not currently used but wired in context doc
    pattern: /^\/incidents\/([^/]+)\/timeline$/,
    handler: ({ id }) => {
      const inc = MOCK_INCIDENTS.find((i) => i.incident_id === id)
      return inc?.events ?? []
    },
  },
  {
    // GET /incidents/stats
    pattern: /^\/incidents\/stats$/,
    handler: () => MOCK_STATS,
  },
  {
    // GET /incidents/:id
    pattern: /^\/incidents\/([^/]+)$/,
    handler: ({ id }) => {
      const inc = MOCK_INCIDENTS.find((i) => i.incident_id === id)
      if (!inc) throw { response: { status: 404 } }
      return inc
    },
  },
  {
    // GET /incidents
    pattern: /^\/incidents$/,
    handler: () => MOCK_INCIDENTS,
  },
  {
    // GET /research/platforms — per-platform comparison for the headline chart
    pattern: /^\/research\/platforms$/,
    handler: () => MOCK_PLATFORM_COMPARISON,
  },
  {
    // GET /research/export
    pattern: /^\/research\/export$/,
    handler: () => MOCK_EXPERIMENT_RUNS,
  },
]

const mockClient = {
  get: async (url: string, config?: { params?: { offset?: number } }) => {
    await sleep(MOCK_DELAY_MS)
    // extract path param if present
    for (const route of MOCK_ROUTES) {
      const match = url.match(route.pattern)
      if (match) {
        const id = match[1]
        const data = route.handler({ id, offset: config?.params?.offset })
        return { data }
      }
    }
    throw { response: { status: 404, data: { detail: `No mock for ${url}` } } }
  },
  // Stub — POST is not used while VITE_USE_MOCK=true; throws clearly instead of silently failing
  post: async (_url: string, _body?: unknown) => {
    const refreshMatch = _url.match(/^\/incidents\/([^/]+)\/refresh$/)
    if (refreshMatch) {
      await sleep(MOCK_DELAY_MS)
      const id = refreshMatch[1]
      const inc = MOCK_INCIDENTS.find((i) => i.incident_id === id)
      if (!inc) throw { response: { status: 404 } }
      inc.status = 'collecting'
      inc.events = []
      inc.report_text = null
      return {
        data: {
          incident_id: id,
          status: 'collecting',
          message: 'Forensics refresh started. CloudTrail can take up to 15 minutes to surface fresh events.',
        },
      }
    }
    if (_url === '/assistant/search') {
      await sleep(MOCK_DELAY_MS)
      const body = _body as { question?: string; incident_id?: string; generate_answer?: boolean }
      const result = mockSearch(String(body?.question ?? ''), body?.incident_id)
      if (body?.generate_answer) result.generated_answer = {
        status: 'unavailable',
        message: 'Model answers require the live backend and a model selected in Settings.',
      }
      return { data: result }
    }
    throw new Error(`POST ${_url} is not implemented in the mock client`)
  },
} as Pick<ReturnType<typeof axios.create>, 'get' | 'post'>

/** Mock search: platform-word match over mock incidents. The real one is retrieval over a KB. */
function mockSearch(question: string, incidentId?: string): SearchResult {
  const q = question.toLowerCase()
  const aliases: Record<string, string> = { claude: 'anthropic', gpt: 'openai', chatgpt: 'openai', grok: 'xai' }
  const platforms = [...Object.keys(AI_LABELS), 'aws', 'gcp', 'azure', 'stripe', 'twilio', 'github']
    .filter(p => q.includes(p))
  for (const [alias, provider] of Object.entries(aliases)) if (q.includes(alias)) platforms.push(provider)
  const selected = MOCK_INCIDENTS.filter(i => incidentId ? i.incident_id === incidentId
    : platforms.length ? platforms.includes(derivePlatform(i)) : /\bai\b/.test(q) ? isAIIncident(i) : /\b(incidents?|detections?|show|list)\b/.test(q))
  const incidents = selected.map((i) => ({
    incident_id: i.incident_id,
    platform: i.platform ?? 'aws',
    credential_type: i.credential_type,
    credential_hint: i.credential_hint,
    repo_url: i.repo_url,
    exposure_start: i.exposure_start,
    status: i.status,
    overall_severity: i.overall_severity,
    forensic_tier: i.forensic_tier ?? 1,
  }))
  return {
    question,
    intent: incidentId ? 'knowledge' : incidents.length ? 'incidents' : 'knowledge',
    disclaimer: 'Synthetic preview results. Real search requires the backend; these examples are not evidence of a breach.',
    filters: {},
    incidents,
    passages: incidentId ? selected.filter(i => i.report_text).map(i => ({
      id: `demo:${i.incident_id}`, source_type: 'incident', source_id: i.incident_id,
      title: 'Synthetic incident report', text: i.report_text ?? '', highlight: '', similarity: null,
    })) : [],
    confident: incidents.length > 0,
    semantic: false,
    suggestions: incidents.length ? [] : ['AI incidents', 'Sarvam incidents', 'Claude incidents'],
  }
}

/* ─── real client ─────────────────────────────────────────────── */

export const realClient = axios.create({
  baseURL: import.meta.env.VITE_API_URL ?? 'http://localhost:8000',
  timeout: 30_000,
  headers: {
    'Content-Type': 'application/json',
  },
})

realClient.interceptors.request.use(config => {
  const token = localStorage.getItem('bt_token')
  if (token) config.headers.Authorization = `Bearer ${token}`
  return config
})
realClient.interceptors.response.use(response => response, error => {
  if (error.response?.status === 401 && localStorage.getItem('bt_token') && !error.config?.url?.startsWith('/auth/token')) {
    localStorage.removeItem('bt_token')
    window.dispatchEvent(new Event('bt-session-expired'))
  }
  return Promise.reject(error)
})

/* ─── export whichever is active ─────────────────────────────── */

// Mock mode returns data from mockData.ts with 600 ms of artificial latency so
// the UI can be developed without a backend.
//
// Resolution order:
//   VITE_USE_MOCK=true   → always mock
//   VITE_USE_MOCK=false  → always live, even with no VITE_API_URL set
//   unset                → mock only when no VITE_API_URL is configured
//
// The unset case keeps a fresh clone usable with no setup, while a configured
// API URL means someone intends to talk to a real backend.
const mockFlag = import.meta.env.VITE_USE_MOCK
export const USE_MOCK =
  mockFlag === 'true' || (mockFlag === undefined && !import.meta.env.VITE_API_URL)

if (import.meta.env.DEV) {
  console.info(
    USE_MOCK
      ? '[BreachTrace] Mock API — set VITE_API_URL to use a live backend.'
      : `[BreachTrace] Live API — ${import.meta.env.VITE_API_URL ?? 'http://localhost:8000'}`,
  )
}

const client = USE_MOCK ? mockClient : realClient

export default client
