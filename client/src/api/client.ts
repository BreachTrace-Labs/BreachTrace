import axios from 'axios'
import { MOCK_INCIDENTS, MOCK_EXPERIMENT_RUNS, MOCK_STATS } from './mockData'

/* ─── mock client ─────────────────────────────────────────────── */

const MOCK_DELAY_MS = 600

function sleep(ms: number) {
  return new Promise((r) => setTimeout(r, ms))
}

// Route patterns → handlers
type MockHandler = (params: { id?: string }) => unknown

const MOCK_ROUTES: Array<{ pattern: RegExp; handler: MockHandler }> = [
  {
    // GET /incidents/:id/timeline  — not currently used but wired in context doc
    pattern: /^\/incidents\/([^/]+)\/timeline$/,
    handler: ({ id }) => {
      const inc = MOCK_INCIDENTS.find((i) => i.incident_id === id)
      return inc?.events ?? []
    },
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
    // GET /incidents/stats
    pattern: /^\/incidents\/stats$/,
    handler: () => MOCK_STATS,
  },
  {
    // GET /research/export
    pattern: /^\/research\/export$/,
    handler: () => MOCK_EXPERIMENT_RUNS,
  },
]

const mockClient = {
  get: async (url: string) => {
    await sleep(MOCK_DELAY_MS)
    // extract path param if present
    for (const route of MOCK_ROUTES) {
      const match = url.match(route.pattern)
      if (match) {
        const id = match[1]
        const data = route.handler({ id })
        return { data }
      }
    }
    throw { response: { status: 404, data: { detail: `No mock for ${url}` } } }
  },
  // Stub — POST is not used while VITE_USE_MOCK=true; throws clearly instead of silently failing
  post: async (_url: string, _body?: unknown) => {
    throw new Error(`POST ${_url} is not implemented in the mock client`)
  },
} as Pick<ReturnType<typeof axios.create>, 'get' | 'post'>

/* ─── real client ─────────────────────────────────────────────── */

const realClient = axios.create({
  baseURL: import.meta.env.VITE_API_URL ?? 'http://localhost:8000',
  timeout: 30_000,
  headers: {
    'Content-Type': 'application/json',
  },
})

/* ─── export whichever is active ─────────────────────────────── */

// Set VITE_USE_MOCK=true in .env.local (or Vite dev server config) to run
// the UI without a live backend. The mock client returns data from mockData.ts
// and has artificial 600 ms latency to simulate real network round-trips.
const USE_MOCK = import.meta.env.VITE_USE_MOCK === 'true'

const client = USE_MOCK ? mockClient : realClient

export default client

