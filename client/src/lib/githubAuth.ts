import { realClient } from '@/api/client'

type GitHubConfig = { enabled: boolean; client_id: string | null; callback_url: string | null }
const KEY = 'bt_github_oauth'
function base64url(bytes: Uint8Array): string { return btoa(String.fromCharCode(...bytes)).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '') }
export async function startGitHubLogin(destination: string) {
  const { data } = await realClient.get<GitHubConfig>('/auth/github/config')
  if (!data.enabled || !data.client_id || !data.callback_url) throw new Error('GitHub sign-in is not configured. Contact your administrator.')
  const callback = new URL(data.callback_url)
  if (callback.origin !== window.location.origin) throw new Error('GitHub sign-in is configured for a different app address. Open the configured address and try again.')
  const state = base64url(crypto.getRandomValues(new Uint8Array(32)))
  const verifier = base64url(crypto.getRandomValues(new Uint8Array(32)))
  const challenge = base64url(new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(verifier))))
  sessionStorage.setItem(KEY, JSON.stringify({ state, verifier, created: Date.now(), destination }))
  const url = new URL('https://github.com/login/oauth/authorize')
  url.search = new URLSearchParams({ client_id: data.client_id, redirect_uri: data.callback_url, scope: 'user:email', state, code_challenge: challenge, code_challenge_method: 'S256' }).toString()
  window.location.assign(url.toString())
}
export function consumeGitHubCallback(params: URLSearchParams) {
  const raw = sessionStorage.getItem(KEY); sessionStorage.removeItem(KEY)
  if (!raw) throw new Error('GitHub sign-in expired. Please start again.')
  let saved: { state?: unknown; verifier?: unknown; created?: unknown; destination?: unknown }
  try { saved = JSON.parse(raw) } catch { throw new Error('GitHub sign-in expired. Please start again.') }
  if (typeof saved.created !== 'number' || Date.now() - saved.created > 600000 || Date.now() < saved.created || typeof saved.state !== 'string' || params.get('state') !== saved.state || typeof saved.verifier !== 'string') throw new Error('GitHub sign-in expired or could not be verified. Please start again.')
  const code = params.get('code')
  if (!code || params.has('error')) throw new Error('GitHub authorization was cancelled or failed.')
  const destination = typeof saved.destination === 'string' && saved.destination.startsWith('/') && !saved.destination.startsWith('//') ? saved.destination : '/dashboard'
  return { code, verifier: saved.verifier, destination }
}
