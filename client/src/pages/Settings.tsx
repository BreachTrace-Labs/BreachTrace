import { useEffect, useState } from 'react'
import { realClient as api } from '@/api/client'
import { Button } from '@/components/ui/button'

type SettingsData = { provider: string; model: string; ollama_url: string; model_path: string; timeout_s: number; api_key_configured: boolean }
const initial: SettingsData = { provider: 'none', model: '', ollama_url: 'http://127.0.0.1:11434', model_path: '', timeout_s: 60, api_key_configured: false }

export default function Settings() {
  const [settings, setSettings] = useState(initial)
  const [key, setKey] = useState('')
  const [clearKey, setClearKey] = useState(false)
  const [message, setMessage] = useState('')
  const [busy, setBusy] = useState(true)
  const [ready, setReady] = useState(false)
  const [hardware, setHardware] = useState('')
  const [dirty, setDirty] = useState(false)
  useEffect(() => {
    let active = true
    Promise.all([api.get('/settings/model'), api.get('/settings/model/hardware')])
      .then(([model, host]) => { if (active) { setSettings(model.data); setReady(true); setHardware(`${host.data.os} ${host.data.architecture} · ${host.data.cpu_count ?? '?'} CPU cores · ${host.data.ram_gb ?? 'unknown'} GB RAM`) } })
      .catch(() => { if (active) setMessage('Cannot load settings. Connect to the local backend to configure models.') })
      .finally(() => { if (active) setBusy(false) })
    return () => { active = false }
  }, [])
  function change(field: string, value: string | number) {
    setSettings(s => ({ ...s, [field]: value }))
    setDirty(true)
    setMessage('')
    if (field === 'provider') { setKey(''); setClearKey(false); setSettings(s => ({ ...s, api_key_configured: false })) }
  }
  async function save() {
    setBusy(true); setMessage('')
    try {
      const { data } = await api.put('/settings/model', { ...settings, api_key: key || undefined, clear_api_key: clearKey })
      setSettings(data); setKey(''); setClearKey(false); setDirty(false)
      setMessage('Saved. Entered API keys stay in server memory until restart.')
    } catch { setMessage('Settings could not be saved. Check the selected model and local backend connection.') }
    finally { setBusy(false) }
  }
  async function test() {
    setBusy(true)
    try { const { data } = await api.post('/settings/model/test', undefined, { timeout: 310_000 }); setMessage(data.message) }
    catch { setMessage('Model check failed. Check credentials, model access, or the local runtime.') }
    finally { setBusy(false) }
  }
  const cloud = ['openai', 'anthropic', 'gemini'].includes(settings.provider)
  const inputClass = 'block w-full border rounded p-2 bg-transparent mt-1'
  return <div className="max-w-2xl mx-auto space-y-6">
    <h1 className="text-xl font-bold">Model settings</h1>
    <p>Choose the model that writes report prose and, when requested, answers Search questions from retrieved evidence. Incident facts, severity and remediation remain checked by BreachTrace. No model is bundled or downloaded automatically.</p>
    <p className="text-sm text-[var(--color-muted-foreground)]">Backend hardware: {hardware || 'Loading…'}. Local model memory needs depend on model size, quantization and context. Use measured benchmark results for this machine.</p>
    <form onSubmit={e => { e.preventDefault(); void save() }} className="space-y-4">
      <label className="block">Provider<select className={inputClass} disabled={!ready || busy} value={settings.provider} onChange={e => change('provider', e.target.value)}>
        <option value="none">Deterministic reports (no model)</option><option value="openai">OpenAI</option><option value="anthropic">Anthropic / Claude</option><option value="gemini">Google Gemini</option><option value="ollama">Local model via Ollama</option><option value="local">Local GGUF via llama.cpp</option>
      </select></label>
      {!['none', 'local'].includes(settings.provider) && <label className="block">Model name<input required className={inputClass} value={settings.model} onChange={e => change('model', e.target.value)} placeholder="Exact model ID available to your account or installed locally" /></label>}
      {settings.provider === 'ollama' && <label className="block">Ollama address<input className={inputClass} value={settings.ollama_url} onChange={e => change('ollama_url', e.target.value)} /></label>}
      {settings.provider === 'local' && <label className="block">GGUF file on backend machine<input required className={inputClass} value={settings.model_path} onChange={e => change('model_path', e.target.value)} /><span className="text-sm">Requires the optional llama.cpp runtime and a passing quality-gate manifest.</span></label>}
      {cloud && <>
        <p className="text-sm">Report facts will be sent to the selected provider. Its usage charges and data policies apply. The connection check sends a short test prompt.</p>
        <label className="block">API key<input type="password" autoComplete="off" className={inputClass} value={key} onChange={e => { setKey(e.target.value); setDirty(true) }} placeholder={settings.api_key_configured ? 'Configured; leave blank to keep' : 'Enter key (not saved to disk)'} /></label>
        <label className="flex items-center gap-2"><input type="checkbox" checked={clearKey} onChange={e => { setClearKey(e.target.checked); setDirty(true) }} />Clear the key held in server memory (environment key may still apply)</label>
      </>}
      <label className="block">Request timeout (seconds)<input className={inputClass} type="number" min={5} max={300} value={settings.timeout_s} onChange={e => change('timeout_s', Number(e.target.value))} /></label>
      <div className="flex gap-3"><Button disabled={!ready || busy} type="submit">{busy ? 'Working…' : 'Save settings'}</Button><Button disabled={!ready || busy || dirty} type="button" variant="outline" onClick={() => void test()}>Test saved model</Button></div>
      {dirty && <p className="text-sm">Save changes before testing the connection.</p>}
    </form>
    {message && <p role="status" className="border rounded p-3">{message}</p>}
  </div>
}
