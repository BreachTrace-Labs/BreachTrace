import assert from 'node:assert/strict'
import { readFile } from 'node:fs/promises'
import { createElement } from 'react'
import { renderToStaticMarkup } from 'react-dom/server'
import { createServer } from 'vite'

// Exercise real presentation logic/components without adding a browser runtime.
const server = await createServer({
  server: { middlewareMode: true, hmr: false, ws: false }, appType: 'custom',
  cacheDir: 'node_modules/.vite-ui-checks', optimizeDeps: { noDiscovery: true, include: [] },
})
try {
  const ui = await server.ssrLoadModule('/src/lib/incidentPresentation.ts')
  const fixtures = JSON.parse(await readFile(new URL('../src/api/aiDemoIncidents.json', import.meta.url), 'utf8'))
  const all = [...fixtures, { credential_type: 'github_pat', forensic_tier: 2, status: 'complete' }, { credential_type: 'aws_access_key', status: 'complete' }]
  assert.equal(all.filter(i => ui.filterIncident(i, 'ai')).length, 6)
  assert.equal(all.filter(i => ui.filterIncident(i, 'other')).length, 1)
  assert.equal(all.filter(i => ui.filterIncident(i, 'aws')).length, 1)
  assert.equal(all.filter(i => ui.filterIncident(i, 'all')).length, 8)
  for (const fixture of fixtures) {
    assert.equal(ui.isSyntheticIncident(fixture), true)
    assert.equal(ui.completeLabel(fixture), 'Detection complete')
    assert.equal(ui.exposureLabel(fixture), 'Demo credential')
    assert.equal(ui.exposureDuration(fixture), 'Demo')
    assert.equal(ui.repositoryLink(fixture.repo_url), null)
  }
  assert.equal(ui.exposureLabel({ exposure_end: null }), 'Closure not confirmed')
  assert.equal(ui.exposureDuration({ exposure_start: '2026-01-01T00:00:00Z' }), 'Not confirmed')
  assert.equal(ui.exposureDuration({ exposure_start: '2026-01-01T02:00:00Z', exposure_end: '2026-01-01T00:00:00Z' }), 'Invalid timestamps')
  assert.equal(ui.exposureDuration({ exposure_start: '2026-01-01T00:00:00Z', exposure_end: '2026-01-01T01:01:02Z' }), '1h 1m 2s')
  assert.equal(ui.repositoryLink('javascript:alert(1)'), null)
  assert.equal(ui.repositoryLink('https://token@github.com/team/repo'), null)
  assert.equal(ui.repositoryLink('https://github.com/team/repo'), 'https://github.com/team/repo')
  const { default: Notice } = await server.ssrLoadModule('/src/components/SyntheticNotice.tsx')
  const { default: Unavailable } = await server.ssrLoadModule('/src/components/ForensicsUnavailable.tsx')
  assert.match(renderToStaticMarkup(createElement(Notice)), /Synthetic demo data/)
  for (const fixture of fixtures) {
    const html = renderToStaticMarkup(createElement(Unavailable, { incident: fixture }))
    assert.match(html, /Forensic reconstruction unavailable/)
    assert.match(html, /have not been verified/)
    assert.ok(!html.includes('Awaiting forensic data'))
  }
  console.log('UI checks passed: AI/Other filters, synthetic labels, unknown closure, durations, safe links and six detection-only panels.')
} finally {
  await server.close()
}
