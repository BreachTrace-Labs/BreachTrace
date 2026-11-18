import assert from 'node:assert/strict'
import { readFile } from 'node:fs/promises'
import { createElement } from 'react'
import { renderToStaticMarkup } from 'react-dom/server'
import { MemoryRouter } from 'react-router-dom'
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
  const evidence = await server.ssrLoadModule('/src/lib/forensicEvidence.ts')
  const { default: SourceIPs } = await server.ssrLoadModule('/src/components/SourceIPs.tsx')
  const { default: AffectedResources } = await server.ssrLoadModule('/src/components/AffectedResources.tsx')
  const { default: FinancialImpactPanel } = await server.ssrLoadModule('/src/components/FinancialImpactPanel.tsx')
  const { default: ComplianceReview } = await server.ssrLoadModule('/src/components/ComplianceReview.tsx')
  const { complianceFrameworks } = await server.ssrLoadModule('/src/data/compliance.ts')
  assert.deepEqual(complianceFrameworks.map(item => item.id), ['owasp-nhi2', 'gdpr-32-33', 'pci-incident-response', 'soc2-security'])
  const review = renderToStaticMarkup(createElement(MemoryRouter, null, createElement(ComplianceReview, { incident: { credential_type: 'stripe_secret_key', compliance_review_flags: [{id:'pci-incident-response',reason:'Review payment context.'}] } })))
  assert.match(review, /PCI DSS/)
  assert.match(review, /regulations#pci-incident-response/)
  assert.match(review, /not proof/)
  const event = (timestamp, overrides = {}) => ({ timestamp, platform: 'aws', api_action: 'ListBuckets', source_ip: null, affected_resource: null, resource_type: null, success: true, impact_category: 'reconnaissance', severity_weight: 1, ...overrides })
  const recorded = [event('2026-01-01T00:00:00Z'), event('2026-01-02T00:00:00Z', { source_ip: '192.0.2.1', affected_resource: 'bucket' }), event('2026-01-04T00:00:00Z')]
  const windowEvents = evidence.inExposureWindow(recorded, '2026-01-02T00:00:00Z', '2026-01-03T00:00:00Z')
  assert.equal(windowEvents.length, 1)
  assert.equal(evidence.inExposureWindow(recorded, 'invalid', null).length, 0)
  const preview = evidence.previewBlastRadius({ events: recorded, exposure_start: '2026-01-02T00:00:00Z', exposure_end: '2026-01-03T00:00:00Z', forensic_tier: 1, status: 'complete' })
  assert.equal(preview.event_count, 1)
  assert.equal(preview.severity, 'LOW')
  assert.equal(preview.resource_count, 1)
  assert.match(renderToStaticMarkup(createElement(SourceIPs, { events: windowEvents, platform: 'aws', collecting: false, error: false })), /192\.0\.2\.1/)
  assert.match(renderToStaticMarkup(createElement(AffectedResources, { events: windowEvents, collecting: false, error: false })), /bucket/)
  assert.match(renderToStaticMarkup(createElement(SourceIPs, { events: [event('2026-01-02T00:00:00Z')], platform: 'stripe', collecting: false, error: false })), /do not supply source IPs/)
  assert.match(renderToStaticMarkup(createElement(AffectedResources, { events: [], collecting: false, error: false })), /resources are unknown/)
  const finance = { financial_impact_lines: [], financial_history_lines: [{platform:'stripe',kind:'charge',label:'Stripe',text:'Stripe charge',amount:170,currency:'USD',unit:null,quantity:3,actual:true}], estimated_financial_impact: 'stale amount' }
  const exposureFinance = renderToStaticMarkup(createElement(FinancialImpactPanel, { incident: finance, scope: 'window' }))
  assert.match(exposureFinance, /No financial activity found/)
  assert.ok(!exposureFinance.includes('stale amount'))
  const historyFinance = renderToStaticMarkup(createElement(FinancialImpactPanel, { incident: finance, scope: 'history' }))
  assert.match(historyFinance, /All collected history/)
  assert.match(historyFinance, /3 transactions/)
  assert.match(historyFinance, /events outside the exposure window/)
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
