/** Landing page content for BreachTrace. */
export const LANDING = {
  product: 'BreachTrace',
  valueProp: 'Find exposed credentials, investigate available activity, and coordinate your response.',
  hookFirst: 'A leaked key is',
  hookSecond: 'only the beginning.',
  primaryCta: 'Open BreachTrace',
  secondaryCta: 'See how it works',
  accent: '#fafafa',
  program: 'Credential forensics',
  proof: 'DETECT EXPOSURE  |  INVESTIGATE THE EVIDENCE',
  trustCaption: 'A connected workflow for credential exposure and investigation.',
  logos: ['GITHUB', 'AWS', 'GOOGLE CLOUD', 'AZURE', 'STRIPE', 'TWILIO', 'LOCAL MODELS'],
  incidents: ['Repository exposure', 'Cloud activity', 'Stripe event', 'Twilio activity', 'Detection-only finding', 'Incident report'],
  stats: [
    { value: 2, suffix: '', description: 'Ways to detect: scan a snapshot or monitor new GitHub pushes.', source: 'DETECTION WORKFLOWS' },
    { value: 5, suffix: '', description: 'Provider collectors: AWS, Google Cloud, Azure, Stripe, and Twilio.', source: 'SUBJECT TO PROVIDER ACCESS' },
    { value: 2, suffix: '', description: 'Forensic tiers distinguish supported collection from detection-only findings.', source: 'FORENSIC TIERS' },
  ],
  highlights: [
    { title: 'For project members', description: 'Review incidents in assigned projects and document a dismissal when appropriate.', label: 'REVIEW FINDINGS' },
    { title: 'For responders', description: 'Review available provider events, see the exposure timeline, and refresh supported investigations.', label: 'INVESTIGATE ACTIVITY' },
    { title: 'For administrators', description: 'Manage projects and access, invite users, and review the organisation audit log.', label: 'COORDINATE RESPONSE' },
  ],
  capabilities: ['Project access', 'Signed webhooks', 'Masked credentials', 'Encrypted wallet', 'Audit trail', 'Incident assignment', 'PDF reports', 'Email & Slack alerts'],
  tools: ['GitHub', 'AWS', 'Google Cloud', 'Azure', 'Stripe', 'Twilio', 'OpenAI', 'Anthropic', 'Gemini', 'Ollama', 'Local GGUF'],
}
