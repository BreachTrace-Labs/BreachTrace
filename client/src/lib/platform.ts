/**
 * Single source of truth for cloud-platform identity in the UI.
 *
 * Mirrors `IncidentRecord.platform` in backend/db/models.py — the backend derives
 * platform from credential_type rather than storing it as a column, so the same
 * derivation has to exist here for two reasons:
 *
 *   1. `/incidents` did not return `platform` before the multi-platform API
 *      landed. Reading the field blindly makes the platform filter silently
 *      match nothing on a live backend.
 *   2. Mock data and live data must agree on how a platform is named.
 *
 * Keep `derivePlatform` in lockstep with `_derive_platform()` in
 * backend/routers/incidents.py.
 */

export const AI_LABELS = {
  openai: "OpenAI / GPT",
  anthropic: "Anthropic / Claude",
  gemini: "Google Gemini",
  googleai: "Google API key (AI usage unconfirmed)",
  groq: "Groq",
  xai: "xAI / Grok",
  openrouter: "OpenRouter",
  deepseek: "DeepSeek",
  mistral: "Mistral",
  cohere: "Cohere",
  together: "Together AI",
  perplexity: "Perplexity",
  replicate: "Replicate",
  sarvam: "Sarvam AI",
  cerebras: "Cerebras",
  fireworks: "Fireworks AI",
  nvidia: "NVIDIA NIM",
  ai21: "AI21",
  deepinfra: "DeepInfra",
  sambanova: "SambaNova",
  anyscale: "Anyscale",
  lepton: "Lepton AI",
  siliconflow: "SiliconFlow",
  moonshot: "Moonshot / Kimi",
  zhipu: "Zhipu / Z.ai",
  dashscope: "Alibaba DashScope / Qwen",
  minimax: "MiniMax",
  baidu: "Baidu / Qianfan",
  azureopenai: "Azure OpenAI / Foundry",
  huggingface: "Hugging Face",
  voyage: "Voyage AI",
  jina: "Jina AI",
  runpod: "RunPod",
  fal: "fal.ai",
  stability: "Stability AI",
  elevenlabs: "ElevenLabs",
  assemblyai: "AssemblyAI",
  deepgram: "Deepgram",
  cartesia: "Cartesia",
  novita: "Novita AI",
  nebius: "Nebius AI",
  baseten: "Baseten",
  friendli: "FriendliAI",
  aimlapi: "AI/ML API",
  bedrock: "Amazon Bedrock bearer token",
  vertexai: "Google Vertex AI",
  volcengine: "Volcengine / Doubao",
  hunyuan: "Tencent Hunyuan",
  ollama: "Ollama cloud",
} as const
type AIPlatform = keyof typeof AI_LABELS

export type Platform = AIPlatform
  | 'aws' | 'gcp' | 'azure'          // cloud, Tier 1
  | 'stripe' | 'twilio'              // SaaS, Tier 1
  | 'github' | 'slack' | 'npm' | 'sendgrid' | 'huggingface' | 'db'  // Tier 2

export const PLATFORMS: Platform[] = [
  'aws', 'gcp', 'azure', 'stripe', 'twilio',
  'github', 'slack', 'npm', 'sendgrid', 'db',
  ...Object.keys(AI_LABELS) as AIPlatform[],
]

/** Platforms with a queryable audit log — these produce a real timeline. */
export const FORENSIC_PLATFORMS: Platform[] = ['aws', 'gcp', 'azure', 'stripe', 'twilio']

/**
 * Dashboard filter options. Deliberately not every platform: eleven filter
 * chips is unusable, and the ones that matter for filtering are the Tier-1
 * platforms plus a catch-all for detection-only findings.
 */
export const PLATFORM_FILTERS = ['All', 'AWS', 'GCP', 'Azure', 'Stripe', 'Twilio', 'Other'] as const

interface PlatformMeta {
  /** Display name used in tables, filters and chart axes. */
  label: string
  /** Vendor name of the audit log this platform's events come from. */
  auditLog: string
  /** Theme token for the platform's accent colour. */
  color: string
  /** What the leaked credential is called on this platform. */
  identityLabel: string
}

export const PLATFORM_META: Record<Platform, PlatformMeta> = {
  ...Object.fromEntries(Object.entries(AI_LABELS).map(([key, label]) => [key, {
    label, auditLog: 'AI credential detection only', color: 'var(--color-platform-tier2)',
    identityLabel: 'API Key',
  }])) as Record<AIPlatform, PlatformMeta>,
  aws: {
    label: 'AWS',
    auditLog: 'CloudTrail',
    color: 'var(--color-platform-aws)',
    identityLabel: 'Access Key ID',
  },
  gcp: {
    label: 'GCP',
    auditLog: 'Cloud Audit Logs',
    color: 'var(--color-platform-gcp)',
    identityLabel: 'Service Account',
  },
  azure: {
    label: 'Azure',
    auditLog: 'Activity Log',
    color: 'var(--color-platform-azure)',
    identityLabel: 'Client ID',
  },
  stripe: {
    label: 'Stripe',
    auditLog: 'Events API',
    color: 'var(--color-platform-stripe)',
    identityLabel: 'Secret Key',
  },
  twilio: {
    label: 'Twilio',
    auditLog: 'Messages & Calls',
    color: 'var(--color-platform-twilio)',
    identityLabel: 'Account SID',
  },
  // Tier 2 — no audit log to name, so auditLog describes the absence.
  github: {
    label: 'GitHub',
    auditLog: 'no per-token audit log',
    color: 'var(--color-platform-tier2)',
    identityLabel: 'Personal Access Token',
  },
  slack: {
    label: 'Slack',
    auditLog: 'no audit log below Enterprise Grid',
    color: 'var(--color-platform-tier2)',
    identityLabel: 'Webhook / Token',
  },
  npm: {
    label: 'npm',
    auditLog: 'no per-token audit API',
    color: 'var(--color-platform-tier2)',
    identityLabel: 'Access Token',
  },
  sendgrid: {
    label: 'SendGrid',
    auditLog: 'Email Activity API (paid add-on)',
    color: 'var(--color-platform-tier2)',
    identityLabel: 'API Key',
  },
  huggingface: {
    label: 'Hugging Face',
    auditLog: 'no audit API',
    color: 'var(--color-platform-tier2)',
    identityLabel: 'Access Token',
  },
  db: {
    label: 'Database',
    auditLog: 'audit logging lives inside the target database',
    color: 'var(--color-platform-tier2)',
    identityLabel: 'Connection String',
  },
}

/** Anything carrying enough information to work out which platform it belongs to. */
interface PlatformSource {
  platform?: string | null
  credential_type?: string | null
}

/**
 * Resolve the platform for an incident or event.
 *
 * Prefers an explicit `platform` field when the backend supplies one, and falls
 * back to the credential type so the UI stays correct against an API that
 * predates the multi-platform fields. Defaults to `aws`, matching the backend.
 */
export function derivePlatform(source: PlatformSource | null | undefined): Platform {
  if (!source) return 'aws'

  const explicit = source.platform?.toLowerCase()
  if (explicit && (PLATFORMS as string[]).includes(explicit)) {
    return explicit as Platform
  }

  return CREDENTIAL_TYPE_TO_PLATFORM[source.credential_type?.toLowerCase() ?? ''] ?? 'aws'
}

/**
 * credential_type -> platform, mirroring CREDENTIAL_TYPE_TO_PLATFORM in
 * backend/db/models.py. An explicit map rather than substring matching: with
 * twelve credential types, `includes('gcp')`-style checks start colliding and
 * mis-routing is silent.
 */
const CREDENTIAL_TYPE_TO_PLATFORM: Record<string, Platform> = {
  ...Object.fromEntries(Object.keys(AI_LABELS).map(p => [`${p}_api_key`, p])) as Record<string, AIPlatform>,
  aws_access_key: 'aws',
  gcp_service_account: 'gcp',
  // Firebase keys ARE GCP service account keys and collect through Cloud Audit
  // Logs, so they belong to the GCP platform despite the distinct label.
  firebase_service_account: 'gcp',
  azure_service_principal: 'azure',
  azure_client_secret: 'azure',
  azure_storage_connection: 'azure',
  stripe_secret_key: 'stripe',
  twilio_account_sid: 'twilio',
  github_pat: 'github',
  slack_webhook: 'slack',
  slack_token: 'slack',
  npm_token: 'npm',
  sendgrid_api_key: 'sendgrid',
  huggingface_token: 'huggingface',
  db_connection_string: 'db',
}

/**
 * Whether an incident's blast radius was actually reconstructable.
 *
 * Defaults a missing `forensic_tier` to Tier 1. That direction matters: an
 * incident cached from before the field shipped has a real timeline, and
 * treating `undefined` as Tier 2 would hide it behind the "unavailable" panel.
 */
export function isForensicTier(source: { forensic_tier?: number | null } | null | undefined): boolean {
  return (source?.forensic_tier ?? 1) === 1
}

/** Filter chip -> predicate. 'Other' collects every Tier-2 platform. */
export function matchesPlatformFilter(
  incident: PlatformSource & { forensic_tier?: number | null },
  filter: string,
): boolean {
  if (filter === 'All') return true
  const platform = derivePlatform(incident)
  if (filter === 'Other') return !FORENSIC_PLATFORMS.includes(platform)
  return platform === filter.toLowerCase()
}

export function platformMeta(source: PlatformSource | null | undefined): PlatformMeta {
  return PLATFORM_META[derivePlatform(source)]
}

/**
 * The platform-specific identifier that was actually leaked, for the incident
 * header. Each platform names its principal differently, and showing an empty
 * "Access Key ID" on a GCP incident reads as a bug.
 *
 * Returns null when no identifier is available — the caller should omit the
 * tile rather than render a blank one.
 */
export function platformIdentity(
  incident: {
    platform?: string | null
    credential_type?: string | null
    access_key_id?: string | null
    principal_id?: string | null
    gcp_project_id?: string | null
    azure_tenant_id?: string | null
    azure_subscription_id?: string | null
  },
  /**
   * Collected events, used only to recover the principal when the incident
   * payload omits it. Events carry `principal_id` ahead of incidents doing so,
   * so this keeps the identity visible against an older API.
   */
  events: { principal_id?: string | null }[] = [],
): { label: string; value: string; context?: string } | null {
  const platform = derivePlatform(incident)
  const meta = PLATFORM_META[platform]
  const principal =
    incident.principal_id ?? events.find(e => e.principal_id)?.principal_id ?? null

  switch (platform) {
    case 'gcp': {
      const value = principal
      if (!value) return null
      return {
        label: meta.identityLabel,
        value,
        context: incident.gcp_project_id ? `project ${incident.gcp_project_id}` : undefined,
      }
    }
    case 'azure': {
      const value = principal
      if (!value) return null
      return {
        label: meta.identityLabel,
        value,
        context: incident.azure_subscription_id
          ? `subscription ${incident.azure_subscription_id}`
          : incident.azure_tenant_id
            ? `tenant ${incident.azure_tenant_id}`
            : undefined,
      }
    }
    default: {
      const value = incident.access_key_id
      if (!value) return null
      return { label: meta.identityLabel, value }
    }
  }
}
