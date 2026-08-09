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

export type Platform = 'aws' | 'gcp' | 'azure'

export const PLATFORMS: Platform[] = ['aws', 'gcp', 'azure']

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

  const credentialType = source.credential_type?.toLowerCase() ?? ''
  if (credentialType.includes('gcp') || credentialType.includes('firebase')) return 'gcp'
  if (credentialType.includes('azure')) return 'azure'
  return 'aws'
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
