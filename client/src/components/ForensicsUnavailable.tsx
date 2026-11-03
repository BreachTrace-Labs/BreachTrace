import { ShieldQuestion, AlertTriangle, ExternalLink } from 'lucide-react'
import { Card, CardHeader, CardTitle, CardContent } from '@/components/ui/card'
import { platformMeta, derivePlatform } from '@/lib/platform'
import type { IncidentRecord } from '@/types'

/**
 * Shown instead of a timeline when an incident is Tier 2 — the platform exposes
 * no queryable per-credential audit log.
 *
 * This is the most important honest moment in the product. Every competing tool
 * says "your key leaked" and stops; showing an empty timeline here would say
 * "and nothing happened", which is the false reassurance BreachTrace exists to
 * eliminate. The panel states plainly that the activity is unknowable, says
 * why, and gives the user something to do about it.
 */

interface Props {
  incident: IncidentRecord
}

/** Where a user can go to check manually, since we cannot check for them. */
const MANUAL_CHECK: Record<string, { label: string; url: string }> = {
  github: {
    label: 'GitHub security log',
    url: 'https://github.com/settings/security-log',
  },
  slack: {
    label: 'Slack app management',
    url: 'https://api.slack.com/apps',
  },
  npm: {
    label: 'npm access tokens',
    url: 'https://www.npmjs.com/settings/~/tokens',
  },
  sendgrid: {
    label: 'SendGrid activity feed',
    url: 'https://app.sendgrid.com/email_activity',
  },
  huggingface: {
    label: 'Hugging Face access tokens',
    url: 'https://huggingface.co/settings/tokens',
  },
}

const ForensicsUnavailable: React.FC<Props> = ({ incident }) => {
  const platform = derivePlatform(incident)
  const meta = platformMeta(incident)
  const manual = MANUAL_CHECK[platform]

  return (
    <Card>
      <CardHeader className="pb-3">
        <CardTitle className="flex flex-wrap items-center gap-2 text-sm">
          <ShieldQuestion size={14} strokeWidth={2} />
          Forensic reconstruction unavailable
          <span
            className="ml-auto text-[10px] font-bold uppercase tracking-wider px-1.5 py-0.5 rounded"
            style={{
              backgroundColor: 'color-mix(in srgb, var(--color-platform-tier2) 18%, transparent)',
              color: 'var(--color-platform-tier2)',
            }}
          >
            {meta.label}
          </span>
        </CardTitle>
      </CardHeader>

      <CardContent className="space-y-4 text-sm">
        {/* The reason, straight from the backend so UI and report never diverge. */}
        <p style={{ color: 'var(--color-foreground)' }}>
          {incident.unavailable_reason ??
            `BreachTrace does not collect activity for this ${meta.label} credential type. Activity during the exposure window has not been reconstructed.`}
        </p>

        {/* The critical distinction. Absence of evidence is not evidence of absence. */}
        <div
          className="flex gap-2.5 p-3 rounded-sm"
          style={{
            backgroundColor: 'color-mix(in srgb, var(--color-sev-high) 10%, transparent)',
            border: '1px solid color-mix(in srgb, var(--color-sev-high) 30%, transparent)',
          }}
        >
          <AlertTriangle
            size={15}
            strokeWidth={2}
            className="shrink-0 mt-0.5"
            style={{ color: 'var(--color-sev-high)' }}
          />
          <div>
            <p className="font-semibold" style={{ color: 'var(--color-sev-high)' }}>
              An empty timeline is not proof the credential went unused.
            </p>
            <p className="mt-1" style={{ color: 'var(--color-muted-foreground)' }}>
              Key validity and usage have not been verified. If this is a real
              credential exposed in a repository, rotate it and review provider records.
            </p>
          </div>
        </div>

        {/* What we cannot do, stated concretely rather than vaguely. */}
        <div>
          <p
            className="text-[11px] font-semibold uppercase tracking-widest mb-2"
            style={{ color: 'var(--color-muted-foreground)' }}
          >
            Why this platform differs
          </p>
          <p style={{ color: 'var(--color-muted-foreground)' }}>
            Cloud forensics requires authorized access to the organization’s audit logs.{' '}
            For {meta.label}, BreachTrace’s current coverage is{' '}
            <span style={{ color: 'var(--color-foreground)' }}>{meta.auditLog}</span>.
            Review available usage and security records in the provider console.
          </p>
        </div>

        {manual && (
          <a
            href={manual.url}
            target="_blank"
            rel="noopener noreferrer"
            className="inline-flex items-center gap-1.5 text-xs font-medium hover:underline"
            style={{ color: 'var(--color-foreground)' }}
          >
            <ExternalLink size={12} strokeWidth={2} />
            Check manually: {manual.label}
          </a>
        )}
      </CardContent>
    </Card>
  )
}

export default ForensicsUnavailable
