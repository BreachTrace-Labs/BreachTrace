export interface ComplianceFramework {
  id: string
  kind: string
  label: string
  title: string
  url: string
  description: string
  trigger: string
}

export const complianceFrameworks: ComplianceFramework[] = [
  {
    id: 'owasp-nhi2',
    kind: 'SECURITY GUIDANCE',
    label: 'OWASP NHI2',
    title: 'OWASP Non-Human Identities Top 10: Secret Leakage',
    url: 'https://owasp.org/www-project-non-human-identities-top-10/',
    description: 'Guidance on secrets used by applications, services and automation being exposed in source code, logs or other places they should not be.',
    trigger: 'A secret candidate was detected in a commit or snapshot. Review applies only if it belongs to a non-human identity; validity and ownership are not established by detection alone.',
  },
  {
    id: 'gdpr-32-33',
    kind: 'REGULATION',
    label: 'GDPR Articles 32-33',
    title: 'Security of processing and personal-data breach notification',
    url: 'https://gdpr-info.eu/art-33-gdpr/',
    description: 'Article 32 covers appropriate security of processing. Article 33 covers notifying the supervisory authority of a personal-data breach.',
    trigger: 'A collected event is classified as data access or exfiltration and names a resource containing a personal-data keyword. The name alone does not establish personal data, a breach, or applicability.',
  },
  {
    id: 'pci-incident-response',
    kind: 'STANDARD',
    label: 'PCI DSS incident response',
    title: 'PCI DSS incident response requirements',
    url: 'https://www.pcisecuritystandards.org/document_library/',
    description: 'PCI DSS requires an incident response plan and procedures for suspected compromise of the cardholder-data environment.',
    trigger: 'A financial-activity classification or payment-related resource name appears in collected events. This does not establish cardholder data, a cardholder-data environment, or PCI DSS scope.',
  },
  {
    id: 'soc2-security',
    kind: 'FRAMEWORK',
    label: 'SOC 2 Security criteria',
    title: 'AICPA Trust Services Criteria: Security',
    url: 'https://www.aicpa-cima.com/topic/audit-assurance/audit-and-assurance-greater-than-soc-2',
    description: 'The Security criteria cover protection against unauthorised access, including logical access controls and monitoring of anomalies.',
    trigger: 'An event is classified as privilege escalation, exfiltration, or resource abuse. Review whether it relates to controls in your SOC 2 scope; classification does not establish a control failure.',
  },
]
