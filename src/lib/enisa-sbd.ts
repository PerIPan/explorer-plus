// src/lib/enisa-sbd.ts
//
// ENISA's Secure by Design and Default playbooks, as a reference list on the
// CRA page.
//
// WHY IT LIVES HERE AND NOT IN /frameworks
// Every other entry in the Frameworks section bridges to ATT&CK techniques;
// this one cannot. Measured across all 22 playbooks on 2026-10-03: ZERO mention
// ATT&CK, a T-number, CWE, CAPEC, NIST, ISO, IEC 62443, D3FEND, NIS2 or even
// the CRA itself, and exactly one mentions OWASP. There is no identifier to
// join on, so any technique or Annex I mapping would be this project's
// editorial opinion presented as data. It is therefore a reading list with its
// provenance attached, placed beside the regulation it was written to support,
// and nothing here claims a crosswalk.
//
// RIGHTS
// CC BY 4.0 (Attribution 4.0 International), per the LICENSE in the source
// repository — so unlike ISO 27002, PCI DSS, SOC 2, IEC 62443 or CIS Controls,
// the titles and principle text below may be reproduced with attribution.
// `ENISA_SBD_SOURCE` carries that attribution and the page renders it.
//
// TITLES AND LINKS
// Titles are each playbook's own H1, not the repository index's casing, which
// is inconsistent with them. Slugs are the real filenames: the index's links
// are broken upstream for two entries — it spells `07-lifecycle-management`
// and `22-secure-recovery-and-ownership-lifecycle`, while the files are
// `07-life-cycle-management` and `22-secure-recovery-and-ownership-life-cycle`.
// Both real spellings return 200 and both index spellings 404, verified
// 2026-10-03.

/** ENISA's own top-level split: 14 "by design", 8 "by default". */
export type SbdGroup = 'design' | 'default';

export interface SbdPlaybook {
  /** 1-22, the playbook's own number in the source. */
  readonly id: number;
  readonly group: SbdGroup;
  /** ENISA's sub-grouping within the group. */
  readonly section: string;
  readonly title: string;
  /** First sentence of the playbook's Principle. CC BY 4.0, see above. */
  readonly principle: string;
  /** Source filename, which is also the deep link's last segment. */
  readonly slug: string;
}

/** The two groups, with ENISA's own one-line description of each. */
export const ENISA_SBD_GROUPS: readonly { key: SbdGroup; label: string; blurb: string }[] = [
  {
    key: 'design',
    label: 'Secure by design',
    blurb:
      'Protective measures embedded into products during development, rather than added retrospectively.',
  },
  {
    key: 'default',
    label: 'Secure by default',
    blurb:
      'Products ship in the most secure configuration reasonably possible, so security does not depend on user expertise.',
  },
];

export const ENISA_SBD_PLAYBOOKS: readonly SbdPlaybook[] = [
  { id: 1, group: "design", section: "Architectural foundations",
    title: "Trust boundaries and threat modelling",
    principle: "Secure architectures make trust explicit rather than assumed.",
    slug: "01-trust-boundaries-and-threat-modelling" },
  { id: 2, group: "design", section: "Architectural foundations",
    title: "Least privilege",
    principle: "Every user, service and process operates with the feasible minimum permissions needed to do its job – no more and for no longer than necessary.",
    slug: "02-least-privilege" },
  { id: 3, group: "design", section: "Architectural foundations",
    title: "Strong identity and authentication architecture",
    principle: "Design identity and authentication as a core part of the architecture.",
    slug: "03-strong-identity-and-authentication-architecture" },
  { id: 4, group: "design", section: "Architectural foundations",
    title: "Attack surface minimisation",
    principle: "Expose only what is strictly necessary.",
    slug: "04-attack-surface-minimisation" },
  { id: 5, group: "design", section: "Architectural foundations",
    title: "Defence in depth",
    principle: "Apply multiple layers of security so that the failure or bypass of a single control does not result in full compromise.",
    slug: "05-defence-in-depth" },
  { id: 6, group: "design", section: "Architectural foundations",
    title: "Open design",
    principle: "Systems should not depend on secrecy of design or hidden behaviour for protection.",
    slug: "06-open-design" },
  { id: 7, group: "design", section: "Operational integrity",
    title: "Life-cycle management",
    principle: "Security responsibilities extend beyond initial development.",
    slug: "07-life-cycle-management" },
  { id: 8, group: "design", section: "Operational integrity",
    title: "User-centric design",
    principle: "Security mechanisms must be usable and understandable even for everyday users.",
    slug: "08-user-centric-design" },
  { id: 9, group: "design", section: "Operational integrity",
    title: "Secure coding and verification practices",
    principle: "Developers should follow established secure coding standards to prevent common vulnerabilities.",
    slug: "09-secure-coding-and-verification-practices" },
  { id: 10, group: "design", section: "Operational integrity",
    title: "Logging, monitoring and alerting",
    principle: "Systems should generate appropriate security-relevant logs, retain them for a defined period and protect them from tampering, so that they can support investigation and compliance needs.",
    slug: "10-logging-monitoring-and-alerting" },
  { id: 11, group: "design", section: "Operational integrity",
    title: "Configuration and change management",
    principle: "Secure operation requires configurations to be controlled, consistent and auditable.",
    slug: "11-configuration-and-change-management" },
  { id: 12, group: "design", section: "Operational integrity",
    title: "Incident response and recovery",
    principle: "Developers must be prepared to respond quickly and effectively to security incidents that affect their products in the field, including vulnerabilities, compromised code, malicious updates and misuse of product functionality.",
    slug: "12-incident-response-and-recovery" },
  { id: 13, group: "design", section: "Operational integrity",
    title: "Vulnerability and patch management",
    principle: "Manufacturers should establish practical, repeatable vulnerability and patch management processes and prioritise remediation according to risk.",
    slug: "13-vulnerability-and-patch-management" },
  { id: 14, group: "design", section: "Operational integrity",
    title: "Supply-chain controls",
    principle: "Developers should protect product integrity without excessive process overhead, focusing on the points where a compromise would have the largest impact: code repositories, build systems, signing keys and the channels used to distribute updates.",
    slug: "14-supply-chain-controls" },
  { id: 15, group: "default", section: "Default hardening",
    title: "Minimisation of default services",
    principle: "Disable non-essential features and services by default.",
    slug: "15-minimisation-of-default-services" },
  { id: 16, group: "default", section: "Default hardening",
    title: "Restrictive initial access",
    principle: "Ship systems in the most restrictive access state possible.",
    slug: "16-restrictive-initial-access" },
  { id: 17, group: "default", section: "Default hardening",
    title: "Secure communication by default",
    principle: "Enforce secure communication from the start.",
    slug: "17-secure-communication-by-default" },
  { id: 18, group: "default", section: "Default hardening",
    title: "Unique device identity and secrets by default",
    principle: "Ship each product instance with a unique cryptographic identity and secrets by default if it uses any private/secret value.",
    slug: "18-unique-device-identity-and-secrets-by-default" },
  { id: 19, group: "default", section: "Guided protection",
    title: "Mandatory security onboarding",
    principle: "Require critical security controls to be configured during initial set-up.",
    slug: "19-mandatory-security-onboarding" },
  { id: 20, group: "default", section: "Guided protection",
    title: "Automated maintenance and updates",
    principle: "Manufacturers should provide secure update mechanisms that minimise user and operational effort.",
    slug: "20-automated-maintenance-and-updates" },
  { id: 21, group: "default", section: "Guided protection",
    title: "Transparent security posture",
    principle: "Make the system’s security posture visible and understandable.",
    slug: "21-transparent-security-posture" },
  { id: 22, group: "default", section: "Guided protection",
    title: "Secure recovery and ownership life cycle",
    principle: "Provide secure, guided recovery and ownership transfer mechanisms by default.",
    slug: "22-secure-recovery-and-ownership-life-cycle" },
] as const;

export const ENISA_SBD_COUNT = ENISA_SBD_PLAYBOOKS.length;

/** Deep link to one playbook in the source repository. */
export function sbdUrl(p: SbdPlaybook): string {
  return `${ENISA_SBD_SOURCE.repo}/blob/main/playbooks/${p.slug}.md`;
}

export const ENISA_SBD_SOURCE = {
  publisher: 'ENISA',
  title: 'Secure by Design and Default Playbook',
  subtitle: 'A Practical Guide to Secure by Design and Default Principles for SMEs',
  version: 'v1',
  published: 'July 2026',
  licence: 'CC BY 4.0',
  licenceUrl: 'https://creativecommons.org/licenses/by/4.0/',
  repo: 'https://github.com/enisaeu/enisa-sbd-playbook',
  pdf: 'https://www.enisa.europa.eu/sites/default/files/2026-07/ENISA_Secure_By_Design_and_Default_Playbook_v1.pdf',
} as const;
