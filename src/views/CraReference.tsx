import { PageHeader } from '../components/layout/PageHeader';
import { Badge } from '../components/shared/Badge';

interface AnnexRequirement {
  id: string;
  title: string;
  summary: string;
}

// Source: Regulation (EU) 2024/2847, Annex I Part I — essential cybersecurity
// requirements for products with digital elements. Summaries paraphrase the
// regulation text for quick scanning; see EUR-Lex for the authoritative wording.
const ANNEX_I_PART_I: AnnexRequirement[] = [
  { id: '1', title: 'Appropriate level of cybersecurity', summary: 'Delivered with a level of cybersecurity appropriate to the risks.' },
  { id: '2', title: 'No known exploitable vulnerabilities', summary: 'Placed on the market without known exploitable vulnerabilities.' },
  { id: '3', title: 'Secure by default configuration', summary: 'Default configuration must be secure; reset to initial state must be possible.' },
  { id: '4', title: 'Security updates', summary: 'Vulnerabilities addressed through security updates, including automatic updates where appropriate, with an opt-out.' },
  { id: '5', title: 'Access protection', summary: 'Protection from unauthorised access via authentication, identity, or access management.' },
  { id: '6', title: 'Confidentiality protection', summary: 'Protect the confidentiality of stored, transmitted, or processed data (personal or other) — e.g. by encryption at rest and in transit.' },
  { id: '7', title: 'Integrity protection', summary: 'Protect the integrity of data, commands, programs, and configuration against unauthorised manipulation; report corruption.' },
  { id: '8', title: 'Data minimisation', summary: 'Only process data adequate, relevant, and limited to what is necessary ("minimisation of data").' },
  { id: '9', title: 'Availability of essential functions', summary: 'Protect availability of essential and basic functions, including resilience against and mitigation of DoS.' },
  { id: '10', title: 'Minimise impact on others', summary: 'Minimise negative impact on the availability of services provided by other devices or networks.' },
  { id: '11', title: 'Limit attack surface', summary: 'Designed, developed, and produced to limit attack surfaces, including external interfaces.' },
  { id: '12', title: 'Reduce incident impact', summary: 'Reduce the impact of an incident using appropriate exploitation mitigation mechanisms and techniques.' },
  { id: '13', title: 'Security-relevant logging', summary: 'Provide security-related information by recording and monitoring relevant internal activity, including access to or modification of data, services, or functions — with an opt-out.' },
  { id: '14', title: 'Secure update mechanism', summary: 'Ensure vulnerabilities can be addressed through security updates, including, where applicable, automatic updates and notification to users.' },
  { id: '15', title: 'Secure decommissioning', summary: 'Provide the possibility for users to securely and easily remove all data and settings on a permanent basis.' },
];

// Annex I Part II — vulnerability-handling requirements for the product lifecycle.
const ANNEX_I_PART_II: AnnexRequirement[] = [
  { id: 'VH-1', title: 'SBOM', summary: 'Identify and document vulnerabilities and components by drawing up a software bill of materials in a commonly used machine-readable format covering the top-level dependencies.' },
  { id: 'VH-2', title: 'Vulnerability disclosure policy', summary: 'Put in place a coordinated vulnerability disclosure policy.' },
  { id: 'VH-3', title: 'Timely remediation', summary: 'Address and remediate vulnerabilities without delay, including by providing security updates.' },
  { id: 'VH-4', title: 'Regular testing', summary: 'Apply effective and regular security tests and reviews of the product.' },
  { id: 'VH-5', title: 'Public disclosure of fixed vulnerabilities', summary: 'Once a security update is made available, publicly disclose information on fixed vulnerabilities (CVEs, severity, impact, remediation).' },
  { id: 'VH-6', title: 'Facilitate information sharing', summary: 'Share and publicly disclose information about potential vulnerabilities, including contact information for reports.' },
  { id: 'VH-7', title: 'Secure update distribution', summary: 'Provide mechanisms to securely distribute updates to ensure that vulnerabilities are fixed or mitigated in a timely manner and, where applicable, for automatic updates.' },
  { id: 'VH-8', title: 'Free & timely security updates', summary: 'Ensure that security updates are disseminated without delay and, unless otherwise agreed for tailor-made products, free of charge, along with advisories.' },
];

interface ReportingStage {
  stage: string;
  vulnerability: string;
  incident: string;
  trigger: string;
}

// Article 14 reporting cadence to CSIRT + ENISA SRP.
const REPORTING_STAGES: ReportingStage[] = [
  { stage: 'Early warning', vulnerability: '24 hours', incident: '24 hours', trigger: 'From becoming aware of an actively exploited vulnerability / severe incident' },
  { stage: 'Notification', vulnerability: '72 hours', incident: '72 hours', trigger: 'Vulnerability assessment + corrective measures / incident assessment' },
  { stage: 'Final report', vulnerability: '14 days post-mitigation', incident: '1 month post-notification', trigger: 'Root cause + mitigation / full incident details' },
];

interface ProductClass {
  label: string;
  examples: string[];
  tone: 'blue' | 'yellow' | 'orange' | 'pink';
}

const PRODUCT_CLASSES: ProductClass[] = [
  { label: 'Default (non-important)', examples: ['Games', 'Word processors', 'Photo-editing software', 'Consumer IoT unrelated to safety/security functions'], tone: 'blue' },
  { label: 'Important — Class I', examples: ['Password managers', 'Antivirus / endpoint protection', 'VPN clients', 'Network management tools', 'Remote-access software', 'Microcontrollers with security functions', 'Smart home assistants', 'Physical network interfaces'], tone: 'yellow' },
  { label: 'Important — Class II', examples: ['Hypervisors & container runtimes', 'Firewalls', 'IDS / IPS', 'Tamper-resistant microprocessors / microcontrollers'], tone: 'orange' },
  { label: 'Critical', examples: ['Smart meter gateways', 'Secure elements & crypto hardware', 'Smartcards'], tone: 'pink' },
];

export function CraReference() {
  return (
    <div className="space-y-8">
      <PageHeader
        title="EU Cyber Resilience Act (CRA)"
        subtitle="Regulation (EU) 2024/2847 — cybersecurity requirements for products with digital elements"
        titleAction={<Badge label="Work in progress" variant="yellow" />}
      />

      {/* WIP notice */}
      <div className="rounded-lg border border-[var(--yellow-dim)] bg-[var(--yellow-faint)] px-4 py-3 text-sm text-[var(--text-primary)]">
        <p className="font-medium text-[var(--accent-yellow)] mb-1">Reference page — not a data-backed framework yet</p>
        <p className="text-[var(--text-secondary)] leading-relaxed">
          This page summarises the regulation for orientation. Unlike OWASP Top 10 or NIST 800-53, there is no
          authoritative technical crosswalk yet between CRA essential requirements and ATT&amp;CK / CWE / NIST 800-53.
          CEN/CENELEC JTC 13 is drafting the harmonised standards. Mappings will be added once they become public
          or once we commit editorial mappings with sources.
        </p>
      </div>

      {/* Key dates */}
      <section>
        <h2 className="text-sm font-bold uppercase tracking-wider text-[var(--accent-teal)] mb-3">Key dates</h2>
        <ul className="grid gap-2 md:grid-cols-2">
          <li className="rounded-md border border-[var(--border-color)] bg-[var(--surface-card)] px-3 py-2">
            <div className="text-xs text-[var(--text-secondary)]">Entry into force</div>
            <div className="text-sm font-semibold text-[var(--text-primary)]">10 December 2024</div>
          </li>
          <li className="rounded-md border border-[var(--border-color)] bg-[var(--surface-card)] px-3 py-2">
            <div className="text-xs text-[var(--text-secondary)]">Vulnerability-handling obligations apply</div>
            <div className="text-sm font-semibold text-[var(--text-primary)]">11 September 2026</div>
          </li>
          <li className="rounded-md border border-[var(--border-color)] bg-[var(--surface-card)] px-3 py-2">
            <div className="text-xs text-[var(--text-secondary)]">Conformity-assessment bodies notification</div>
            <div className="text-sm font-semibold text-[var(--text-primary)]">11 June 2026</div>
          </li>
          <li className="rounded-md border border-[var(--border-color)] bg-[var(--surface-card)] px-3 py-2">
            <div className="text-xs text-[var(--text-secondary)]">Full application (CE marking required)</div>
            <div className="text-sm font-semibold text-[var(--text-primary)]">11 December 2027</div>
          </li>
        </ul>
      </section>

      {/* Article 14 reporting cadence */}
      <section>
        <h2 className="text-sm font-bold uppercase tracking-wider text-[var(--accent-teal)] mb-3">
          Article 14 reporting cadence
        </h2>
        <p className="text-sm text-[var(--text-secondary)] mb-3 leading-relaxed">
          Manufacturers must notify the CSIRT of their main establishment and ENISA via the Single Reporting
          Platform (SRP) when they become aware of an actively exploited vulnerability or a severe incident
          impacting the security of the product.
        </p>
        <div className="overflow-x-auto rounded-md border border-[var(--border-color)]">
          <table className="w-full text-sm">
            <thead className="bg-[var(--surface-deep)] text-left text-xs uppercase tracking-wider text-[var(--text-secondary)]">
              <tr>
                <th className="px-3 py-2 font-semibold">Stage</th>
                <th className="px-3 py-2 font-semibold">Vulnerability</th>
                <th className="px-3 py-2 font-semibold">Severe incident</th>
                <th className="px-3 py-2 font-semibold">Trigger</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-[var(--border-color)]">
              {REPORTING_STAGES.map((s) => (
                <tr key={s.stage} className="bg-[var(--surface-card)]">
                  <td className="px-3 py-2 font-medium text-[var(--text-primary)]">{s.stage}</td>
                  <td className="px-3 py-2 text-[var(--text-primary)]">{s.vulnerability}</td>
                  <td className="px-3 py-2 text-[var(--text-primary)]">{s.incident}</td>
                  <td className="px-3 py-2 text-[var(--text-secondary)]">{s.trigger}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </section>

      {/* Annex I Part I — essential requirements */}
      <section>
        <h2 className="text-sm font-bold uppercase tracking-wider text-[var(--accent-teal)] mb-3">
          Annex I — Part I: essential cybersecurity requirements
        </h2>
        <p className="text-sm text-[var(--text-secondary)] mb-3 leading-relaxed">
          Products with digital elements (PDE) must be designed, developed, and produced to meet these
          essential requirements, based on a risk assessment.
        </p>
        <ol className="space-y-2">
          {ANNEX_I_PART_I.map((r) => (
            <li
              key={r.id}
              className="rounded-md border border-[var(--border-color)] bg-[var(--surface-card)] px-3 py-2"
            >
              <div className="flex items-start gap-3">
                <span className="mt-0.5 font-mono text-xs text-[var(--accent-teal)] w-6 shrink-0">{r.id}</span>
                <div>
                  <div className="text-sm font-semibold text-[var(--text-primary)]">{r.title}</div>
                  <div className="text-xs text-[var(--text-secondary)] leading-relaxed">{r.summary}</div>
                </div>
              </div>
            </li>
          ))}
        </ol>
      </section>

      {/* Annex I Part II — vuln handling */}
      <section>
        <h2 className="text-sm font-bold uppercase tracking-wider text-[var(--accent-teal)] mb-3">
          Annex I — Part II: vulnerability-handling requirements
        </h2>
        <p className="text-sm text-[var(--text-secondary)] mb-3 leading-relaxed">
          Lifecycle obligations on manufacturers throughout the product&rsquo;s support period (minimum 5
          years unless the expected use is shorter).
        </p>
        <ol className="space-y-2">
          {ANNEX_I_PART_II.map((r) => (
            <li
              key={r.id}
              className="rounded-md border border-[var(--border-color)] bg-[var(--surface-card)] px-3 py-2"
            >
              <div className="flex items-start gap-3">
                <span className="mt-0.5 font-mono text-xs text-[var(--accent-orange)] w-10 shrink-0">{r.id}</span>
                <div>
                  <div className="text-sm font-semibold text-[var(--text-primary)]">{r.title}</div>
                  <div className="text-xs text-[var(--text-secondary)] leading-relaxed">{r.summary}</div>
                </div>
              </div>
            </li>
          ))}
        </ol>
      </section>

      {/* Product classes */}
      <section>
        <h2 className="text-sm font-bold uppercase tracking-wider text-[var(--accent-teal)] mb-3">
          Product categories (Annex III &amp; IV)
        </h2>
        <p className="text-sm text-[var(--text-secondary)] mb-3 leading-relaxed">
          The conformity-assessment route depends on the product category. Higher classes require third-party
          assessment; critical products may require EU cybersecurity certification.
        </p>
        <ul className="grid gap-2 md:grid-cols-2">
          {PRODUCT_CLASSES.map((c) => (
            <li key={c.label} className="rounded-md border border-[var(--border-color)] bg-[var(--surface-card)] px-3 py-3">
              <div className="flex items-center gap-2 mb-1.5">
                <Badge label={c.label} variant={c.tone} />
              </div>
              <div className="text-xs text-[var(--text-secondary)] leading-relaxed">
                {c.examples.join(' · ')}
              </div>
            </li>
          ))}
        </ul>
      </section>

      {/* External references */}
      <section>
        <h2 className="text-sm font-bold uppercase tracking-wider text-[var(--accent-teal)] mb-3">References</h2>
        <ul className="space-y-1.5 text-sm">
          <li>
            <a
              href="https://eur-lex.europa.eu/eli/reg/2024/2847/oj"
              target="_blank"
              rel="noopener noreferrer"
              className="text-[var(--accent-teal)] hover:underline"
            >
              Regulation (EU) 2024/2847 — full text (EUR-Lex)
            </a>
          </li>
          <li>
            <a
              href="https://digital-strategy.ec.europa.eu/en/policies/cyber-resilience-act"
              target="_blank"
              rel="noopener noreferrer"
              className="text-[var(--accent-teal)] hover:underline"
            >
              European Commission — CRA policy page
            </a>
          </li>
          <li>
            <a
              href="https://www.enisa.europa.eu/topics/cyber-resilience-act"
              target="_blank"
              rel="noopener noreferrer"
              className="text-[var(--accent-teal)] hover:underline"
            >
              ENISA — CRA resources &amp; Single Reporting Platform
            </a>
          </li>
          <li>
            <a
              href="https://www.cencenelec.eu/news-and-events/news/2024/brief-news/2024-10-22-harmonised-standards-cra/"
              target="_blank"
              rel="noopener noreferrer"
              className="text-[var(--accent-teal)] hover:underline"
            >
              CEN-CENELEC JTC 13 — CRA harmonised standards programme
            </a>
          </li>
        </ul>
      </section>
    </div>
  );
}
