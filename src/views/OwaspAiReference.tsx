import { PageHeader } from '../components/layout/PageHeader';
import { Badge } from '../components/shared/Badge';

// All content faithfully mirrors owaspai.org/docs/ai_security_overview/
// Labels + /go/<slug>/ short-links match upstream exactly so readers can
// click through to the canonical Exchange page for each item.
const GO_BASE = 'https://owaspai.org/go/';

interface ThreatItem {
  label: string;
  slug: string;
  surface: string;
}

interface ImpactGroup {
  impact: string;
  goal: 'Disclose' | 'Deceive' | 'Disrupt';
  threats: ThreatItem[];
}

const THREATS: ImpactGroup[] = [
  {
    impact: 'Model behaviour integrity',
    goal: 'Deceive',
    threats: [
      { label: 'Direct prompt injection', slug: 'directpromptinjection', surface: 'Runtime — Model use' },
      { label: 'Indirect prompt injection', slug: 'indirectpromptinjection', surface: 'Runtime — Model use' },
      { label: 'Evasion (adversarial examples)', slug: 'evasion', surface: 'Runtime — Model use' },
      { label: 'Direct runtime model poisoning (reprogramming)', slug: 'runtimemodelpoison', surface: 'Runtime — Break into deployed model' },
      { label: 'Direct development-environment model poisoning', slug: 'devmodelpoison', surface: 'Development — Engineering env' },
      { label: 'Data poisoning of train/finetune data', slug: 'datapoison', surface: 'Development — Engineering env' },
      { label: 'Supply-chain model poisoning', slug: 'supplymodelpoison', surface: 'Development — Supply chain' },
    ],
  },
  {
    impact: 'Training data confidentiality',
    goal: 'Disclose',
    threats: [
      { label: 'Disclosure in output', slug: 'disclosureinoutput', surface: 'Runtime — Model use' },
      { label: 'Model inversion / Membership inference', slug: 'modelinversionandmembership', surface: 'Runtime — Model use' },
      { label: 'Direct training data leak', slug: 'devdataleak', surface: 'Development — Engineering env' },
    ],
  },
  {
    impact: 'Model confidentiality',
    goal: 'Disclose',
    threats: [
      { label: 'Model exfiltration (I/O harvesting)', slug: 'modelexfiltration', surface: 'Runtime — Model use' },
      { label: 'Direct runtime model leak', slug: 'runtimemodelleak', surface: 'Runtime — Break into deployed model' },
      { label: 'Direct development-time model leak', slug: 'devmodelleak', surface: 'Development — Engineering env' },
    ],
  },
  {
    impact: 'Model behaviour availability',
    goal: 'Disrupt',
    threats: [
      { label: 'AI resource exhaustion', slug: 'airesourceexhaustion', surface: 'Model use' },
    ],
  },
  {
    impact: 'Model input-data confidentiality',
    goal: 'Disclose',
    threats: [
      { label: 'Input data leak', slug: 'inputdataleak', surface: 'Runtime — All IT' },
    ],
  },
  {
    impact: 'Any asset — CIA',
    goal: 'Disrupt',
    threats: [
      { label: 'Output contains conventional injection', slug: 'outputcontainsconventionalinjection', surface: 'Runtime — All IT' },
    ],
  },
];

interface ControlItem {
  label: string;
  slug: string;
}

interface ControlCategory {
  category: string;
  tone: 'blue' | 'teal' | 'yellow' | 'orange' | 'pink' | 'neutral';
  subgroups: { heading: string; items: ControlItem[] }[];
}

const CONTROLS: ControlCategory[] = [
  {
    category: '1 · AI Governance',
    tone: 'blue',
    subgroups: [
      {
        heading: 'AI governance controls',
        items: [
          { label: 'AI PROGRAM', slug: 'aiprogram' },
          { label: 'SEC PROGRAM', slug: 'secprogram' },
          { label: 'DEV PROGRAM', slug: 'devprogram' },
          { label: 'SECDEV PROGRAM', slug: 'secdevprogram' },
          { label: 'CHECK COMPLIANCE', slug: 'checkcompliance' },
          { label: 'SEC EDUCATE', slug: 'seceducate' },
        ],
      },
    ],
  },
  {
    category: '2 · Conventional security (+ AI-adapted)',
    tone: 'teal',
    subgroups: [
      {
        heading: 'Supply-chain management',
        items: [{ label: 'SUPPLY CHAIN MANAGE', slug: 'supplychainmanage' }],
      },
      {
        heading: 'Development-time',
        items: [
          { label: 'DEV SECURITY', slug: 'devsecurity' },
          { label: 'SEGREGATE DATA', slug: 'segregatedata' },
          { label: 'DISCRETE', slug: 'discrete' },
        ],
      },
      {
        heading: 'Runtime',
        items: [
          { label: 'RUNTIME MODEL INTEGRITY', slug: 'runtimemodelintegrity' },
          { label: 'RUNTIME MODEL IO INTEGRITY', slug: 'runtimemodeliointegrity' },
          { label: 'RUNTIME MODEL CONFIDENTIALITY', slug: 'runtimemodelconfidentiality' },
          { label: 'MODEL INPUT CONFIDENTIALITY', slug: 'modelinputconfidentiality' },
          { label: 'ENCODE MODEL OUTPUT', slug: 'encodemodeloutput' },
          { label: 'LIMIT RESOURCES', slug: 'limitresources' },
          { label: 'AUGMENTATION DATA CONFIDENTIALITY', slug: 'augmentationdataconfidentiality' },
          { label: 'AUGMENTATION DATA INTEGRITY', slug: 'augmentationdataintegrity' },
        ],
      },
      {
        heading: 'Adapted conventional controls',
        items: [
          { label: 'MONITOR USE', slug: 'monitoruse' },
          { label: 'MODEL ACCESS CONTROL', slug: 'modelaccesscontrol' },
          { label: 'RATE LIMIT', slug: 'ratelimit' },
        ],
      },
      {
        heading: 'New IT security controls',
        items: [
          { label: 'CONF COMPUTE', slug: 'confcompute' },
          { label: 'MODEL OBFUSCATION', slug: 'modelobfuscation' },
          { label: 'INPUT SEGREGATION', slug: 'inputsegregation' },
        ],
      },
    ],
  },
  {
    category: '3 · AI-engineer controls',
    tone: 'yellow',
    subgroups: [
      {
        heading: '3a · Model engineering',
        items: [{ label: 'MODEL ALIGNMENT', slug: 'modelalignment' }],
      },
      {
        heading: '3b · Data/model engineering',
        items: [
          { label: 'FEDERATED LEARNING', slug: 'federatedlearning' },
          { label: 'CONTINUOUS VALIDATION', slug: 'continuousvalidation' },
          { label: 'UNWANTED BIAS TESTING', slug: 'unwantedbiastesting' },
          { label: 'EVASION ROBUST MODEL', slug: 'evasionrobustmodel' },
          { label: 'POISON ROBUST MODEL', slug: 'poisonrobustmodel' },
          { label: 'TRAIN ADVERSARIAL', slug: 'trainadversarial' },
          { label: 'TRAIN DATA DISTORTION', slug: 'traindatadistortion' },
          { label: 'ADVERSARIAL ROBUST DISTILLATION', slug: 'adversarialrobustdistillation' },
          { label: 'MODEL ENSEMBLE', slug: 'modelensemble' },
          { label: 'MORE TRAINDATA', slug: 'moretraindata' },
          { label: 'SMALL MODEL', slug: 'smallmodel' },
          { label: 'DATA QUALITY CONTROL', slug: 'dataqualitycontrol' },
        ],
      },
      {
        heading: '3c · Model I/O handling',
        items: [
          { label: 'ANOMALOUS INPUT HANDLING', slug: 'anomalousinputhandling' },
          { label: 'EVASION INPUT HANDLING', slug: 'evasioninputhandling' },
          { label: 'UNWANTED INPUT SERIES HANDLING', slug: 'unwantedinputserieshandling' },
          { label: 'PROMPT INJECTION I/O HANDLING', slug: 'promptinjectioniohandling' },
          { label: 'DOS INPUT VALIDATION', slug: 'dosinputvalidation' },
          { label: 'INPUT DISTORTION', slug: 'inputdistortion' },
          { label: 'SENSITIVE OUTPUT HANDLING', slug: 'sensitiveoutputhandling' },
          { label: 'OBSCURE CONFIDENCE', slug: 'obscureconfidence' },
        ],
      },
    ],
  },
  {
    category: '4 · Data minimisation / obfuscation',
    tone: 'pink',
    subgroups: [
      {
        heading: 'Data handling limits',
        items: [
          { label: 'DATA MINIMIZE', slug: 'dataminimize' },
          { label: 'ALLOWED DATA', slug: 'alloweddata' },
          { label: 'SHORT RETAIN', slug: 'shortretain' },
          { label: 'OBFUSCATE TRAINING DATA', slug: 'obfuscatetrainingdata' },
        ],
      },
    ],
  },
  {
    category: '5 · Limit model behaviour',
    tone: 'orange',
    subgroups: [
      {
        heading: 'Behavioural guardrails',
        items: [
          { label: 'OVERSIGHT', slug: 'oversight' },
          { label: 'LEAST MODEL PRIVILEGE', slug: 'leastmodelprivilege' },
          { label: 'MODEL ALIGNMENT', slug: 'modelalignment' },
          { label: 'AI TRANSPARENCY', slug: 'aitransparency' },
          { label: 'EXPLAINABILITY', slug: 'explainability' },
          { label: 'CONTINUOUS VALIDATION', slug: 'continuousvalidation' },
          { label: 'UNWANTED BIAS TESTING', slug: 'unwantedbiastesting' },
        ],
      },
    ],
  },
];

const GOAL_SUMMARIES: { goal: string; tone: 'blue' | 'yellow' | 'orange'; summary: string }[] = [
  { goal: 'Disclose (Confidentiality)', tone: 'blue', summary: 'Training/test data, model IP (parameters + process), input or augmentation data.' },
  { goal: 'Deceive (Integrity)', tone: 'yellow', summary: 'Model-behaviour manipulation causing unintended outputs or actions.' },
  { goal: 'Disrupt (Availability)', tone: 'orange', summary: 'Model availability + CIA of non-AI-specific assets around the model.' },
];

export function OwaspAiReference() {
  return (
    <div className="space-y-8">
      <PageHeader
        title="OWASP AI Exchange"
        subtitle="Cross-industry reference for AI & ML security, privacy, and governance controls"
        titleAction={<Badge label="Work in progress" variant="yellow" />}
      />

      {/* WIP notice */}
      <div className="rounded-lg border border-[var(--yellow-dim)] bg-[var(--yellow-faint)] px-4 py-3 text-sm text-[var(--text-primary)]">
        <p className="font-medium text-[var(--accent-yellow)] mb-1">Reference page — no machine-readable feed yet</p>
        <p className="text-[var(--text-secondary)] leading-relaxed">
          OWASP AI Exchange publishes threats and controls as prose on owaspai.org, not as JSON/YAML/CSV.
          Explicit crosswalks to MITRE ATLAS, ATT&amp;CK, CWE, and NIST AI RMF are on the 2026 roadmap.
          This page mirrors the taxonomy from the AI Security Overview and deep-links each item to its
          canonical Exchange page via <code className="px-1 rounded bg-[var(--surface-deep)] text-[var(--accent-teal)]">/go/&lt;slug&gt;/</code> short-links.
          Content faithfully follows <a href="https://owaspai.org/docs/ai_security_overview/" target="_blank" rel="noopener noreferrer" className="text-[var(--accent-teal)] hover:underline">owaspai.org/docs/ai_security_overview</a>.
        </p>
      </div>

      {/* Attacker goals */}
      <section>
        <h2 className="text-sm font-bold uppercase tracking-wider text-[var(--accent-teal)] mb-3">
          Three attacker goals — six impact categories
        </h2>
        <ul className="grid gap-2 md:grid-cols-3">
          {GOAL_SUMMARIES.map((g) => (
            <li key={g.goal} className="rounded-md border border-[var(--border-color)] bg-[var(--surface-card)] px-3 py-3">
              <div className="flex items-center gap-2 mb-1.5">
                <Badge label={g.goal} variant={g.tone} />
              </div>
              <div className="text-xs text-[var(--text-secondary)] leading-relaxed">{g.summary}</div>
            </li>
          ))}
        </ul>
      </section>

      {/* Threat matrix — impact rows × surface context */}
      <section>
        <h2 className="text-sm font-bold uppercase tracking-wider text-[var(--accent-teal)] mb-3">
          Threats — by impact &amp; attack surface
        </h2>
        <p className="text-sm text-[var(--text-secondary)] mb-3 leading-relaxed">
          The OWASP AI Exchange organises threats in a matrix of six impact dimensions against five
          attack-surface/lifecycle contexts. Click any threat to open its Exchange page.
        </p>
        <div className="space-y-3">
          {THREATS.map((group) => (
            <div
              key={group.impact}
              className="rounded-md border border-[var(--border-color)] bg-[var(--surface-card)] px-4 py-3"
            >
              <div className="flex items-center justify-between mb-2">
                <div className="text-sm font-semibold text-[var(--text-primary)]">{group.impact}</div>
                <Badge label={group.goal} variant={group.goal === 'Disclose' ? 'blue' : group.goal === 'Deceive' ? 'yellow' : 'orange'} />
              </div>
              <ul className="space-y-1.5">
                {group.threats.map((t) => (
                  <li key={t.slug} className="flex items-start gap-2">
                    <span className="mt-0.5 shrink-0 text-[10px] uppercase tracking-wider text-[var(--text-secondary)] opacity-70 min-w-[14ch]">
                      {t.surface}
                    </span>
                    <a
                      href={`${GO_BASE}${t.slug}/`}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="text-sm text-[var(--text-primary)] hover:text-[var(--accent-teal)] hover:underline"
                    >
                      {t.label}
                    </a>
                  </li>
                ))}
              </ul>
            </div>
          ))}
        </div>
      </section>

      {/* Controls — 5 top categories */}
      <section>
        <h2 className="text-sm font-bold uppercase tracking-wider text-[var(--accent-teal)] mb-3">
          Controls — 5 categories
        </h2>
        <div className="space-y-3">
          {CONTROLS.map((cat) => (
            <div
              key={cat.category}
              className="rounded-md border border-[var(--border-color)] bg-[var(--surface-card)] px-4 py-3"
            >
              <div className="mb-2">
                <Badge label={cat.category} variant={cat.tone} />
              </div>
              <div className="space-y-2.5">
                {cat.subgroups.map((sub) => (
                  <div key={sub.heading}>
                    <div className="text-[11px] uppercase tracking-wider text-[var(--text-secondary)] mb-1.5">
                      {sub.heading}
                    </div>
                    <ul className="flex flex-wrap gap-1.5">
                      {sub.items.map((item) => (
                        <li key={`${sub.heading}-${item.slug}`}>
                          <a
                            href={`${GO_BASE}${item.slug}/`}
                            target="_blank"
                            rel="noopener noreferrer"
                            className="inline-flex items-center px-2 py-0.5 rounded-full text-[11px] font-mono font-medium border border-[var(--border-color)] bg-[var(--hover-overlay)] text-[var(--text-primary)] hover:border-[var(--accent-teal)] hover:text-[var(--accent-teal)]"
                          >
                            {item.label}
                          </a>
                        </li>
                      ))}
                    </ul>
                  </div>
                ))}
              </div>
            </div>
          ))}
        </div>
      </section>

      {/* Framework alignment */}
      <section>
        <h2 className="text-sm font-bold uppercase tracking-wider text-[var(--accent-teal)] mb-3">
          Framework alignment status
        </h2>
        <div className="overflow-x-auto rounded-md border border-[var(--border-color)]">
          <table className="w-full text-sm">
            <thead className="bg-[var(--surface-deep)] text-left text-xs uppercase tracking-wider text-[var(--text-secondary)]">
              <tr>
                <th className="px-3 py-2 font-semibold">Framework</th>
                <th className="px-3 py-2 font-semibold">Status</th>
                <th className="px-3 py-2 font-semibold">Note</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-[var(--border-color)]">
              {[
                { framework: 'ISO/IEC 27090 (AI security)', status: 'aligned', note: 'Active editorial contribution by OWASP AI Exchange.' },
                { framework: 'ISO/IEC 27091 (AI privacy)', status: 'aligned', note: 'Parallel contribution track.' },
                { framework: 'ISO/IEC 5338 (AI lifecycle)', status: 'aligned', note: 'Lifecycle language shared with Exchange taxonomy.' },
                { framework: 'EU AI Act', status: 'partial', note: '~70 pages contributed during drafting — no formal crosswalk yet.' },
                { framework: 'MITRE ATLAS', status: 'roadmap', note: 'Harmonisation prioritised for summer 2026.' },
                { framework: 'NIST AI RMF', status: 'roadmap', note: 'Mapping planned alongside ATLAS harmonisation.' },
                { framework: 'MITRE ATT&CK / CWE', status: 'roadmap', note: 'No explicit per-threat mapping in the current release.' },
              ].map((a) => {
                const variant = a.status === 'aligned' ? 'green' : a.status === 'partial' ? 'yellow' : 'neutral';
                return (
                  <tr key={a.framework} className="bg-[var(--surface-card)]">
                    <td className="px-3 py-2 font-medium text-[var(--text-primary)]">{a.framework}</td>
                    <td className="px-3 py-2">
                      <Badge label={a.status} variant={variant as 'green' | 'yellow' | 'neutral'} />
                    </td>
                    <td className="px-3 py-2 text-[var(--text-secondary)]">{a.note}</td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      </section>

      {/* External references */}
      <section>
        <h2 className="text-sm font-bold uppercase tracking-wider text-[var(--accent-teal)] mb-3">References</h2>
        <ul className="space-y-1.5 text-sm">
          <li>
            <a
              href="https://owaspai.org/docs/ai_security_overview/"
              target="_blank"
              rel="noopener noreferrer"
              className="text-[var(--accent-teal)] hover:underline"
            >
              AI Security Overview — canonical threat + control catalogue
            </a>
          </li>
          <li>
            <a
              href="https://owaspai.org/"
              target="_blank"
              rel="noopener noreferrer"
              className="text-[var(--accent-teal)] hover:underline"
            >
              OWASP AI Exchange — project home
            </a>
          </li>
          <li>
            <a
              href="https://owaspai.org/docs/2_threats_through_use/"
              target="_blank"
              rel="noopener noreferrer"
              className="text-[var(--accent-teal)] hover:underline"
            >
              Threats through use (runtime model-input threats)
            </a>
          </li>
          <li>
            <a
              href="https://owaspai.org/docs/3_development_time_threats/"
              target="_blank"
              rel="noopener noreferrer"
              className="text-[var(--accent-teal)] hover:underline"
            >
              Development-time threats
            </a>
          </li>
          <li>
            <a
              href="https://github.com/OWASP/www-project-ai-security-and-privacy-guide"
              target="_blank"
              rel="noopener noreferrer"
              className="text-[var(--accent-teal)] hover:underline"
            >
              OWASP AI Security &amp; Privacy Guide (GitHub)
            </a>
          </li>
        </ul>
      </section>
    </div>
  );
}
