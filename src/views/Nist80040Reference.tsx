import Link from 'next/link';
import { PageHeader } from '../components/layout/PageHeader';
import { Badge } from '../components/shared/Badge';
import { Nist80040ControlBridge } from '../components/frameworks/Nist80040ControlBridge';
import {
  NIST_800_40_SOURCE,
  RISK_RESPONSES,
  LIFE_CYCLE,
  SCENARIOS,
  MAINTENANCE_GROUP_EXAMPLES,
  PRINCIPLES,
  RECOMMENDATIONS,
  METRICS_MATRIX,
  CSF_11_SUBCATEGORIES,
  PROCUREMENT_QUESTIONS,
} from '../lib/nist-800-40.mjs';

/**
 * NIST SP 800-40 Rev. 4 — enterprise patch management planning.
 *
 * A reference page with one sourced bridge to ATT&CK (NIST's own list of
 * SP 800-53 controls -> CTID's control mappings), rendered by the client
 * component; everything else is server-rendered text. Scenarios 2 and 3 link
 * to the KEV list because the publication itself names the KEV catalogue as
 * the prioritisation input for emergencies.
 */

const H2 = 'text-sm font-bold uppercase tracking-wider text-[var(--accent-teal)]';
const CARD = 'rounded-md border border-[var(--border-color)] bg-[var(--surface-card)] px-3 py-2';
const LINK = 'text-[var(--accent-teal)] hover:underline';

export function Nist80040Reference() {
  return (
    <div className="space-y-6">
      <PageHeader
        title="NIST SP 800-40 Rev. 4"
        subtitle={<>{NIST_800_40_SOURCE.title} — {NIST_800_40_SOURCE.published}.</>}
        breadcrumb={[{ label: 'Frameworks' }, { label: 'NIST SP 800-40' }]}
      />

      <section className="rounded-lg border border-[var(--border-color)] bg-[var(--surface-card)] p-4">
        <div className="flex flex-wrap items-center gap-2 mb-2">
          <h2 className={H2}>How it reaches ATT&amp;CK</h2>
          <Badge label="via NIST's own control list" variant="teal" />
        </div>
        <p className="text-sm text-[var(--text-secondary)] leading-relaxed mb-3">
          The publication cites no ATT&amp;CK technique. Its appendix does name the eight SP 800-53 Rev. 5 controls
          &ldquo;most important for enterprise patch management planning&rdquo;, and CTID maps 800-53 controls to
          techniques. Those two published lists are the whole bridge: nothing below is this site&rsquo;s judgement.
          Counts are live; a zero means CTID maps no technique to that control.
        </p>
        <Nist80040ControlBridge />
      </section>

      <section>
        <h2 className={`${H2} mb-3`}>Four risk responses</h2>
        <p className="text-sm text-[var(--text-secondary)] mb-3 leading-relaxed">
          Patching is one way to mitigate. Until a response is chosen, the organisation has accepted the risk by default.
        </p>
        <ul className="grid gap-2 sm:grid-cols-2 lg:grid-cols-4">
          {RISK_RESPONSES.map((r) => (
            <li key={r.key} className={CARD}>
              <div className="text-sm font-semibold text-[var(--text-primary)]">{r.label}</div>
              <div className="text-xs text-[var(--text-secondary)] leading-relaxed">{r.summary}</div>
            </li>
          ))}
        </ul>
      </section>

      <section>
        <h2 className={`${H2} mb-3`}>Vulnerability management life cycle</h2>
        <ol className="grid gap-2 sm:grid-cols-3">
          {LIFE_CYCLE.map((s) => (
            <li key={s.step} className={CARD}>
              <div className="text-sm font-semibold text-[var(--text-primary)]">
                <span className="font-mono text-[var(--accent-orange)] mr-1.5">{s.step}</span>{s.label}
              </div>
              <div className="text-xs text-[var(--text-secondary)] leading-relaxed">{s.summary}</div>
            </li>
          ))}
        </ol>
      </section>

      <section>
        <h2 className={`${H2} mb-1`}>Risk response scenarios and their maintenance plans</h2>
        <p className="text-sm text-[var(--text-secondary)] mb-3 leading-relaxed">
          Decided in advance, per maintenance group, so a new vulnerability needs a lookup rather than a meeting.
          For the two emergency scenarios the publication points to CISA&rsquo;s{' '}
          <Link href="/cti/cves?source=cisa_kev" className={LINK}>Known Exploited Vulnerabilities</Link>{' '}
          catalogue, which BOD 22-01 gives US federal agencies two weeks to remediate.
        </p>
        <ul className="space-y-2">
          {SCENARIOS.map((s) => (
            <li key={s.key} className={CARD}>
              <div className="flex flex-wrap items-baseline gap-2">
                <span className="font-mono text-xs text-[var(--accent-orange)]">{s.n}</span>
                <span className="text-sm font-semibold text-[var(--text-primary)]">{s.label}</span>
                {(s.key === 'emergency-patch' || s.key === 'emergency-mitigation') && (
                  <Link href="/cti/cves?source=cisa_kev" className="text-[11px] text-[var(--accent-teal)] hover:underline">
                    KEV list ↗
                  </Link>
                )}
              </div>
              <div className="mt-1 grid gap-1 sm:grid-cols-2 text-xs leading-relaxed">
                <div><span className="text-[var(--text-secondary)] uppercase tracking-wider text-[10px] mr-1">When</span><span className="text-[var(--text-primary)]">{s.when}</span></div>
                <div><span className="text-[var(--text-secondary)] uppercase tracking-wider text-[10px] mr-1">Plan</span><span className="text-[var(--text-primary)]">{s.plan}</span></div>
              </div>
            </li>
          ))}
        </ul>
      </section>

      <section>
        <h2 className={`${H2} mb-1`}>Example maintenance groups</h2>
        <p className="text-sm text-[var(--text-secondary)] mb-3 leading-relaxed">
          NIST&rsquo;s own six illustrations. An asset that cannot be patched is not an exception — it belongs to a
          group with its own plan, like the legacy OT row.
        </p>
        <div className="overflow-x-auto rounded-md border border-[var(--border-color)]">
          <table className="w-full text-xs">
            <thead className="bg-[var(--surface-card)] text-[var(--text-secondary)] uppercase tracking-wider text-[10px]">
              <tr>
                <th className="text-left px-3 py-2">Group</th>
                <th className="text-left px-3 py-2">Software to patch</th>
                <th className="text-left px-3 py-2">Outage restrictions</th>
                <th className="text-left px-3 py-2">Existing mitigations</th>
                <th className="text-left px-3 py-2">Impact if compromised</th>
              </tr>
            </thead>
            <tbody>
              {MAINTENANCE_GROUP_EXAMPLES.map((g) => (
                <tr key={g.label} className="border-t border-[var(--border-color)] align-top">
                  <td className="px-3 py-2 text-[var(--text-primary)] font-medium">{g.label}</td>
                  <td className="px-3 py-2 text-[var(--text-secondary)]">{g.software}</td>
                  <td className="px-3 py-2 text-[var(--text-secondary)]">{g.outage}</td>
                  <td className="px-3 py-2 text-[var(--text-secondary)]">{g.mitigations}</td>
                  <td className="px-3 py-2">
                    <Badge label={g.impact} variant={g.impact === 'High' ? 'orange' : 'neutral'} />
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </section>

      <section className="grid gap-4 lg:grid-cols-2">
        <div>
          <h2 className={`${H2} mb-3`}>Principles</h2>
          <ul className="space-y-2">
            {PRINCIPLES.map((p) => (
              <li key={p.label} className={CARD}>
                <div className="text-sm font-semibold text-[var(--text-primary)]">{p.label}</div>
                <div className="text-xs text-[var(--text-secondary)] leading-relaxed">{p.summary}</div>
              </li>
            ))}
          </ul>
        </div>
        <div>
          <h2 className={`${H2} mb-3`}>Recommendations</h2>
          <ol className="space-y-1.5">
            {RECOMMENDATIONS.map((r) => (
              <li key={r.section} className="flex gap-2 text-sm">
                <span className="font-mono text-xs text-[var(--accent-orange)] w-7 shrink-0 pt-0.5">{r.section}</span>
                <span className="text-[var(--text-primary)]">{r.label}</span>
              </li>
            ))}
          </ol>
        </div>
      </section>

      <section>
        <h2 className={`${H2} mb-1`}>Actionable metrics (§3.6)</h2>
        <p className="text-sm text-[var(--text-secondary)] mb-2 leading-relaxed">{METRICS_MATRIX.caution}</p>
        <div className={`${CARD} text-xs leading-relaxed`}>
          <div><span className="text-[var(--text-secondary)]">Rows:</span> <span className="text-[var(--text-primary)]">{METRICS_MATRIX.rows}</span></div>
          <div><span className="text-[var(--text-secondary)]">Columns:</span> <span className="text-[var(--text-primary)]">{METRICS_MATRIX.columns}</span></div>
          <div><span className="text-[var(--text-secondary)]">Each cell:</span> <span className="text-[var(--text-primary)]">{METRICS_MATRIX.measures.join(' · ')}</span></div>
          <div className="mt-1 text-[var(--text-secondary)]">
            NIST&rsquo;s table uses illustrative numbers, so only its shape is shown. For building a measurement
            programme, see{' '}
            <a href={METRICS_MATRIX.measurementGuide.url} target="_blank" rel="noopener noreferrer" className={LINK}>
              {METRICS_MATRIX.measurementGuide.id}
            </a>.
          </div>
        </div>
      </section>

      <section>
        <h2 className={`${H2} mb-3`}>Procurement questions (§3.7)</h2>
        <ol className="list-decimal pl-5 space-y-1 text-sm text-[var(--text-primary)]">
          {PROCUREMENT_QUESTIONS.map((q) => <li key={q}>{q}</li>)}
        </ol>
      </section>

      <section>
        <h2 className={`${H2} mb-1`}>CSF subcategories named in the appendix</h2>
        <p className="text-sm text-[var(--text-secondary)] mb-3 leading-relaxed">
          These are CSF 1.1 identifiers, listed as published. They are not translated to CSF 2.0 here: NIST&rsquo;s
          1.1 → 2.0 mapping is many-to-many, so a translation would be this site&rsquo;s choice. The CSF 2.0
          crosswalk to ATT&amp;CK is on <Link href="/frameworks/csf" className={LINK}>NIST CSF v2</Link>.
        </p>
        <ul className="grid gap-1.5 sm:grid-cols-2">
          {CSF_11_SUBCATEGORIES.map((c) => (
            <li key={c.id} className="flex gap-2 text-xs">
              <span className="font-mono text-[var(--accent-orange)] w-16 shrink-0">{c.id}</span>
              <span className="text-[var(--text-primary)]">{c.title}</span>
            </li>
          ))}
        </ul>
      </section>

      <section>
        <h2 className={`${H2} mb-3`}>Source</h2>
        <p className="text-sm text-[var(--text-secondary)] leading-relaxed">
          {NIST_800_40_SOURCE.authors},{' '}
          <a href={NIST_800_40_SOURCE.doi} target="_blank" rel="noopener noreferrer" className={LINK}>
            <em>{NIST_800_40_SOURCE.title}</em>
          </a>
          , NIST {NIST_800_40_SOURCE.id} ({NIST_800_40_SOURCE.published}). A US Government work; section text is
          paraphrased, control and subcategory titles are quoted. Implementation companion:{' '}
          <a href={NIST_800_40_SOURCE.companion.url} target="_blank" rel="noopener noreferrer" className={LINK}>
            {NIST_800_40_SOURCE.companion.id}, {NIST_800_40_SOURCE.companion.title}
          </a>
          . Control-to-technique mappings: MITRE Center for Threat-Informed Defense. Not affiliated with or endorsed by NIST.
        </p>
      </section>
    </div>
  );
}
