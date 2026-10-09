import Link from 'next/link';
import { PageHeader } from '../components/layout/PageHeader';
import { Badge } from '../components/shared/Badge';
import {
  FAIR_CAM_SOURCE,
  FAIR_CAM_ATTRIBUTION,
  FAIR_CAM_DOMAINS,
  FAIR_CAM_FUNCTIONS,
  FAIR_CAM_GROUP_RELATIONS,
  FAIR_CAM_EFFECTIVENESS,
} from '../lib/fair-cam.mjs';
import { D3FEND_TO_FAIR_CAM, MITIGATION_TO_FAIR_CAM } from '../lib/fair-cam-mappings.mjs';

/**
 * FAIR-CAM v1.0 as a reference page, plus this site's classification of
 * D3FEND and ATT&CK controls into its functions.
 *
 * Two kinds of text live here and are kept visibly apart:
 *   - FAIR-CAM's own — names, definitions, units, relationships — quoted from
 *     src/lib/fair-cam.mjs, rendered in quotation blocks, never paraphrased
 *     (CC BY-NC-ND 4.0: no modified versions);
 *   - ours — what the site does with it — in plain paragraphs headed
 *     "On this site", and the mapping tables, labelled as our curation.
 * Attribution sits at the top and the bottom, with the licence link and the
 * fairinstitute.org/FAIR-CAM reference the Standard asks for.
 *
 * Server component: no interaction beyond <details>.
 */

const H2 = 'text-sm font-bold uppercase tracking-wider text-[var(--accent-teal)]';
const LINK = 'text-[var(--accent-teal)] hover:underline';
const QUOTE = 'border-l-2 border-[var(--teal-dim)] pl-3 text-sm text-[var(--text-primary)] leading-relaxed';

const NAME = Object.fromEntries(FAIR_CAM_FUNCTIONS.map((f) => [f.id, f.name]));

function Attribution() {
  return (
    <p className="text-xs text-[var(--text-secondary)] leading-relaxed">
      {FAIR_CAM_ATTRIBUTION}{' '}
      <a href={FAIR_CAM_SOURCE.licenceUrl} target="_blank" rel="noopener noreferrer" className={LINK}>Licence</a>
      {' · '}
      <a href={FAIR_CAM_SOURCE.referenceUrl} target="_blank" rel="noopener noreferrer" className={LINK}>
        Current guidance: fairinstitute.org/FAIR-CAM
      </a>
      {' · '}
      <a href={FAIR_CAM_SOURCE.standardPdf} target="_blank" rel="noopener noreferrer" className={LINK}>Standard v1.0 (PDF)</a>
    </p>
  );
}

/** Rows of a mapping table grouped by the function they serve. */
function byFunction(table: Readonly<Record<string, { functions: readonly string[]; rationale: string; notAControl?: boolean }>>) {
  const out = new Map<string, string[]>();
  for (const [id, row] of Object.entries(table)) {
    for (const fn of row.functions) out.set(fn, [...(out.get(fn) ?? []), id]);
  }
  return out;
}

export function FairCamReference() {
  const d3 = byFunction(D3FEND_TO_FAIR_CAM);
  const mit = byFunction(MITIGATION_TO_FAIR_CAM);
  const mapped = FAIR_CAM_FUNCTIONS.filter((f) => d3.has(f.id) || mit.has(f.id));

  return (
    <div className="space-y-6">
      <PageHeader
        title="FAIR-CAM"
        subtitle={<>{FAIR_CAM_SOURCE.name} v{FAIR_CAM_SOURCE.version} — how controls affect risk, by function, with a unit of measurement for each.</>}
        breadcrumb={[{ label: 'Frameworks' }, { label: 'FAIR-CAM' }]}
      />

      <section className="rounded-lg border border-[var(--border-color)] bg-[var(--surface-card)] p-4 space-y-2">
        <Attribution />
        <div className="flex flex-wrap items-center gap-2">
          <h2 className={H2}>Two kinds of content on this page</h2>
          <Badge label="quoted" variant="teal" />
          <Badge label="our curation" variant="yellow" />
        </div>
        <p className="text-sm text-[var(--text-secondary)] leading-relaxed">
          The domains, function names, definitions, units and relationships are the FAIR Institute&rsquo;s, quoted
          unmodified and shown in indented blocks. Everything else is this site&rsquo;s: the explanations headed
          &ldquo;On this site&rdquo;, and the classification of D3FEND countermeasures and ATT&amp;CK mitigations into
          FAIR-CAM functions at the bottom. FAIR-CAM maps no D3FEND or ATT&amp;CK identifier itself, and no open
          mapping exists, so that classification is our judgement, with a reason for every row.
        </p>
      </section>

      <section>
        <h2 className={`${H2} mb-3`}>Three ways controls affect risk</h2>
        <ul className="grid gap-2 sm:grid-cols-3">
          {FAIR_CAM_DOMAINS.map((d) => (
            <li key={d.id} className="rounded-md border border-[var(--border-color)] bg-[var(--surface-card)] px-3 py-2">
              <div className="text-sm font-semibold text-[var(--text-primary)]">{d.plural} <span className="font-mono text-xs text-[var(--text-secondary)]">({d.id})</span></div>
              <blockquote className="mt-1 text-xs text-[var(--text-secondary)] italic">&ldquo;{d.effect}&rdquo;</blockquote>
            </li>
          ))}
        </ul>
      </section>

      {FAIR_CAM_DOMAINS.map((d) => {
        const fns = FAIR_CAM_FUNCTIONS.filter((f) => f.domain === d.id);
        const groups = [...new Set(fns.map((f) => f.group))];
        const groupRel = FAIR_CAM_GROUP_RELATIONS.find((r) => r.domain === d.id);
        return (
          <section key={d.id} className="space-y-3">
            <h2 className={H2}>{d.name} functions</h2>
            {groupRel && <blockquote className={QUOTE}>&ldquo;{groupRel.text}&rdquo; <span className="text-xs text-[var(--text-secondary)]">(§{groupRel.section})</span></blockquote>}
            {groups.map((g) => (
              <div key={g} className="space-y-2">
                <div className="text-[11px] font-semibold uppercase tracking-wider text-[var(--text-secondary)]">{g}</div>
                {fns.filter((f) => f.group === g).map((f) => (
                  <div key={f.id} id={f.id} className="rounded-md border border-[var(--border-color)] bg-[var(--surface-card)] px-3 py-2 scroll-mt-20">
                    <div className="flex flex-wrap items-baseline gap-2">
                      <span className="text-sm font-semibold text-[var(--text-primary)]">{f.name}</span>
                      <span className="font-mono text-[10px] text-[var(--text-secondary)]">§{f.section}</span>
                    </div>
                    <blockquote className={`${QUOTE} mt-1`}>&ldquo;{f.definition}&rdquo;</blockquote>
                    <div className="mt-1 text-xs text-[var(--text-secondary)]">
                      <span className="uppercase tracking-wider text-[10px] mr-1">Unit</span>&ldquo;{f.unit}&rdquo;
                    </div>
                    <div className="mt-1 text-xs text-[var(--text-secondary)]">
                      <span className="uppercase tracking-wider text-[10px] mr-1">Relationship</span>&ldquo;{f.relation}&rdquo;
                    </div>
                  </div>
                ))}
              </div>
            ))}
          </section>
        );
      })}

      <section className="space-y-2">
        <h2 className={H2}>Operational effectiveness</h2>
        <blockquote className={QUOTE}>&ldquo;{FAIR_CAM_EFFECTIVENESS.intro}&rdquo;</blockquote>
        <ul className="grid gap-2 sm:grid-cols-3">
          {FAIR_CAM_EFFECTIVENESS.attributes.map((a) => (
            <li key={a.name} className="rounded-md border border-[var(--border-color)] bg-[var(--surface-card)] px-3 py-2">
              <div className="text-sm font-semibold text-[var(--text-primary)]">{a.name}</div>
              <blockquote className="text-xs text-[var(--text-secondary)] italic">&ldquo;{a.text}&rdquo;</blockquote>
            </li>
          ))}
        </ul>
        <blockquote className={QUOTE}>
          &ldquo;{FAIR_CAM_EFFECTIVENESS.formulaNote}&rdquo;
          <div className="mt-1 font-mono text-xs">{FAIR_CAM_EFFECTIVENESS.reliabilityFormula} &nbsp;·&nbsp; {FAIR_CAM_EFFECTIVENESS.binaryOpEffFormula}</div>
          <div className="mt-1 text-xs">&ldquo;{FAIR_CAM_EFFECTIVENESS.example}&rdquo;</div>
          <div className="mt-1 text-[10px] text-[var(--text-secondary)]">— An Overview of FAIR-CAM (FAIR Institute)</div>
        </blockquote>
      </section>

      <section className="rounded-lg border border-[var(--border-color)] bg-[var(--surface-card)] p-4 space-y-2">
        <h2 className={H2}>On this site</h2>
        <p className="text-sm text-[var(--text-secondary)] leading-relaxed">
          This site can say which <em>candidate</em> controls exist in public knowledge bases for a technique — never
          whether an organisation has them, how well they work, how much of the estate they cover, or how often they
          drift. Those are FAIR-CAM&rsquo;s measurements, and they need your data. So the FAIR-CAM card on a
          technique&rsquo;s 360 view, and the coverage panels on a threat profile or a group, show{' '}
          <em>availability</em>: for prevention, evidence (Visibility), recognition and response, whether at least one
          candidate exists. Where none exists the card says <strong>none found</strong> only if every source that
          could supply one is loaded for that ATT&amp;CK domain; otherwise it says <strong>not covered by loaded
          sources</strong> — for example, ATT&amp;CK detection strategies and Sigma rules are loaded for Enterprise
          only. Monitoring (time between reviews) is always yours to measure, and Deterrence and Loss Reduction are
          barely modelled by these sources, so neither counts as a gap. A parent technique includes its
          sub-techniques&rsquo; controls.
        </p>
        <p className="text-sm text-[var(--text-secondary)] leading-relaxed">
          In FAIR-CAM&rsquo;s own terms, a site like this one is itself a control: it provides threat data and controls
          data to decisions (Decision Support) and helps notice changes in the threat landscape (Variance Management:
          Threat Intelligence). See a technique&rsquo;s 360 view, for example{' '}
          <Link href="/?entity=T1059.001&tab=technique-map" className={LINK}>PowerShell (T1059.001)</Link>.
        </p>
      </section>

      <section className="space-y-3">
        <div className="flex flex-wrap items-center gap-2">
          <h2 className={H2}>Our classification of controls into FAIR-CAM functions</h2>
          <Badge label="our curation" variant="yellow" />
        </div>
        <p className="text-sm text-[var(--text-secondary)] leading-relaxed">
          {Object.keys(D3FEND_TO_FAIR_CAM).length} D3FEND countermeasures and {Object.keys(MITIGATION_TO_FAIR_CAM).length}{' '}
          ATT&amp;CK Enterprise and ICS mitigations, each assigned the FAIR-CAM functions it can serve, with the
          reason. Mobile and ATLAS mitigations are not classified yet. Not reviewed or endorsed by the FAIR Institute.
        </p>
        {mapped.map((f) => (
          <details key={f.id} className="rounded-md border border-[var(--border-color)] bg-[var(--surface-card)] px-3 py-2">
            <summary className="cursor-pointer text-sm text-[var(--text-primary)]">
              <span className="font-semibold">{f.name}</span>{' '}
              <span className="text-xs text-[var(--text-secondary)]">
                {d3.get(f.id)?.length ?? 0} D3FEND · {mit.get(f.id)?.length ?? 0} mitigations
              </span>
            </summary>
            <ul className="mt-2 space-y-1 text-xs">
              {[...(d3.get(f.id) ?? []).map((id) => ({ id, row: D3FEND_TO_FAIR_CAM[id] })), ...(mit.get(f.id) ?? []).map((id) => ({ id, row: MITIGATION_TO_FAIR_CAM[id] }))].map(({ id, row }) => (
                <li key={id} className="flex gap-2">
                  <Link
                    href={id.startsWith('D3-') ? `/frameworks/d3fend/${id}` : `/mitigations/${id}`}
                    className="font-mono text-[var(--accent-orange)] w-20 shrink-0 hover:underline"
                  >
                    {id}
                  </Link>
                  <span className="text-[var(--text-secondary)]">{row.rationale}{row.functions.length > 1 ? ` (also: ${row.functions.filter((x) => x !== f.id).map((x) => NAME[x]).join(', ')})` : ''}</span>
                </li>
              ))}
            </ul>
          </details>
        ))}
      </section>

      <section className="space-y-1">
        <h2 className={H2}>Source</h2>
        <Attribution />
        <p className="text-xs text-[var(--text-secondary)]">
          Not affiliated with or endorsed by the FAIR Institute. FAIR-CAM™ is a trademark of the FAIR Institute.
          D3FEND™ and ATT&amp;CK® are trademarks of The MITRE Corporation.
        </p>
      </section>
    </div>
  );
}
