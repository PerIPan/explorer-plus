import { PageHeader } from '../components/layout/PageHeader';
import { Badge } from '../components/shared/Badge';
import {
  ENISA_SBD_PLAYBOOKS,
  ENISA_SBD_GROUPS,
  ENISA_SBD_COUNT,
  ENISA_SBD_SOURCE,
  sbdUrl,
} from '../lib/enisa-sbd';

/**
 * ENISA's Secure by Design and Default playbooks.
 *
 * A reading list, not a crosswalk, and the page says so above the fold. The
 * absence is measured rather than hedged: across all 22 playbooks, none
 * mentions ATT&CK, a T-number, CWE, CAPEC, NIST, ISO, IEC 62443, D3FEND or
 * NIS2, and exactly one mentions OWASP. There is no identifier to join on, so
 * every other page in the Frameworks section can bridge to techniques and this
 * one cannot.
 *
 * It is NOT on the CRA page, which was the first instinct and was wrong. The
 * source mentions the CRA exactly once, as a disclaimer — "This guidance is
 * without prejudice to such obligations, which take precedence" — so ENISA
 * distances the playbooks from the regulation rather than aligning them to it.
 * Filing them under the CRA would have asserted a compliance relationship the
 * author declines to claim.
 *
 * Server component, like the CRA and OWASP AI reference pages: nothing here is
 * interactive, so none of it needs to reach the browser as JavaScript.
 */
export function EnisaPlaybooks() {
  return (
    <div className="space-y-6">
      <PageHeader
        title="ENISA Playbooks"
        subtitle={
          <>
            Secure by Design and Secure by Default — {ENISA_SBD_COUNT} practical playbooks for SMEs,
            published by the European Union Agency for Cybersecurity.
          </>
        }
        breadcrumb={[{ label: 'Frameworks' }, { label: 'ENISA Playbooks' }]}
      />

      {/* The honesty statement, first and unavoidable. */}
      <section className="rounded-lg border border-[var(--border-color)] bg-[var(--surface-card)] p-4">
        <div className="flex flex-wrap items-center gap-2 mb-2">
          <h2 className="text-sm font-bold uppercase tracking-wider text-[var(--accent-teal)]">
            No ATT&amp;CK mapping
          </h2>
          <Badge label="reference only" variant="neutral" />
        </div>
        <p className="text-sm text-[var(--text-secondary)] leading-relaxed">
          Every other framework on this site bridges to ATT&amp;CK techniques. This one does not,
          and the reason is in the source rather than in the work: across all {ENISA_SBD_COUNT}{' '}
          playbooks, none cites an ATT&amp;CK technique, a CWE, a CAPEC pattern, a NIST control, an
          ISO clause, IEC 62443, D3FEND or NIS2 — one mentions OWASP. With no identifier to join
          on, any crosswalk shown here would be this project&rsquo;s editorial opinion presented as
          data, so none is shown. The playbooks are reproduced as a reading list, with their
          provenance attached.
        </p>
      </section>

      <section>
        <h2 className="text-sm font-bold uppercase tracking-wider text-[var(--accent-teal)] mb-3">
          What each playbook contains
        </h2>
        <ul className="grid gap-2 sm:grid-cols-2 lg:grid-cols-5">
          {[
            ['Principle', 'the security property being upheld'],
            ['Objective', 'what applying it should achieve'],
            ['Checklist', 'the steps, in order'],
            ['Minimum evidence', 'what to keep to show it was done'],
            ['Release gate', 'the checks that must pass to ship'],
          ].map(([label, hint]) => (
            <li
              key={label}
              className="rounded-md border border-[var(--border-color)] bg-[var(--surface-card)] px-3 py-2"
            >
              <div className="text-sm font-semibold text-[var(--text-primary)]">{label}</div>
              <div className="text-xs text-[var(--text-secondary)] leading-relaxed">{hint}</div>
            </li>
          ))}
        </ul>
      </section>

      {/* The playbooks, in ENISA's own two groups and four sub-sections, in the
          source's numbering rather than alphabetically. */}
      {ENISA_SBD_GROUPS.map((g) => {
        const inGroup = ENISA_SBD_PLAYBOOKS.filter((p) => p.group === g.key);
        const sections = [...new Set(inGroup.map((p) => p.section))];
        return (
          <section key={g.key}>
            <div className="flex flex-wrap items-baseline gap-x-2 mb-1">
              <h2 className="text-sm font-bold uppercase tracking-wider text-[var(--accent-teal)]">
                {g.label}
              </h2>
              <span className="rounded-full border border-[var(--teal-dim)] bg-[var(--teal-faint)] px-2 py-0.5 text-xs font-semibold tabular-nums text-[var(--accent-teal)]">
                {inGroup.length}
              </span>
            </div>
            <p className="text-sm text-[var(--text-secondary)] mb-3 leading-relaxed">{g.blurb}</p>

            {sections.map((s) => (
              <div key={s} className="mb-4">
                <p className="text-[11px] font-semibold uppercase tracking-wider text-[var(--text-secondary)] mb-1.5">
                  {s}
                </p>
                <ul className="space-y-2">
                  {inGroup
                    .filter((p) => p.section === s)
                    .map((p) => (
                      <li key={p.id}>
                        <a
                          href={sbdUrl(p)}
                          target="_blank"
                          rel="noopener noreferrer"
                          className="flex items-start gap-3 rounded-md border border-[var(--border-color)] bg-[var(--surface-card)] px-3 py-2 hover:border-[var(--border-hover)] hover:bg-[var(--hover-overlay)] transition-colors"
                        >
                          <span className="mt-0.5 w-6 shrink-0 font-mono text-xs tabular-nums text-[var(--accent-orange)]">
                            {p.id}
                          </span>
                          <span className="min-w-0">
                            <span className="block text-sm font-semibold text-[var(--text-primary)]">
                              {p.title}
                            </span>
                            <span className="block text-xs leading-relaxed text-[var(--text-secondary)]">
                              {p.principle}
                            </span>
                          </span>
                        </a>
                      </li>
                    ))}
                </ul>
              </div>
            ))}
          </section>
        );
      })}

      {/* CC BY 4.0 requires attribution, and this is it. That licence is also
          why the titles and principle text above may be reproduced at all —
          unlike ISO 27002, PCI DSS, SOC 2, IEC 62443 or CIS Controls, whose
          text this project never shows. */}
      <section>
        <h2 className="text-sm font-bold uppercase tracking-wider text-[var(--accent-teal)] mb-3">
          Source
        </h2>
        <p className="text-sm text-[var(--text-secondary)] leading-relaxed">
          {ENISA_SBD_SOURCE.publisher},{' '}
          <a
            href={ENISA_SBD_SOURCE.pdf}
            target="_blank"
            rel="noopener noreferrer"
            className="text-[var(--accent-teal)] hover:underline"
          >
            <em>{ENISA_SBD_SOURCE.title}</em>: {ENISA_SBD_SOURCE.subtitle}
          </a>{' '}
          {ENISA_SBD_SOURCE.version} ({ENISA_SBD_SOURCE.published}). Licensed{' '}
          <a
            href={ENISA_SBD_SOURCE.licenceUrl}
            target="_blank"
            rel="noopener noreferrer"
            className="text-[var(--accent-teal)] hover:underline"
          >
            {ENISA_SBD_SOURCE.licence}
          </a>
          ; titles and principle text are reproduced under it, and the groupings are
          ENISA&rsquo;s own. Each entry links to its playbook in the{' '}
          <a
            href={ENISA_SBD_SOURCE.repo}
            target="_blank"
            rel="noopener noreferrer"
            className="text-[var(--accent-teal)] hover:underline"
          >
            source repository
          </a>
          . Not affiliated with or endorsed by ENISA.
        </p>
      </section>
    </div>
  );
}
