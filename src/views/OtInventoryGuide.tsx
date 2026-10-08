import Link from 'next/link';
import { PageHeader } from '../components/layout/PageHeader';
import { Badge } from '../components/shared/Badge';
import {
  CISA_OT_SOURCE,
  INVENTORY_STEPS,
  INVENTORY_FIELDS,
  ICS_ASSET_NAMES,
  SECTORS,
  sectorTable,
  sectorCoverage,
  assetsForCriticality,
  otProfileHref,
} from '../lib/cisa-ot-inventory.mjs';

/**
 * CISA's multinational OT asset-inventory guidance, and this project's
 * crosswalk from its example sector taxonomies to the ATT&CK for ICS assets.
 *
 * The crosswalk is curation, and the page leads with that: the guide carries
 * no ATT&CK identifier, so each row's `match` + `rationale` is a judgement,
 * shown next to the row it judges. Rows ATT&CK does not model (pumps,
 * transformers, HVAC) are listed with `none` rather than dropped, and each
 * sector's split is shown as numbers.
 *
 * "Rank" links go to the OT threat profile one criticality level at a time —
 * a whole sector reaches most of the 18 assets, where lift stops meaning
 * anything (see assetsForCriticality).
 *
 * Server component: static data, no interaction.
 */

const H2 = 'text-sm font-bold uppercase tracking-wider text-[var(--accent-teal)]';
const LINK = 'text-[var(--accent-teal)] hover:underline';

const PRIORITY_VARIANT = { high: 'orange', medium: 'yellow', low: 'neutral' } as const;
const MATCH_VARIANT = { direct: 'teal', partial: 'blue', none: 'neutral' } as const;
const CRIT_LABEL = { high: 'High criticality', medium: 'Medium criticality', low: 'Low criticality' } as const;

export function OtInventoryGuide() {
  return (
    <div className="space-y-6">
      <PageHeader
        title="OT Asset Inventory"
        subtitle={
          <>
            CISA and eight partner agencies&rsquo; guidance for building an OT asset inventory and taxonomy (
            {CISA_OT_SOURCE.published}), with its example sector taxonomies mapped to the 18 ATT&amp;CK for ICS
            assets.
          </>
        }
        breadcrumb={[{ label: 'Frameworks' }, { label: 'OT Asset Inventory' }]}
      />

      <section className="rounded-lg border border-[var(--border-color)] bg-[var(--surface-card)] p-4">
        <div className="flex flex-wrap items-center gap-2 mb-2">
          <h2 className={H2}>Crosswalk is this site&rsquo;s curation</h2>
          <Badge label="editorial" variant="yellow" />
        </div>
        <p className="text-sm text-[var(--text-secondary)] leading-relaxed">
          The guide carries no ATT&amp;CK identifier. The steps, fields and taxonomy rows below are CISA&rsquo;s;
          the link from each row to an ATT&amp;CK ICS asset is ours, with the reason beside it.{' '}
          <strong className="text-[var(--text-primary)]">direct</strong> means the row names the device class ATT&amp;CK
          models; <strong className="text-[var(--text-primary)]">partial</strong> means ATT&amp;CK models part of it;{' '}
          <strong className="text-[var(--text-primary)]">none</strong> means physical process, power or facility
          equipment that ATT&amp;CK for ICS does not model — listed anyway, because hiding it would overstate the
          coverage. CISA itself calls these taxonomies examples, not authoritative.
        </p>
        <ul className="mt-3 grid gap-2 sm:grid-cols-3">
          {SECTORS.map((s) => {
            const c = sectorCoverage(s.key);
            return (
              <li key={s.key} className="rounded-md border border-[var(--border-color)] px-3 py-2">
                <a href={`#${s.key}`} className="text-sm font-semibold text-[var(--text-primary)] hover:underline">{s.label}</a>
                <div className="text-xs text-[var(--text-secondary)] tabular-nums">
                  {c.total} rows · {c.direct} direct · {c.partial} partial · {c.none} none · {c.assets.length} of 18 assets
                </div>
              </li>
            );
          })}
        </ul>
      </section>

      <section>
        <h2 className={`${H2} mb-3`}>Five steps</h2>
        <ol className="grid gap-2 sm:grid-cols-2 lg:grid-cols-5">
          {INVENTORY_STEPS.map((s) => (
            <li key={s.n} className="rounded-md border border-[var(--border-color)] bg-[var(--surface-card)] px-3 py-2">
              <div className="text-sm font-semibold text-[var(--text-primary)]">
                <span className="font-mono text-[var(--accent-orange)] mr-1.5">{s.n}</span>{s.title}
              </div>
              <div className="text-xs text-[var(--text-secondary)] leading-relaxed">{s.summary}</div>
            </li>
          ))}
        </ol>
      </section>

      <section>
        <h2 className={`${H2} mb-1`}>Inventory fields (Appendix A)</h2>
        <p className="text-sm text-[var(--text-secondary)] mb-3 leading-relaxed">
          Collect the high-priority fields first. Where a field drives something on this site, the last column says
          where.
        </p>
        <div className="overflow-x-auto rounded-md border border-[var(--border-color)]">
          <table className="w-full text-xs">
            <thead className="bg-[var(--surface-card)] text-[var(--text-secondary)] uppercase tracking-wider text-[10px]">
              <tr>
                <th className="text-left px-3 py-2">Field</th>
                <th className="text-left px-3 py-2">Priority</th>
                <th className="text-left px-3 py-2">Why</th>
                <th className="text-left px-3 py-2">On this site</th>
              </tr>
            </thead>
            <tbody>
              {INVENTORY_FIELDS.map((f) => (
                <tr key={f.field} className="border-t border-[var(--border-color)] align-top">
                  <td className="px-3 py-1.5 text-[var(--text-primary)] font-medium">{f.field}</td>
                  <td className="px-3 py-1.5"><Badge label={f.priority} variant={PRIORITY_VARIANT[f.priority]} /></td>
                  <td className="px-3 py-1.5 text-[var(--text-secondary)]">{f.benefit}</td>
                  <td className="px-3 py-1.5">
                    {f.inApp ? (
                      f.inApp.href.startsWith('#') ? (
                        <a href={f.inApp.href} className={LINK}>{f.inApp.label}</a>
                      ) : (
                        <Link href={f.inApp.href} className={LINK}>{f.inApp.label}</Link>
                      )
                    ) : (
                      <span className="text-[var(--text-secondary)]">—</span>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </section>

      <section id="taxonomies" className="space-y-6">
        <h2 className={H2}>Sector taxonomies → ATT&amp;CK ICS assets</h2>
        {SECTORS.map((s) => (
          <div key={s.key} id={s.key} className="space-y-3 scroll-mt-20">
            <div className="flex flex-wrap items-baseline gap-2">
              <h3 className="text-base font-semibold text-[var(--text-primary)]">{s.label}</h3>
              <span className="text-xs text-[var(--text-secondary)]">{s.tables}</span>
            </div>
            {sectorTable(s.key).map((g) => {
              const assets = assetsForCriticality(s.key, g.criticality);
              return (
                <div key={g.criticality} className="rounded-lg border border-[var(--border-color)] overflow-hidden">
                  <div className="flex flex-wrap items-center justify-between gap-2 px-3 py-2 bg-[var(--surface-card)]">
                    <span className="text-xs font-bold uppercase tracking-wider text-[var(--text-secondary)]">
                      {CRIT_LABEL[g.criticality]}
                    </span>
                    {assets.length > 0 && (
                      <Link href={otProfileHref(assets)} className="text-xs text-[var(--accent-teal)] hover:underline">
                        Rank ICS techniques for these {assets.length} assets →
                      </Link>
                    )}
                  </div>
                  <div className="divide-y divide-[var(--border-color)]">
                    {g.categories.map((c) => (
                      <div key={c.category} className="px-3 py-2">
                        <div className="text-[11px] font-semibold uppercase tracking-wider text-[var(--text-secondary)] mb-1">
                          {c.category}
                        </div>
                        <ul className="space-y-1.5">
                          {c.items.map((it) => (
                            <li key={it.key} className="grid gap-x-3 gap-y-0.5 sm:grid-cols-[minmax(0,2fr)_auto_minmax(0,3fr)]">
                              <span className="text-sm text-[var(--text-primary)]">{it.item}</span>
                              <span className="flex flex-wrap items-start gap-1">
                                <Badge label={it.match} variant={MATCH_VARIANT[it.match]} />
                                {it.assets.map((a) => (
                                  <Link
                                    key={a}
                                    href={`/assets/${a}`}
                                    title={ICS_ASSET_NAMES[a]}
                                    className="font-mono text-[11px] text-[var(--accent-teal)] hover:underline"
                                  >
                                    {a}
                                  </Link>
                                ))}
                              </span>
                              <span className="text-[11px] text-[var(--text-secondary)] leading-relaxed">{it.rationale}</span>
                            </li>
                          ))}
                        </ul>
                      </div>
                    ))}
                  </div>
                </div>
              );
            })}
          </div>
        ))}
      </section>

      <section>
        <h2 className={`${H2} mb-3`}>Source</h2>
        <p className="text-sm text-[var(--text-secondary)] leading-relaxed">
          {CISA_OT_SOURCE.publisher} with {CISA_OT_SOURCE.coAuthors.join(', ')},{' '}
          <a href={CISA_OT_SOURCE.page} target="_blank" rel="noopener noreferrer" className={LINK}>
            <em>{CISA_OT_SOURCE.title}</em>
          </a>{' '}
          ({CISA_OT_SOURCE.published}, {CISA_OT_SOURCE.marking}; <a href={CISA_OT_SOURCE.pdf} target="_blank" rel="noopener noreferrer" className={LINK}>PDF</a>).
          Field benefits are paraphrased; taxonomy rows are quoted. The ATT&amp;CK asset mapping is this
          project&rsquo;s, as are the Purdue placements it lands on (<Link href="/frameworks/purdue" className={LINK}>Purdue model</Link>).
          Not affiliated with or endorsed by CISA or its co-authors.
        </p>
      </section>
    </div>
  );
}
