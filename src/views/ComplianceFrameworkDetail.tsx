'use client';

import { useEffect, useMemo, useState } from 'react';
import Link from 'next/link';
import { PageHeader } from '../components/layout/PageHeader';
import {
  getFrameworkEntry,
  type ScfFrameworkEntry,
} from '../lib/scf-framework-registry';
import { tacticColors as sharedTacticColors, tacticOrder as sharedTacticOrder } from '../lib/tacticColors';

interface TechniqueRef {
  attack_id: string;
  technique_name: string | null;
  tactic: string | null;
  tactic_attack_id: string | null;
  parent_attack_id: string | null;
  parent_name: string | null;
  scf_id: string;
  cve_count: number;
  has_kev: boolean;
  group_count: number;
}

// All technique / sub-technique chips link to the 360 view (entity map) rather
// than the detail page — per user preference for compliance UI navigation.
function techniqueHref(attackId: string): string {
  return `/?entity=${encodeURIComponent(attackId)}&tab=technique-map`;
}
function tacticHref(tacticAttackId: string): string {
  return `/?entity=${encodeURIComponent(tacticAttackId)}&tab=tactic-map`;
}

/** Tiny compact chip — used for heat badges next to a technique.
 *  Solid backgrounds with white/dark text for readability in both themes. */
function HeatBadges({ t }: { t: TechniqueRef }) {
  const badges: { label: string; title: string }[] = [];
  if (t.has_kev) {
    badges.push({
      label: 'KEV',
      title: 'A curated CVE for this technique is in CISA Known Exploited Vulnerabilities',
    });
  }
  if (t.cve_count >= 3) {
    badges.push({
      label: `CVE ${t.cve_count.toLocaleString()}`,
      title: 'Curated CVE→technique links (CTID / CISA hand-mapped — not CWE inference)',
    });
  }
  if (t.group_count >= 20) {
    badges.push({
      label: `WIDE ${t.group_count}`,
      title: 'Number of tracked threat groups using this technique',
    });
  } else if (t.group_count >= 5) {
    badges.push({
      label: `${t.group_count} groups`,
      title: 'Number of tracked threat groups using this technique',
    });
  }
  if (badges.length === 0) return null;
  return (
    <span className="inline-flex flex-wrap gap-1 ml-1.5">
      {badges.map((b) => (
        <span
          key={b.label}
          title={b.title}
          className={`text-[10px] font-mono px-1.5 py-0.5 rounded border whitespace-nowrap ${BADGE_CLS}`}
        >
          {b.label}
        </span>
      ))}
    </span>
  );
}

/** Legend block — explains the heat badges with definitions + calculations. */
const LEGEND_ROWS: Array<{
  label: string; short: string; definition: string; calc: string;
}> = [
  {
    label: 'KEV',
    short: "curated CVE on CISA's actively-exploited list",
    definition: 'CISA Known Exploited Vulnerabilities — a catalog of CVEs confirmed exploited in the wild. Maintained by CISA since November 2021.',
    calc: 'A curated (CTID / CISA hand-mapped) CVE for this technique is on CISA KEV. Grounded on the precise CVE→technique mappings, NOT CWE→CAPEC inference.',
  },
  {
    label: 'CVE N',
    short: 'curated CVE→technique links',
    definition: 'Count of CVEs analyst-mapped directly to this technique (CTID / CISA curated). These are high-confidence, hand-validated links — not the broad CWE→CAPEC inference, which fans catch-all weakness types onto unrelated techniques.',
    calc: "COUNT(DISTINCT cve) over capec_mappings rows with capec_id='CTID-DIRECT' for this technique. Shown when ≥3. Covers ~45 techniques with strong real-world exploitation evidence (e.g. T1190, T1203, T1059, T1068).",
  },
  {
    label: 'WIDE N',
    short: 'tracked threat groups (≥20)',
    definition: 'Named ATT&CK adversary groups (APT29, Lazarus, Volt Typhoon, …) that MITRE attributes this technique to, from open-source incident reporting.',
    calc: 'COUNT(DISTINCT group_id) over group_techniques — sourced directly from ATT&CK, no inference. Cumulative across ATT&CK history; no recency weighting.',
  },
];

// Single neutral chip style — used for every heat badge (legend + inline next to
// techniques + tactic-header summary). Keeps the page focused; signal comes
// from presence + count, not colour.
const BADGE_CLS = 'bg-transparent text-[var(--text-primary)] border-[var(--border-color)]';

function HeatLegend() {
  const [openExplain, setOpenExplain] = useState(false);
  return (
    <div className="mb-4 px-4 py-3 rounded-md border border-[var(--border-color)] bg-[var(--surface-card)]">
      <div className="flex items-baseline justify-between mb-3 gap-2 flex-wrap">
        <div className="flex items-baseline gap-2 flex-wrap">
          <h2 className="text-sm font-semibold text-[var(--text-primary)]">CTI heat signals</h2>
          <span className="text-xs text-[var(--text-secondary)]">
            · curated CVE links + threat-group breadth (not CWE inference)
          </span>
        </div>
        <button
          type="button"
          onClick={() => setOpenExplain((v) => !v)}
          className="text-[11px] text-[var(--accent-teal)] hover:underline"
        >
          {openExplain ? 'Hide definitions ▴' : 'How is this calculated? ▾'}
        </button>
      </div>
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-x-6 gap-y-2 text-[12px]">
        {LEGEND_ROWS.map((r) => (
          <div key={r.label} className="flex items-baseline gap-2">
            <span
              className={`inline-flex items-baseline gap-1.5 font-mono text-xs px-2 py-0.5 rounded border whitespace-nowrap shrink-0 cursor-help ${BADGE_CLS}`}
              title={`${r.definition}\n\nCalc: ${r.calc}`}
            >
              {r.label}
              <span
                className="inline-flex items-center justify-center w-3.5 h-3.5 rounded-full border border-[var(--text-secondary)] text-[9px] font-bold leading-none"
                aria-label="More info"
              >
                i
              </span>
            </span>
            <span className="text-[var(--text-secondary)]">{r.short}</span>
          </div>
        ))}
      </div>
      {openExplain && (
        <div className="mt-3 pt-3 border-t border-[var(--border-color)] space-y-3 text-[11px]">
          {LEGEND_ROWS.map((r) => (
            <div key={r.label}>
              <div className="flex items-baseline gap-2 mb-1">
                <span className={`font-mono text-[10px] px-1.5 py-0.5 rounded border whitespace-nowrap shrink-0 ${BADGE_CLS}`}>
                  {r.label}
                </span>
                <span className="text-[var(--text-primary)] font-medium">{r.short}</span>
              </div>
              <p className="text-[var(--text-secondary)] pl-2 leading-relaxed">
                <strong className="text-[var(--text-primary)]">Definition:</strong> {r.definition}
              </p>
              <p className="text-[var(--text-secondary)] pl-2 leading-relaxed mt-0.5">
                <strong className="text-[var(--text-primary)]">Calculation:</strong> {r.calc}
              </p>
            </div>
          ))}
          <p className="text-[10px] text-[var(--text-secondary)] italic pt-2 border-t border-[var(--border-color)]">
            Grounded on CTID hand-curated CVE→technique mappings (capec_id =
            ‘CTID-DIRECT’), <strong>not</strong> broad CWE→CAPEC inference.
            Thresholds: <strong>KEV</strong> — any curated CVE on CISA KEV;{' '}
            <strong>CVE N</strong> — shown at ≥ 3; <strong>WIDE N</strong> — ≥ 20
            tracked threat groups (or an “N groups” chip at ≥ 5).
          </p>
        </div>
      )}
    </div>
  );
}

/** Aggregate heat summary shown next to a tactic header — answers "how dangerous
 *  is this tactic for this article?". Counts KEV-backed and WIDE (≥20 groups) techniques. */
function TacticHeatSummary({ techniques }: { techniques: TechniqueRef[] }) {
  let kev = 0;
  let wide = 0;
  for (const t of techniques) {
    if (t.has_kev) kev++;
    if (t.group_count >= 20) wide++;
  }
  if (kev === 0 && wide === 0) return null;
  return (
    <span className="inline-flex flex-wrap gap-1 ml-1.5">
      {kev > 0 && (
        <span title="Techniques with a curated CISA-KEV CVE" className={`text-[9px] font-mono px-1.5 py-0.5 rounded border whitespace-nowrap ${BADGE_CLS}`}>
          {kev} KEV
        </span>
      )}
      {wide > 0 && (
        <span title="Techniques used by ≥20 tracked threat groups" className={`text-[9px] font-mono px-1.5 py-0.5 rounded border whitespace-nowrap ${BADGE_CLS}`}>
          {wide} WIDE
        </span>
      )}
    </span>
  );
}

const tacticOrder = sharedTacticOrder;
const tacticColors = sharedTacticColors;

interface SectionData {
  section: string;
  ref_count: number;
  technique_count: number;
  refs: { ref_id: string; techniques: TechniqueRef[] }[];
}

interface TechRow {
  attack_id: string;
  technique_name: string | null;
  tactic: string | null;
  refs: string[];
}

interface Related {
  other_key: string;
  name: string;
  technique_overlap: number;
  region: string;
  tier: number;
}

interface ApiPayload {
  framework: {
    framework_key: string;
    name: string;
    version: string | null;
    source_org: string;
    upstream_url: string;
    region: string;
    tier: number;
    license: string | null;
    short_blurb: string | null;
    scf_controls: number | null;
    techniques_total: number | null;
    techniques_filtered: number | null;
  };
  article_count: number;
  sections: SectionData[];
  techniques: TechRow[];
  related: Related[];
}

const REGION_LABEL: Record<string, string> = {
  global: 'Global', eu: 'EU', us: 'US', uk: 'UK', apac: 'APAC', mena: 'MENA', americas: 'Americas',
};

export function ComplianceFrameworkDetail({ frameworkKey }: { frameworkKey: string }) {
  const [data, setData] = useState<ApiPayload | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [view, setView] = useState<'article' | 'technique'>('article');
  const [openSections, setOpenSections] = useState<Set<string>>(new Set());

  useEffect(() => {
    const ctrl = new AbortController();
    setData(null);
    setError(null);
    setOpenSections(new Set());
    fetch(`/api/v1/compliance/frameworks/${encodeURIComponent(frameworkKey)}`, { signal: ctrl.signal })
      .then((r) => (r.ok ? r.json() : Promise.reject(new Error(`HTTP ${r.status}`))))
      .then((d: ApiPayload) => {
        if (ctrl.signal.aborted) return;
        setData(d);
        // All sections start closed — let the user pick what to expand.
      })
      .catch((e) => { if (!ctrl.signal.aborted) setError(e.message); });
    return () => ctrl.abort();
  }, [frameworkKey]);

  const curated: ScfFrameworkEntry | undefined = useMemo(
    () => getFrameworkEntry(frameworkKey),
    [frameworkKey],
  );

  if (error) {
    return (
      <div className="p-6 max-w-5xl">
        <PageHeader title="Compliance" />
        <div className="rounded-md border border-red-500/30 bg-red-500/10 p-4 text-sm text-red-300">
          {error}
        </div>
      </div>
    );
  }

  if (!data) {
    return (
      <div className="p-6 max-w-5xl">
        <PageHeader title="Compliance" />
        <div className="text-sm text-[var(--text-secondary)]">Loading framework...</div>
      </div>
    );
  }

  const f = data.framework;

  return (
    <div className="p-6 max-w-6xl">
      <div className="mb-2 text-xs">
        <Link href="/compliance" className="text-[var(--accent-teal)] hover:underline">← Compliance</Link>
      </div>
      <PageHeader title={f.name} subtitle={f.short_blurb ?? undefined} />

      {/* Metadata block */}
      <div className="mb-6 rounded-md border border-[var(--border-color)] bg-[var(--surface-card)] p-4">
        <div className="grid grid-cols-1 md:grid-cols-[auto_1fr] gap-x-6 gap-y-1.5 text-sm">
          {f.version && (
            <>
              <dt className="text-[var(--text-secondary)] text-xs uppercase tracking-wider">Version</dt>
              <dd className="text-[var(--text-primary)]">{f.version}</dd>
            </>
          )}
          <dt className="text-[var(--text-secondary)] text-xs uppercase tracking-wider">Region</dt>
          <dd className="text-[var(--text-primary)]">{REGION_LABEL[f.region] ?? f.region}</dd>
          <dt className="text-[var(--text-secondary)] text-xs uppercase tracking-wider">Source</dt>
          <dd className="text-[var(--text-primary)]">{f.source_org}</dd>
          {curated?.effective && (
            <>
              <dt className="text-[var(--text-secondary)] text-xs uppercase tracking-wider">Effective</dt>
              <dd className="text-[var(--text-primary)]">{curated.effective}</dd>
            </>
          )}
          {curated?.scope && (
            <>
              <dt className="text-[var(--text-secondary)] text-xs uppercase tracking-wider">Scope</dt>
              <dd className="text-[var(--text-primary)]">{curated.scope}</dd>
            </>
          )}
          {curated?.enforcer && (
            <>
              <dt className="text-[var(--text-secondary)] text-xs uppercase tracking-wider">Enforcer</dt>
              <dd className="text-[var(--text-primary)]">{curated.enforcer}</dd>
            </>
          )}
          {f.license && (
            <>
              <dt className="text-[var(--text-secondary)] text-xs uppercase tracking-wider">License</dt>
              <dd className="text-[var(--text-primary)] text-xs">{f.license}</dd>
            </>
          )}
        </div>
        <div className="mt-4 pt-3 border-t border-[var(--border-color)] flex flex-wrap gap-4 text-sm">
          {/* Headline uses the same metric as the /compliance hub: techniques
              referenced by >=2 SCF controls. data.techniques.length (>=1 control)
              is shown as the wider "referenced" figure so the two views agree. */}
          <span title="ATT&CK techniques referenced by ≥2 SCF controls — the depth-of-coverage metric shown on the Compliance hub. Mappings reflect detection/monitoring intent, not verified mitigation.">
            <strong className="text-[var(--text-primary)]">{f.techniques_filtered ?? data.techniques.length}</strong> ATT&CK techniques
            <span className="text-[var(--text-secondary)] text-xs"> (≥2 controls; {data.techniques.length} referenced)</span>
          </span>
          {f.scf_controls !== null && (
            <>
              <span className="text-[var(--border-color)]">·</span>
              <span><strong className="text-[var(--text-primary)]">{f.scf_controls}</strong> SCF controls</span>
            </>
          )}
          <span className="text-[var(--border-color)]">·</span>
          <span><strong className="text-[var(--text-primary)]">{data.article_count}</strong> sections cited</span>
          <span className="ml-auto">
            <a href={f.upstream_url} target="_blank" rel="noopener noreferrer" className="text-[var(--accent-teal)] hover:underline">
              Read the upstream ↗
            </a>
          </span>
        </div>
      </div>

      {/* Heat badge legend — grid layout + expandable "How is this calculated?" */}
      <HeatLegend />


      {/* View toggle */}
      <div className="mb-4 flex items-center gap-2 text-xs">
        <span className="text-[var(--text-secondary)] mr-1">View:</span>
        <button
          type="button"
          onClick={() => setView('article')}
          className={`px-3 py-1 rounded-md border transition-colors ${
            view === 'article'
              ? 'border-[var(--accent-teal)] text-[var(--accent-teal)] bg-[var(--teal-faint)]'
              : 'border-[var(--border-color)] text-[var(--text-secondary)] hover:text-[var(--text-primary)]'
          }`}
        >
          By section
        </button>
        <button
          type="button"
          onClick={() => setView('technique')}
          className={`px-3 py-1 rounded-md border transition-colors ${
            view === 'technique'
              ? 'border-[var(--accent-teal)] text-[var(--accent-teal)] bg-[var(--teal-faint)]'
              : 'border-[var(--border-color)] text-[var(--text-secondary)] hover:text-[var(--text-primary)]'
          }`}
        >
          By technique
        </button>
      </div>

      {view === 'article' && (
        <div className="space-y-2">
          {data.sections.map((s) => {
            const isOpen = openSections.has(s.section);
            return (
              <div key={s.section} className="rounded-md border border-[var(--border-color)]">
                <button
                  type="button"
                  onClick={() => {
                    const next = new Set(openSections);
                    if (next.has(s.section)) next.delete(s.section); else next.add(s.section);
                    setOpenSections(next);
                  }}
                  className="w-full px-3 py-2 flex items-center gap-2 hover:bg-[var(--hover-overlay)] transition-colors"
                >
                  <svg className={`w-3 h-3 transition-transform ${isOpen ? 'rotate-90' : ''}`} fill="none" stroke="currentColor" strokeWidth={2.5} viewBox="0 0 24 24" aria-hidden="true">
                    <path strokeLinecap="round" strokeLinejoin="round" d="M9 5l7 7-7 7" />
                  </svg>
                  <span className="text-sm font-medium text-[var(--text-primary)]">{s.section}</span>
                  <span className="ml-auto text-xs text-[var(--text-secondary)]">
                    {s.technique_count} techniques · {s.ref_count} refs
                  </span>
                </button>
                {isOpen && (
                  <ul className="border-t border-[var(--border-color)] divide-y divide-[var(--border-color)]">
                    {s.refs.map((r) => (
                      <RefItem key={r.ref_id} refData={r} />
                    ))}
                  </ul>
                )}
              </div>
            );
          })}
        </div>
      )}

      {view === 'technique' && (
        <ul className="divide-y divide-[var(--border-color)] border border-[var(--border-color)] rounded-md">
          {data.techniques.map((t) => (
            <li key={t.attack_id} className="px-3 py-2 grid grid-cols-[6rem_1fr_auto] items-baseline gap-3">
              <Link href={techniqueHref(t.attack_id)} className="text-sm font-mono text-[var(--accent-teal)] hover:underline">
                {t.attack_id}
              </Link>
              <div className="min-w-0">
                <div className="text-sm text-[var(--text-primary)] truncate">{t.technique_name ?? '(unknown)'}</div>
                {t.tactic && (
                  <div className={`text-[11px] inline-flex items-center gap-1 ${tacticColors(t.tactic).text}`}>
                    <span className={`w-1.5 h-1.5 rounded-full ${tacticColors(t.tactic).dot}`} aria-hidden="true" />
                    {t.tactic}
                  </div>
                )}
              </div>
              <div className="text-xs text-[var(--text-secondary)] text-right truncate max-w-md">
                {t.refs.slice(0, 5).join(', ')}{t.refs.length > 5 ? ` +${t.refs.length - 5}` : ''}
              </div>
            </li>
          ))}
        </ul>
      )}

      {/* Related frameworks */}
      {data.related.length > 0 && (
        <div className="mt-8">
          <h2 className="text-[11px] font-bold uppercase tracking-widest text-[var(--accent-teal)] mb-3">Related frameworks (technique overlap)</h2>
          <ul className="divide-y divide-[var(--border-color)] border border-[var(--border-color)] rounded-md">
            {data.related.map((r) => (
              <li key={r.other_key}>
                <Link href={`/compliance/${r.other_key}`} className="flex items-center gap-3 px-3 py-2 text-sm hover:bg-[var(--hover-overlay)] transition-colors">
                  <span className="text-[var(--accent-teal)] truncate flex-1">{r.name}</span>
                  <span className="text-xs text-[var(--text-secondary)] font-mono">{r.technique_overlap} tech</span>
                </Link>
              </li>
            ))}
          </ul>
        </div>
      )}

      {/* Sources */}
      <div className="mt-8 text-xs text-[var(--text-secondary)]">
        <p>
          Sources:{' '}
          <a href={f.upstream_url} target="_blank" rel="noopener noreferrer" className="text-[var(--accent-teal)] hover:underline">
            upstream {f.source_org} document
          </a>
          {' · '}
          <a href="https://www.securecontrolsframework.com/" target="_blank" rel="noopener noreferrer" className="text-[var(--accent-teal)] hover:underline">
            Secure Controls Framework (SCF)
          </a>
        </p>
        <p className="mt-3 italic">
          Compliance mappings indicate framework intent, not verified technical mitigation.
          Combine with ATT&CK&apos;s own M-mitigations and detection strategies on each technique page.
        </p>
      </div>
    </div>
  );
}

/** Render the techniques under a ref_id, grouped by tactic (kill-chain order)
 *  with sub-techniques nested under their parent. */
function RefItem({ refData }: { refData: { ref_id: string; techniques: TechniqueRef[] } }) {
  // Dedup by attack_id first.
  const uniqTechs = new Map<string, TechniqueRef>();
  for (const t of refData.techniques) if (!uniqTechs.has(t.attack_id)) uniqTechs.set(t.attack_id, t);
  const techs = [...uniqTechs.values()];

  // Group by tactic.
  const byTactic = new Map<string, TechniqueRef[]>();
  for (const t of techs) {
    const k = t.tactic ?? '(unspecified)';
    if (!byTactic.has(k)) byTactic.set(k, []);
    byTactic.get(k)!.push(t);
  }
  const tacticEntries = [...byTactic.entries()].sort(
    (a, b) => tacticOrder(a[0] === '(unspecified)' ? null : a[0]) - tacticOrder(b[0] === '(unspecified)' ? null : b[0]),
  );

  return (
    <li className="px-3 py-2">
      <div className="flex items-baseline gap-2 mb-1.5">
        <span className="text-[11px] font-mono text-[var(--text-secondary)]">{refData.ref_id}</span>
        <span className="text-[10px] text-[var(--text-secondary)]">{techs.length} techniques</span>
      </div>
      <div className="space-y-2">
        {tacticEntries.map(([tactic, techsInTactic], idx) => (
          <TacticGroup
            key={tactic}
            tactic={tactic}
            techniques={techsInTactic}
            defaultOpen={idx === 0}
          />
        ))}
      </div>
    </li>
  );
}

/** A single tactic block: collapsible header + nested parent/sub-technique chips.
 *  Closed by default — sections are still dense even after grouping.
 *  `defaultOpen` is set true for the first tactic in a section. */
function TacticGroup({
  tactic,
  techniques,
  defaultOpen = false,
}: {
  tactic: string;
  techniques: TechniqueRef[];
  defaultOpen?: boolean;
}) {
  const [open, setOpen] = useState(defaultOpen);
  // Memoise the per-tactic grouping — without this each accordion toggle on the
  // outer section re-runs Map construction for every TacticGroup that isn't
  // open (and there can be 14 per section × many sections).
  const { byParent, standalone, parentInList } = useMemo(() => {
    const bp = new Map<string, TechniqueRef[]>();
    const sa: TechniqueRef[] = [];
    const pl = new Map<string, TechniqueRef>();
    for (const t of techniques) {
      if (t.parent_attack_id) {
        if (!bp.has(t.parent_attack_id)) bp.set(t.parent_attack_id, []);
        bp.get(t.parent_attack_id)!.push(t);
      } else {
        pl.set(t.attack_id, t);
      }
    }
    for (const [parentId, parentT] of pl.entries()) {
      if (!bp.has(parentId)) sa.push(parentT);
    }
    return { byParent: bp, standalone: sa, parentInList: pl };
  }, [techniques]);

  const colors = tacticColors(tactic);

  return (
    <div className={`rounded ${open ? colors.tint : ''}`}>
      <button
        type="button"
        onClick={() => setOpen((v) => !v)}
        className={`flex items-center gap-1.5 text-[10px] uppercase tracking-wider font-semibold mb-1 px-1.5 py-0.5 ${colors.text} hover:opacity-80 transition-opacity`}
      >
        <svg
          className={`w-2.5 h-2.5 transition-transform ${open ? 'rotate-90' : ''}`}
          fill="none" stroke="currentColor" strokeWidth={2.5} viewBox="0 0 24 24" aria-hidden="true"
        >
          <path strokeLinecap="round" strokeLinejoin="round" d="M9 5l7 7-7 7" />
        </svg>
        <span className={`w-1.5 h-1.5 rounded-full ${colors.dot}`} aria-hidden="true" />
        {tactic}
        <span className="text-[var(--text-secondary)] font-normal">({techniques.length})</span>
        <TacticHeatSummary techniques={techniques} />
      </button>
      {open && (
        <div className="pl-4 pb-2 pr-2 space-y-1.5">
          {[...byParent.entries()]
            .sort((a, b) => a[0].localeCompare(b[0]))
            .map(([parentId, subs]) => (
              <ParentBlock
                key={parentId}
                parentId={parentId}
                parent={parentInList.get(parentId) ?? null}
                parentName={subs.find((s) => s.parent_name)?.parent_name ?? null}
                subs={subs.sort((a, b) => a.attack_id.localeCompare(b.attack_id))}
              />
            ))}
          {standalone
            .sort((a, b) => a.attack_id.localeCompare(b.attack_id))
            .map((t) => (
              <TechniqueChip key={t.attack_id} t={t} rowLayout />
            ))}
        </div>
      )}
    </div>
  );
}

/** Parent technique header + indented subs. */
function ParentBlock({
  parentId,
  parent,
  parentName,
  subs,
}: {
  parentId: string;
  parent: TechniqueRef | null;
  parentName: string | null;
  subs: TechniqueRef[];
}) {
  const displayName = parent?.technique_name ?? parentName ?? null;
  return (
    <div className="w-full">
      <div className="flex items-baseline justify-between gap-2">
        <div className="flex items-baseline gap-1.5 min-w-0">
          <Link href={techniqueHref(parentId)} className="text-xs text-[var(--accent-teal)] hover:underline truncate">
            <span className="font-mono">{parentId}</span>
            {displayName && <span className="text-[var(--text-primary)] ml-1">{displayName}</span>}
          </Link>
          <span className="text-[10px] text-[var(--text-secondary)] shrink-0">({subs.length} sub{subs.length === 1 ? '' : 's'})</span>
        </div>
        <span className="shrink-0">
          {parent && <HeatBadges t={parent} />}
        </span>
      </div>
      <ul className="pl-5 mt-1 space-y-0.5 border-l border-[var(--border-color)] ml-2">
        {subs.map((t) => (
          <li key={t.attack_id} className="pl-2">
            <TechniqueChip t={t} dim rowLayout />
          </li>
        ))}
      </ul>
    </div>
  );
}

function TechniqueChip({ t, dim, rowLayout }: { t: TechniqueRef; dim?: boolean; rowLayout?: boolean }) {
  // Two modes:
  //   rowLayout (used for sub-technique list items + standalone vertical rows):
  //     full-width flex with the link on the left, badges right-aligned —
  //     gives a tidy column of aligned badges.
  //   chip (default, used for standalone chips inside a tactic-group wrap):
  //     inline-flex, badges sit immediately after the name.
  if (rowLayout) {
    return (
      <div className="flex items-baseline justify-between gap-2 w-full">
        <Link
          href={techniqueHref(t.attack_id)}
          className={`text-xs hover:underline truncate min-w-0 ${dim ? 'text-[var(--text-secondary)] hover:text-[var(--accent-teal)]' : 'text-[var(--accent-teal)]'}`}
        >
          <span className="font-mono">{t.attack_id}</span>
          {t.technique_name && <span className="text-[var(--text-secondary)] ml-1">{t.technique_name}</span>}
        </Link>
        <span className="shrink-0">
          <HeatBadges t={t} />
        </span>
      </div>
    );
  }
  return (
    <span className="inline-flex items-baseline gap-1 max-w-full">
      <Link
        href={techniqueHref(t.attack_id)}
        className={`text-xs hover:underline truncate max-w-[22rem] ${dim ? 'text-[var(--text-secondary)] hover:text-[var(--accent-teal)]' : 'text-[var(--accent-teal)]'}`}
      >
        <span className="font-mono">{t.attack_id}</span>
        {t.technique_name && <span className="text-[var(--text-secondary)] ml-1">{t.technique_name}</span>}
      </Link>
      <HeatBadges t={t} />
    </span>
  );
}
