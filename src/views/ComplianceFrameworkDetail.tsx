'use client';

import { useEffect, useMemo, useState } from 'react';
import Link from 'next/link';
import { PageHeader } from '../components/layout/PageHeader';
import {
  getFrameworkEntry,
  type ScfFrameworkEntry,
} from '../lib/scf-framework-registry';

interface TechniqueRef {
  attack_id: string;
  technique_name: string | null;
  tactic: string | null;
  parent_attack_id: string | null;
  parent_name: string | null;
  scf_id: string;
  cve_count: number;
  has_kev: boolean;
  max_epss: number | null;
  ghsa_count: number;
  group_count: number;
}

/** Tiny compact chip — used for heat badges next to a technique. */
function HeatBadges({ t }: { t: TechniqueRef }) {
  const badges: { label: string; cls: string; title: string }[] = [];
  if (t.has_kev) {
    badges.push({
      label: 'KEV',
      cls: 'bg-red-500/20 text-red-300 border-red-500/40',
      title: 'At least one linked CVE is in CISA Known Exploited Vulnerabilities',
    });
  }
  if (t.max_epss != null && t.max_epss >= 0.5) {
    badges.push({
      label: `EPSS ${t.max_epss.toFixed(2)}`,
      cls: 'bg-orange-500/20 text-orange-300 border-orange-500/40',
      title: 'Maximum EPSS exploit-probability across linked CVEs (≥0.5 = exploit predicted within 30 days)',
    });
  }
  if (t.cve_count >= 100) {
    badges.push({
      label: `CVE ${t.cve_count.toLocaleString()}`,
      cls: 'bg-pink-500/15 text-pink-300 border-pink-500/30',
      title: `Linked CVEs (via CWE → CAPEC → ATT&CK)`,
    });
  }
  if (t.ghsa_count >= 100) {
    badges.push({
      label: `GHSA ${t.ghsa_count.toLocaleString()}`,
      cls: 'bg-purple-500/15 text-purple-300 border-purple-500/30',
      title: `Linked GitHub Security Advisories (OSS package angle)`,
    });
  }
  if (t.group_count >= 20) {
    badges.push({
      label: `WIDE ${t.group_count}`,
      cls: 'bg-amber-500/15 text-amber-300 border-amber-500/40',
      title: 'Number of tracked threat groups using this technique',
    });
  } else if (t.group_count >= 5) {
    badges.push({
      label: `${t.group_count} groups`,
      cls: 'bg-slate-500/15 text-[var(--text-secondary)] border-[var(--border-color)]',
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
          className={`text-[9px] font-mono px-1 py-0.5 rounded border ${b.cls}`}
        >
          {b.label}
        </span>
      ))}
    </span>
  );
}

// Enterprise ATT&CK kill-chain order. Anything not in this list (ICS/Mobile
// tactics, or null when technique→tactic join missed) sorts at the end.
const TACTIC_ORDER: Record<string, number> = {
  'Reconnaissance':        1,
  'Resource Development':  2,
  'Initial Access':        3,
  'Execution':             4,
  'Persistence':           5,
  'Privilege Escalation':  6,
  'Defense Evasion':       7,
  'Credential Access':     8,
  'Discovery':             9,
  'Lateral Movement':     10,
  'Collection':           11,
  'Command and Control':  12,
  'Exfiltration':         13,
  'Impact':               14,
};

function tacticOrder(name: string | null): number {
  if (!name) return 99;
  return TACTIC_ORDER[name] ?? 50;
}

// Tactic signature colors. Listed as literal class strings so Tailwind's
// content scanner picks them up. Each tactic gets a dot + tinted header.
const TACTIC_COLOR_CLASS: Record<string, { text: string; dot: string; tint: string }> = {
  'Reconnaissance':        { text: 'text-sky-400',    dot: 'bg-sky-400',    tint: 'bg-sky-400/10' },
  'Resource Development':  { text: 'text-teal-400',   dot: 'bg-teal-400',   tint: 'bg-teal-400/10' },
  'Initial Access':        { text: 'text-blue-500',   dot: 'bg-blue-500',   tint: 'bg-blue-500/10' },
  'Execution':             { text: 'text-purple-500', dot: 'bg-purple-500', tint: 'bg-purple-500/10' },
  'Persistence':           { text: 'text-indigo-500', dot: 'bg-indigo-500', tint: 'bg-indigo-500/10' },
  'Privilege Escalation':  { text: 'text-violet-500', dot: 'bg-violet-500', tint: 'bg-violet-500/10' },
  'Defense Evasion':       { text: 'text-slate-400',  dot: 'bg-slate-400',  tint: 'bg-slate-400/10' },
  'Credential Access':     { text: 'text-yellow-500', dot: 'bg-yellow-500', tint: 'bg-yellow-500/10' },
  'Discovery':             { text: 'text-lime-500',   dot: 'bg-lime-500',   tint: 'bg-lime-500/10' },
  'Lateral Movement':      { text: 'text-green-500',  dot: 'bg-green-500',  tint: 'bg-green-500/10' },
  'Collection':            { text: 'text-amber-500',  dot: 'bg-amber-500',  tint: 'bg-amber-500/10' },
  'Command and Control':   { text: 'text-orange-500', dot: 'bg-orange-500', tint: 'bg-orange-500/10' },
  'Exfiltration':          { text: 'text-red-400',    dot: 'bg-red-400',    tint: 'bg-red-400/10' },
  'Impact':                { text: 'text-rose-500',   dot: 'bg-rose-500',   tint: 'bg-rose-500/10' },
};
const TACTIC_COLOR_FALLBACK = { text: 'text-[var(--text-secondary)]', dot: 'bg-[var(--text-secondary)]', tint: 'bg-[var(--hover-overlay)]' };
function tacticColors(name: string) {
  return TACTIC_COLOR_CLASS[name] ?? TACTIC_COLOR_FALLBACK;
}

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
          <span><strong className="text-[var(--text-primary)]">{data.techniques.length}</strong> ATT&CK techniques</span>
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
              <Link href={`/techniques/${t.attack_id}`} className="text-sm font-mono text-[var(--accent-teal)] hover:underline">
                {t.attack_id}
              </Link>
              <div className="min-w-0">
                <div className="text-sm text-[var(--text-primary)] truncate">{t.technique_name ?? '(unknown)'}</div>
                {t.tactic && <div className="text-[11px] text-[var(--text-secondary)]">{t.tactic}</div>}
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
        {tacticEntries.map(([tactic, techsInTactic]) => (
          <TacticGroup key={tactic} tactic={tactic} techniques={techsInTactic} />
        ))}
      </div>
    </li>
  );
}

/** A single tactic block: collapsible header + nested parent/sub-technique chips.
 *  Closed by default — sections are still dense even after grouping. */
function TacticGroup({ tactic, techniques }: { tactic: string; techniques: TechniqueRef[] }) {
  const [open, setOpen] = useState(false);
  const byParent = new Map<string, TechniqueRef[]>();
  const standalone: TechniqueRef[] = [];
  const parentInList = new Map<string, TechniqueRef>();

  for (const t of techniques) {
    if (t.parent_attack_id) {
      if (!byParent.has(t.parent_attack_id)) byParent.set(t.parent_attack_id, []);
      byParent.get(t.parent_attack_id)!.push(t);
    } else {
      parentInList.set(t.attack_id, t);
    }
  }
  for (const [parentId, parentT] of parentInList.entries()) {
    if (!byParent.has(parentId)) standalone.push(parentT);
  }

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
      </button>
      {open && (
        <div className="flex flex-wrap gap-x-3 gap-y-1.5 pl-4 pb-2">
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
              <TechniqueChip key={t.attack_id} t={t} />
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
      <div className="inline-flex items-baseline gap-1.5">
        <Link href={`/techniques/${parentId}`} className="text-xs text-[var(--accent-teal)] hover:underline">
          <span className="font-mono">{parentId}</span>
          {displayName && <span className="text-[var(--text-secondary)] ml-1">{displayName}</span>}
        </Link>
        <span className="text-[10px] text-[var(--text-secondary)]">({subs.length} sub{subs.length === 1 ? '' : 's'})</span>
        {parent && <HeatBadges t={parent} />}
      </div>
      <div className="flex flex-wrap gap-x-3 gap-y-1 pl-4 mt-1">
        {subs.map((t) => (
          <TechniqueChip key={t.attack_id} t={t} dim />
        ))}
      </div>
    </div>
  );
}

function TechniqueChip({ t, dim }: { t: TechniqueRef; dim?: boolean }) {
  return (
    <span className="inline-flex items-baseline gap-1 max-w-full">
      <Link
        href={`/techniques/${t.attack_id}`}
        className={`text-xs hover:underline truncate max-w-[22rem] ${dim ? 'text-[var(--text-secondary)] hover:text-[var(--accent-teal)]' : 'text-[var(--accent-teal)]'}`}
      >
        <span className="font-mono">{t.attack_id}</span>
        {t.technique_name && <span className="text-[var(--text-secondary)] ml-1">{t.technique_name}</span>}
      </Link>
      <HeatBadges t={t} />
    </span>
  );
}
