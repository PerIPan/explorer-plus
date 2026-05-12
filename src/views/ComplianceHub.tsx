'use client';

import { useEffect, useMemo, useState } from 'react';
import Link from 'next/link';
import { PageHeader } from '../components/layout/PageHeader';

interface Framework {
  framework_key: string;
  name: string;
  version: string | null;
  source_org: string;
  upstream_url: string;
  region: string;
  tier: number;
  license: string | null;
  short_blurb: string | null;
  scf_controls: number;
  techniques_total: number;
  techniques_filtered: number;
}

interface HubMeta {
  framework_count: number;
  control_count: number;
  mapping_count: number;
  unresolved_count: number;
  last_run_at: string | null;
  scf_version: string | null;
}

interface ApiResponse {
  meta: HubMeta;
  frameworks: Framework[];
}

// Dot color encodes license class — fast at-a-glance legality cue.
function licenseClass(license: string | null): 'public' | 'permissive' | 'cc' | 'commercial' {
  if (!license) return 'commercial';
  const l = license.toLowerCase();
  if (l.includes('public domain')) return 'public';
  if (l.includes('cc by')) return 'cc';
  if (l.includes('eu official') || l.includes('open government')) return 'public';
  if (l.includes('apache') || l.includes('mit') || l.includes('free with') || l.includes('open') || l.includes('permissive')) return 'permissive';
  return 'commercial';
}

function licenseDotColor(license: string | null): string {
  switch (licenseClass(license)) {
    case 'public': return 'bg-emerald-500';
    case 'permissive': return 'bg-teal-500';
    case 'cc': return 'bg-amber-500';
    case 'commercial': return 'bg-slate-400';
  }
}

const REGION_LABEL: Record<string, string> = {
  global: 'Global',
  eu: 'EU',
  us: 'US',
  uk: 'UK',
  apac: 'APAC',
  mena: 'MENA',
  americas: 'Americas',
};

// Cross-links to dedicated /frameworks/* pages we've already built.
// These are NOT SCF-backed — they live outside the SCF ingest.
const ALSO_ON_SITE: { label: string; href: string; note: string }[] = [
  { label: 'EU CRA', href: '/frameworks/cra', note: 'EU Cyber Resilience Act reference page (no SCF mappings yet — pending harmonised standards).' },
  { label: 'NIST CSF v2', href: '/frameworks/csf', note: 'Full subcategory → ATT&CK technique browser.' },
  { label: 'NIST 800-53 r5', href: '/frameworks/nist', note: 'Control catalog mapped to techniques.' },
  { label: 'OWASP Top 10', href: '/frameworks/owasp', note: 'Web, ML, and LLM security risks via CWE.' },
  { label: 'OWASP AI Exchange', href: '/frameworks/owasp-ai', note: 'AI/ML threats, controls, and framework alignments.' },
  { label: 'Atomic Red Team', href: '/frameworks/atomic', note: 'Red-team validation tests mapped to techniques.' },
];

// Framework keys with an on-site reference page that should be linked from the
// hub row when SCF coverage is empty (so users don't bounce off a blank
// /compliance/<key> detail page).
const FALLBACK_REFERENCE: Record<string, string> = {
  'eu-cra': '/frameworks/cra',
};

export function ComplianceHub() {
  const [data, setData] = useState<ApiResponse | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [includeAll, setIncludeAll] = useState(false);
  const [regionFilter, setRegionFilter] = useState<string | 'all'>('all');
  const [searchQuery, setSearchQuery] = useState('');

  useEffect(() => {
    const url = `/api/v1/compliance/frameworks${includeAll ? '?include_all=1' : ''}`;
    const ctrl = new AbortController();
    setData(null);
    setError(null);
    fetch(url, { signal: ctrl.signal })
      .then((r) => (r.ok ? r.json() : Promise.reject(new Error(`HTTP ${r.status}`))))
      .then((d: ApiResponse) => { if (!ctrl.signal.aborted) setData(d); })
      .catch((e) => { if (!ctrl.signal.aborted) setError(e.message); });
    return () => ctrl.abort();
  }, [includeAll]);

  const filtered = useMemo(() => {
    if (!data) return [];
    let rows = data.frameworks;
    if (regionFilter !== 'all') rows = rows.filter((r) => r.region === regionFilter);
    if (searchQuery.trim()) {
      const q = searchQuery.trim().toLowerCase();
      rows = rows.filter(
        (r) => r.name.toLowerCase().includes(q) || r.source_org.toLowerCase().includes(q) || r.framework_key.includes(q),
      );
    }
    return rows;
  }, [data, regionFilter, searchQuery]);

  // Section split — three Tier-1/Tier-2 buckets + Tier 3 long-tail.
  const sections = useMemo(() => {
    const tier1Global = filtered.filter((r) => r.tier === 1 && r.region === 'global');
    const tier1Eu = filtered.filter((r) => r.tier === 1 && r.region === 'eu');
    const tier1Us = filtered.filter((r) => r.tier === 1 && r.region === 'us');
    const tier2 = filtered.filter((r) => r.tier === 2);
    const tier3 = filtered.filter((r) => r.tier === 3);
    return { tier1Global, tier1Eu, tier1Us, tier2, tier3 };
  }, [filtered]);

  if (error) {
    return (
      <div className="p-6 max-w-5xl">
        <PageHeader title="Compliance" />
        <div className="rounded-md border border-red-500/30 bg-red-500/10 p-4 text-sm text-red-300">
          Failed to load compliance frameworks: {error}
        </div>
      </div>
    );
  }

  if (!data) {
    return (
      <div className="p-6 max-w-5xl">
        <PageHeader title="Compliance" />
        <div className="text-sm text-[var(--text-secondary)]">Loading frameworks...</div>
      </div>
    );
  }

  const totalTechReferenced = data.meta.mapping_count;

  return (
    <div className="p-6 max-w-6xl">
      <PageHeader
        title="Compliance"
        subtitle="Regulatory and audit frameworks bridged to MITRE ATT&CK Enterprise via the Secure Controls Framework (SCF). ATLAS, ICS, and Mobile have their own compliance ecosystems and are not covered here."
      />

      {/* Meta strip */}
      <div className="mb-6 flex flex-wrap gap-3 text-xs text-[var(--text-secondary)]">
        <span><strong className="text-[var(--text-primary)]">{data.meta.framework_count}</strong> frameworks tracked</span>
        <span className="text-[var(--border-color)]">·</span>
        <span><strong className="text-[var(--text-primary)]">{data.meta.control_count.toLocaleString()}</strong> SCF controls</span>
        <span className="text-[var(--border-color)]">·</span>
        <span><strong className="text-[var(--text-primary)]">{totalTechReferenced.toLocaleString()}</strong> ATT&CK technique references</span>
        {data.meta.unresolved_count > 0 && (
          <>
            <span className="text-[var(--border-color)]">·</span>
            <span className="text-amber-400" title="ATT&CK IDs referenced by SCF that don't exist in our current v19 dataset (typically revoked or renamed in newer ATT&CK release).">
              {data.meta.unresolved_count} unresolved
            </span>
          </>
        )}
        {data.meta.scf_version && (
          <>
            <span className="text-[var(--border-color)]">·</span>
            <span>SCF {data.meta.scf_version}</span>
          </>
        )}
      </div>

      {/* Filter bar */}
      <div className="mb-5 flex flex-wrap items-center gap-2 text-xs">
        <label className="text-[var(--text-secondary)] mr-1">Region:</label>
        {['all', 'global', 'eu', 'us', 'uk', 'apac'].map((r) => (
          <button
            key={r}
            type="button"
            onClick={() => setRegionFilter(r as typeof regionFilter)}
            className={`px-2.5 py-1 rounded-md border transition-colors ${
              regionFilter === r
                ? 'border-[var(--accent-teal)] text-[var(--accent-teal)] bg-[var(--teal-faint)]'
                : 'border-[var(--border-color)] text-[var(--text-secondary)] hover:text-[var(--text-primary)]'
            }`}
          >
            {r === 'all' ? 'All' : REGION_LABEL[r] ?? r}
          </button>
        ))}
        <span className="mx-2 text-[var(--border-color)]">|</span>
        <input
          type="text"
          placeholder="Search frameworks..."
          value={searchQuery}
          onChange={(e) => setSearchQuery(e.target.value)}
          className="px-2.5 py-1 rounded-md border border-[var(--border-color)] bg-transparent text-[var(--text-primary)] placeholder:text-[var(--text-secondary)] focus:outline-none focus:border-[var(--accent-teal)] text-xs w-56"
        />
        <div className="ml-auto flex items-center gap-2">
          <label className="text-[var(--text-secondary)]">
            <input
              type="checkbox"
              checked={includeAll}
              onChange={(e) => setIncludeAll(e.target.checked)}
              className="mr-1.5 align-middle"
            />
            Show all ({data.meta.framework_count})
          </label>
        </div>
      </div>

      {/* Inline tooltip explaining the filtered count metric */}
      <p className="mb-4 text-[11px] text-[var(--text-secondary)] italic">
        <strong>Coverage:</strong> first number is filtered count — ATT&CK techniques referenced by <em>≥2</em> SCF controls in this framework, signalling depth of coverage. Second number is total SCF controls mapped to that framework.
      </p>

      {/* Sections — closed by default; the hub is dense, let users open what matters. */}
      <Section title="Global — Tier 1" rows={sections.tier1Global} defaultOpen={false} />
      <Section title="EU regulatory — Tier 1" rows={sections.tier1Eu} defaultOpen={false} />
      <Section title="US regulatory — Tier 1" rows={sections.tier1Us} defaultOpen={false} />
      <Section title="Sectoral & regional — Tier 2" rows={sections.tier2} defaultOpen={false} />
      {includeAll && (
        <Section title={`All other — Tier 3 (${sections.tier3.length})`} rows={sections.tier3} defaultOpen={false} />
      )}

      {/* Also on this site */}
      <div className="mt-8 pt-5 border-t border-[var(--border-color)]">
        <h2 className="text-[11px] font-bold uppercase tracking-widest text-[var(--accent-teal)] mb-3">Also on this site</h2>
        <ul className="space-y-1.5 text-sm">
          {ALSO_ON_SITE.map((l) => (
            <li key={l.href} className="flex items-baseline gap-2">
              <Link href={l.href} className="text-[var(--accent-teal)] hover:underline">{l.label}</Link>
              <span className="text-[var(--text-secondary)] text-xs">{l.note}</span>
            </li>
          ))}
        </ul>
      </div>

      {/* SCF attribution */}
      <p className="mt-8 pt-4 border-t border-[var(--border-color)] text-[10px] text-[var(--text-secondary)] italic">
        Powered by the{' '}
        <a href="https://www.securecontrolsframework.com/" target="_blank" rel="noopener noreferrer" className="text-[var(--accent-teal)] hover:underline">
          Secure Controls Framework (SCF)
        </a>
        {' '}— licensed{' '}
        <a href="https://creativecommons.org/licenses/by/4.0/" target="_blank" rel="noopener noreferrer" className="text-[var(--accent-teal)] hover:underline">CC BY 4.0</a>.
        {' '}Compliance mappings indicate framework intent, not verified technical mitigation.
      </p>
    </div>
  );
}

function Section({ title, rows, defaultOpen }: { title: string; rows: Framework[]; defaultOpen: boolean }) {
  const [open, setOpen] = useState(defaultOpen);
  if (rows.length === 0) return null;

  return (
    <section className="mb-6">
      <button
        type="button"
        onClick={() => setOpen((v) => !v)}
        className="flex items-center gap-2 text-[11px] font-bold uppercase tracking-widest text-[var(--accent-teal)] mb-2 hover:text-[var(--accent-teal-light)]"
      >
        <svg
          className={`w-3 h-3 transition-transform ${open ? 'rotate-90' : ''}`}
          fill="none" stroke="currentColor" strokeWidth={2.5} viewBox="0 0 24 24" aria-hidden="true"
        >
          <path strokeLinecap="round" strokeLinejoin="round" d="M9 5l7 7-7 7" />
        </svg>
        {title} <span className="text-[var(--text-secondary)] font-normal">({rows.length})</span>
      </button>
      {open && (
        <ul className="divide-y divide-[var(--border-color)] border border-[var(--border-color)] rounded-md overflow-hidden bg-[var(--surface-card)]">
          {rows.map((r) => (
            <Row key={r.framework_key} row={r} />
          ))}
        </ul>
      )}
    </section>
  );
}

function Row({ row }: { row: Framework }) {
  const hasCoverage = row.scf_controls > 0;
  const techCount = hasCoverage ? `${row.techniques_filtered} tech` : 'not yet in SCF';
  const rawTitle = hasCoverage
    ? `${row.techniques_total} total techniques · ${row.scf_controls} SCF controls`
    : 'Framework tracked but the current SCF release has no ATT&CK cross-references for it yet.';
  // When SCF has no data, route to the on-site reference page if we have one;
  // the /compliance/<key> detail page would render empty.
  const href = hasCoverage
    ? `/compliance/${row.framework_key}`
    : (FALLBACK_REFERENCE[row.framework_key] ?? `/compliance/${row.framework_key}`);
  return (
    <li className={hasCoverage ? '' : 'opacity-70'}>
      <Link
        href={href}
        className="grid grid-cols-[auto_1fr_auto_auto_auto] items-center gap-3 px-3 py-2.5 hover:bg-[var(--hover-overlay)] transition-colors"
      >
        <span className={`w-2 h-2 rounded-full ${licenseDotColor(row.license)}`} aria-hidden="true" />
        <div className="min-w-0">
          <div className="text-sm font-medium text-[var(--text-primary)] truncate">
            {row.name}
            {row.version && <span className="ml-1.5 text-[var(--text-secondary)] text-xs">{row.version}</span>}
          </div>
          <div className="text-[11px] text-[var(--text-secondary)] truncate">
            {row.source_org}{row.short_blurb ? ` · ${row.short_blurb}` : ''}
          </div>
        </div>
        <span className="text-[10px] uppercase tracking-wider px-1.5 py-0.5 rounded border border-[var(--border-color)] text-[var(--text-secondary)]">
          {REGION_LABEL[row.region] ?? row.region}
        </span>
        <span className="text-xs font-mono text-[var(--text-secondary)] tabular-nums" title={rawTitle}>
          {hasCoverage ? (
            <>
              <span className="text-[var(--text-primary)]">{techCount}</span>
              <span className="mx-1 text-[var(--border-color)]">·</span>
              <span>{row.scf_controls} SCF</span>
            </>
          ) : (
            <span className="text-[var(--text-secondary)] italic">{techCount}</span>
          )}
        </span>
        <span className="text-[10px] uppercase tracking-wider text-[var(--text-secondary)] text-right min-w-[6rem]">
          {row.license ?? 'unknown'}
        </span>
      </Link>
    </li>
  );
}
