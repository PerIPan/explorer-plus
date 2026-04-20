'use client';
import { useMemo, useState } from 'react';
import Link from 'next/link';
import { useSearchParams } from 'next/navigation';
import { useUpdateParams } from '../hooks/useUpdateParams';
import { useEcosystems } from '../hooks/useApi';
import { PageHeader } from '../components/layout/PageHeader';
import { DiamondLoader } from '../components/shared/FoldingDiamond';
import { Badge } from '../components/shared/Badge';
import { CATEGORY_LABELS, type EcosystemCategory } from '../lib/ecosystems';
import type { EcosystemListRow } from '../lib/types';

type View = 'grid' | 'table';

const CATEGORY_ORDER: EcosystemCategory[] = [
  'package-manager',
  'os-distro',
  'container-distro',
  'kernel-misc',
];

const CATEGORY_BADGE_VARIANT: Record<EcosystemCategory, 'teal' | 'orange' | 'purple' | 'yellow'> = {
  'package-manager': 'teal',
  'os-distro': 'orange',
  'container-distro': 'purple',
  'kernel-misc': 'yellow',
};

const SEVERITY_COLOR: Record<string, string> = {
  CRITICAL: 'bg-[var(--accent-pink)]',
  HIGH: 'bg-[var(--accent-orange)]',
  MEDIUM: 'bg-[var(--accent-yellow)]',
  LOW: 'bg-[var(--accent-blue)]',
  UNRATED: 'bg-[var(--border-color)]',
};

const SEVERITY_ORDER: Array<keyof EcosystemListRow['severityBreakdown']> = [
  'CRITICAL',
  'HIGH',
  'MEDIUM',
  'LOW',
  'UNRATED',
];

function SeverityBar({ breakdown }: { breakdown: EcosystemListRow['severityBreakdown'] }) {
  const total = SEVERITY_ORDER.reduce((s, k) => s + breakdown[k], 0);
  if (total === 0) return null;
  const unratedPct = Math.round((breakdown.UNRATED / total) * 100);
  const tooltip = unratedPct > 20
    ? `${unratedPct}% unrated — distros like Chainguard strip CVSS on rebuild advisories`
    : 'Severity distribution';
  return (
    <div title={tooltip}>
      <div className="flex w-full h-2 rounded overflow-hidden">
        {SEVERITY_ORDER.map((k) => {
          const pct = (breakdown[k] / total) * 100;
          if (pct === 0) return null;
          return (
            <div
              key={k}
              className={SEVERITY_COLOR[k]}
              style={{ width: `${pct}%` }}
              title={`${k}: ${breakdown[k].toLocaleString()}`}
            />
          );
        })}
      </div>
      <div className="flex gap-2 text-[10px] mt-1 text-[var(--text-secondary)]">
        {breakdown.CRITICAL > 0 && <span className="text-[var(--accent-pink)]">C {breakdown.CRITICAL}</span>}
        {breakdown.HIGH > 0 && <span className="text-[var(--accent-orange)]">H {breakdown.HIGH}</span>}
        {breakdown.MEDIUM > 0 && <span className="text-[var(--accent-yellow)]">M {breakdown.MEDIUM}</span>}
        {breakdown.LOW > 0 && <span className="text-[var(--accent-blue)]">L {breakdown.LOW}</span>}
        {unratedPct > 5 && <span>· {unratedPct}% unrated</span>}
      </div>
    </div>
  );
}

function EcosystemCard({ row }: { row: EcosystemListRow }) {
  return (
    <Link
      href={`/ecosystems/${row.slug}`}
      className="block bg-[var(--surface-card)] border border-[var(--border-color)] rounded-md px-4 py-3 space-y-2 hover:border-[var(--accent-teal)] transition-colors"
    >
      <div className="flex items-start justify-between gap-2">
        <div className="font-semibold text-sm text-[var(--text-primary)] truncate">
          {row.displayName}
        </div>
        <Badge label={CATEGORY_LABELS[row.category].toLowerCase()} variant={CATEGORY_BADGE_VARIANT[row.category]} />
      </div>
      <div className="flex gap-3 text-xs">
        <span className="text-[var(--text-secondary)]">
          Total: <span className="font-mono text-[var(--text-primary)]">{row.totalAdvisories.toLocaleString()}</span>
        </span>
        <span className="text-[var(--text-secondary)]">
          14d: <span className="font-mono text-[var(--accent-teal)]">{row.last14dCount.toLocaleString()}</span>
        </span>
      </div>
      <SeverityBar breakdown={row.severityBreakdown} />
      {row.topPackages.length > 0 && (
        <div className="pt-1 border-t border-[var(--border-faint)]">
          <div className="text-[10px] uppercase tracking-wider text-[var(--text-secondary)] mb-1">Top packages</div>
          <ul className="space-y-0.5">
            {row.topPackages.map((p) => (
              <li key={p.name} className="text-xs text-[var(--text-primary)] truncate font-mono">
                {p.name}
                <span className="text-[var(--text-secondary)] font-sans"> · {p.advisoryCount.toLocaleString()}</span>
              </li>
            ))}
          </ul>
        </div>
      )}
    </Link>
  );
}

function CategorySection({
  category,
  rows,
  open,
  onToggle,
}: {
  category: EcosystemCategory;
  rows: EcosystemListRow[];
  open: boolean;
  onToggle: () => void;
}) {
  return (
    <section>
      <button
        type="button"
        onClick={onToggle}
        className="flex items-center gap-2 w-full text-left py-2 border-b border-[var(--border-faint)]"
      >
        <svg
          className={`w-3 h-3 transition-transform ${open ? 'rotate-90' : ''} text-[var(--accent-teal)]`}
          fill="none" stroke="currentColor" strokeWidth={2.5} viewBox="0 0 24 24"
        >
          <path strokeLinecap="round" strokeLinejoin="round" d="M9 5l7 7-7 7" />
        </svg>
        <span className="text-xs font-bold uppercase tracking-wider text-[var(--accent-teal)]">
          {CATEGORY_LABELS[category]}
        </span>
        <span className="text-[10px] text-[var(--text-secondary)]">{rows.length} ecosystems</span>
      </button>
      {open && (
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-3 pt-3">
          {rows.map((r) => <EcosystemCard key={r.slug} row={r} />)}
          {rows.length === 0 && (
            <p className="text-sm text-[var(--text-secondary)] col-span-full py-4 italic">
              No ecosystems in this category yet.
            </p>
          )}
        </div>
      )}
    </section>
  );
}

function TableView({ rows }: { rows: EcosystemListRow[] }) {
  const [sortKey, setSortKey] = useState<'last14d' | 'total' | 'critical' | 'name'>('last14d');
  const sorted = useMemo(() => {
    const copy = [...rows];
    if (sortKey === 'name') copy.sort((a, b) => a.displayName.localeCompare(b.displayName));
    else if (sortKey === 'total') copy.sort((a, b) => b.totalAdvisories - a.totalAdvisories);
    else if (sortKey === 'critical') copy.sort((a, b) => b.severityBreakdown.CRITICAL - a.severityBreakdown.CRITICAL);
    else copy.sort((a, b) => b.last14dCount - a.last14dCount);
    return copy;
  }, [rows, sortKey]);

  return (
    <div className="overflow-x-auto rounded-md border border-[var(--border-color)]">
      <table className="w-full text-sm">
        <thead className="bg-[var(--surface-deep)] text-left text-xs uppercase tracking-wider text-[var(--text-secondary)]">
          <tr>
            <th className="px-3 py-2 cursor-pointer" onClick={() => setSortKey('name')}>Ecosystem</th>
            <th className="px-3 py-2">Type</th>
            <th className="px-3 py-2 text-right cursor-pointer" onClick={() => setSortKey('total')}>Total</th>
            <th className="px-3 py-2 text-right cursor-pointer" onClick={() => setSortKey('last14d')}>Last 14d</th>
            <th className="px-3 py-2 text-right cursor-pointer" onClick={() => setSortKey('critical')}>CRITICAL</th>
            <th className="px-3 py-2">Top package</th>
          </tr>
        </thead>
        <tbody className="divide-y divide-[var(--border-color)]">
          {sorted.map((r) => (
            <tr
              key={r.slug}
              className="bg-[var(--surface-card)] hover:bg-[var(--hover-overlay)] cursor-pointer"
              onClick={() => { window.location.href = `/ecosystems/${r.slug}`; }}
            >
              <td className="px-3 py-2 font-medium text-[var(--text-primary)]">{r.displayName}</td>
              <td className="px-3 py-2">
                <Badge label={CATEGORY_LABELS[r.category].toLowerCase()} variant={CATEGORY_BADGE_VARIANT[r.category]} />
              </td>
              <td className="px-3 py-2 text-right font-mono text-[var(--text-primary)]">{r.totalAdvisories.toLocaleString()}</td>
              <td className="px-3 py-2 text-right font-mono text-[var(--accent-teal)]">{r.last14dCount.toLocaleString()}</td>
              <td className="px-3 py-2 text-right font-mono text-[var(--accent-pink)]">{r.severityBreakdown.CRITICAL.toLocaleString()}</td>
              <td className="px-3 py-2 font-mono text-xs text-[var(--text-secondary)]">{r.topPackages[0]?.name ?? '—'}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

export function EcosystemsList() {
  const searchParams = useSearchParams();
  const updateParams = useUpdateParams();
  const view = (searchParams.get('view') === 'table' ? 'table' : 'grid') as View;

  // Collapsed state — URL-persisted via `collapsed=a,b,c`
  const collapsedParam = searchParams.get('collapsed') ?? '';
  const collapsed = useMemo(() => new Set(collapsedParam.split(',').filter(Boolean)), [collapsedParam]);

  const toggleCategory = (cat: string) => {
    const next = new Set(collapsed);
    if (next.has(cat)) next.delete(cat);
    else next.add(cat);
    updateParams({ collapsed: next.size > 0 ? [...next].join(',') : null });
  };

  const { data, isLoading, error } = useEcosystems();

  if (isLoading) return <DiamondLoader text="Loading ecosystems…" />;
  if (error || !data) {
    return (
      <div className="space-y-4">
        <PageHeader title="Ecosystems" subtitle="Failed to load." />
      </div>
    );
  }

  const byCategory = new Map<EcosystemCategory, EcosystemListRow[]>();
  for (const cat of CATEGORY_ORDER) byCategory.set(cat, []);
  for (const row of data.data) {
    const list = byCategory.get(row.category);
    if (list) list.push(row);
  }
  // Sort within each category by last-14d DESC then displayName
  for (const [, list] of byCategory) {
    list.sort((a, b) => b.last14dCount - a.last14dCount || a.displayName.localeCompare(b.displayName));
  }

  return (
    <div className="space-y-4">
      <PageHeader
        title="Ecosystems"
        subtitle="OSS package registries + OS / distro / kernel advisory catalogues — one card per ecosystem, click through for the full dashboard"
      />

      <div className="flex items-center gap-3 text-sm">
        <div className="inline-flex items-center rounded-md border border-[var(--border-color)] bg-[var(--surface-card)]">
          <button
            type="button"
            onClick={() => updateParams({ view: null })}
            className={`px-3 py-1 text-xs ${view === 'grid' ? 'text-[var(--accent-teal)] font-semibold' : 'text-[var(--text-secondary)]'}`}
          >
            Grid
          </button>
          <button
            type="button"
            onClick={() => updateParams({ view: 'table' })}
            className={`px-3 py-1 text-xs ${view === 'table' ? 'text-[var(--accent-teal)] font-semibold' : 'text-[var(--text-secondary)]'}`}
          >
            Table
          </button>
        </div>
        <span className="text-xs text-[var(--text-secondary)]">
          {data.data.length} ecosystems
        </span>
      </div>

      {view === 'table' ? (
        <TableView rows={data.data} />
      ) : (
        <div className="space-y-6">
          {CATEGORY_ORDER.map((cat) => (
            <CategorySection
              key={cat}
              category={cat}
              rows={byCategory.get(cat) ?? []}
              open={!collapsed.has(cat)}
              onToggle={() => toggleCategory(cat)}
            />
          ))}
        </div>
      )}
    </div>
  );
}
