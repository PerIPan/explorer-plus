import { useState, useMemo } from 'react';
import { useQuery } from '@tanstack/react-query';
import { apiFetch } from '../lib/api';
import { PageHeader } from '../components/layout/PageHeader';
import { EntityLink } from '../components/shared/EntityLink';

interface VerisRow {
  verisId: string;
  techniqueCount: string;
  techniques: string[];
}

interface VerisResponse {
  data: VerisRow[];
  categories: { category: string; count: string }[];
  total: number;
}

const CATEGORY_COLORS: Record<string, string> = {
  action: 'var(--accent-orange)',
  attribute: 'var(--accent-purple)',
  value_chain: 'var(--accent-blue)',
};

export function VerisCategories() {
  const [search, setSearch] = useState('');
  const [category, setCategory] = useState('');

  const { data, isLoading } = useQuery({
    queryKey: ['veris', category, search],
    queryFn: () => {
      const params: Record<string, string> = {};
      if (category) params.category = category;
      if (search) params.q = search;
      return apiFetch<VerisResponse>('/frameworks/veris', params);
    },
  });

  // Group by top-level category (action.hacking.variety.X → action.hacking)
  const grouped = useMemo(() => {
    if (!data?.data) return new Map<string, VerisRow[]>();
    const map = new Map<string, VerisRow[]>();
    for (const row of data.data) {
      const parts = row.verisId.split('.');
      const group = parts.slice(0, 2).join('.');
      if (!map.has(group)) map.set(group, []);
      map.get(group)!.push(row);
    }
    return map;
  }, [data]);

  return (
    <div className="space-y-6">
      <PageHeader
        title="VERIS Incident Categories"
        subtitle="Vocabulary for Event Recording and Incident Sharing — incident classification mapped to ATT&CK techniques (Verizon DBIR standard)"
        actions={
          <span className="text-sm text-[var(--text-secondary)]">
            {data?.total ?? '...'} categories
          </span>
        }
      />

      <div className="flex flex-wrap gap-3">
        <input
          type="search"
          placeholder="Search categories or techniques..."
          value={search}
          onChange={(e) => setSearch(e.target.value)}
          className="min-w-[200px] px-3 py-2 rounded-md text-sm bg-[var(--surface-card)] border border-[var(--border-color)] text-[var(--text-primary)] placeholder:text-[var(--text-secondary)] focus:outline-none focus:border-[var(--accent-teal)] focus:ring-1 focus:ring-[var(--accent-teal)]"
        />
        <select
          value={category}
          onChange={(e) => setCategory(e.target.value)}
          aria-label="Filter by category"
          className="px-3 py-2 rounded-md text-sm bg-[var(--surface-card)] border border-[var(--border-color)] text-[var(--text-primary)] focus:outline-none focus:border-[var(--accent-teal)] focus:ring-1 focus:ring-[var(--accent-teal)]"
        >
          <option value="">All Categories</option>
          {(data?.categories ?? []).map((c) => (
            <option key={c.category} value={c.category}>
              {c.category} ({c.count})
            </option>
          ))}
        </select>
      </div>

      {isLoading && (
        <div className="space-y-2">
          {Array.from({ length: 6 }).map((_, i) => (
            <div key={i} className="h-12 rounded-lg bg-[var(--border-color)] animate-pulse" />
          ))}
        </div>
      )}

      {!isLoading && [...grouped.entries()].map(([group, rows]) => {
        const topLevel = group.split('.')[0];
        const color = CATEGORY_COLORS[topLevel] ?? 'var(--accent-teal)';

        return (
          <section key={group} className="space-y-2">
            <h2
              className="text-xs font-semibold uppercase tracking-wider px-1 py-1"
              style={{ color }}
            >
              {group}
            </h2>

            {rows.map((row) => {
              const shortLabel = row.verisId.split('.').slice(2).join('.');
              return (
                <details
                  key={row.verisId}
                  className="group rounded-lg border border-[var(--border-color)] bg-[var(--surface-card)] overflow-hidden"
                >
                  <summary className="flex items-center gap-3 px-4 py-2 cursor-pointer hover:bg-[var(--teal-ghost)] transition-colors">
                    <svg className="w-3 h-3 text-[var(--text-secondary)] transition-transform group-open:rotate-90 shrink-0" fill="none" stroke="currentColor" strokeWidth={2} viewBox="0 0 24 24" aria-hidden="true">
                      <path strokeLinecap="round" strokeLinejoin="round" d="M9 5l7 7-7 7" />
                    </svg>
                    <a
                      href={`https://center-for-threat-informed-defense.github.io/mappings-explorer/external/veris/`}
                      target="_blank"
                      rel="noopener noreferrer"
                      onClick={(e) => e.stopPropagation()}
                      className="text-sm text-[var(--text-primary)] flex-1 hover:text-[var(--accent-teal)] hover:underline"
                      title="View on CTID Mappings Explorer"
                    >
                      {shortLabel || row.verisId}
                    </a>
                    <span className="text-xs text-[var(--text-secondary)] shrink-0">
                      {row.techniqueCount} techniques
                    </span>
                  </summary>
                  <div className="px-4 pb-3 pt-1 border-t border-[var(--border-color)]">
                    <div className="flex flex-wrap gap-1.5">
                      {row.techniques.map((tid) => (
                        <EntityLink key={tid} type="technique" attackId={tid} name={tid} />
                      ))}
                    </div>
                  </div>
                </details>
              );
            })}
          </section>
        );
      })}

      {!isLoading && (data?.total ?? 0) === 0 && (
        <div className="text-center py-16 text-[var(--text-secondary)]">
          No categories found{search ? ` matching "${search}"` : ''}.
        </div>
      )}
    </div>
  );
}
