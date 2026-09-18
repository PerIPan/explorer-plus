'use client';

import { useEffect, useMemo, useState } from 'react';
import Link from 'next/link';
import { PageHeader } from '../components/layout/PageHeader';

interface AssetRow {
  attackId: string;
  name: string;
  url: string | null;
  sectors: string[];
  platforms: string[];
  primaryLevel: string | null;
  primaryLevelLabel: string | null;
  zone: 'ot' | 'dmz' | 'it' | null;
  spansLevels: string[];
  isBoundary: boolean;
  rationale: string | null;
  techniqueCount: number;
}

interface ApiResponse {
  data: AssetRow[];
  pagination: { page: number; limit: number; total: number; totalPages: number };
}

const ZONE_CHIP: Record<string, string> = {
  ot:  'bg-[var(--orange-faint)] text-[var(--accent-orange)] border-[var(--orange-dim)]',
  dmz: 'bg-[var(--yellow-faint)] text-[var(--accent-yellow)] border-[var(--yellow-dim)]',
  it:  'bg-[var(--blue-faint)] text-[var(--accent-blue)] border-[var(--blue-dim)]',
};

const LEVELS = [
  { key: 'all',  label: 'All levels' },
  { key: 'l0',   label: 'L0 Physical' },
  { key: 'l1',   label: 'L1 Control' },
  { key: 'l2',   label: 'L2 Supervisory' },
  { key: 'l3',   label: 'L3 Site Ops' },
  { key: 'l3_5', label: 'L3.5 DMZ' },
  { key: 'l4',   label: 'L4 Business' },
  { key: 'l5',   label: 'L5 Enterprise' },
];

const fmtLevel = (k: string) => k.replace('_', '.').toUpperCase();

export function AssetsList() {
  const [data, setData] = useState<ApiResponse | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [level, setLevel] = useState('all');
  const [boundaryOnly, setBoundaryOnly] = useState(false);
  const [search, setSearch] = useState('');

  useEffect(() => {
    const params = new URLSearchParams({ limit: '200' });
    if (level !== 'all') params.set('level', level);
    if (boundaryOnly) params.set('boundary', 'true');
    const ctrl = new AbortController();
    setError(null);
    fetch(`/api/v1/assets?${params}`, { signal: ctrl.signal })
      .then((r) => (r.ok ? r.json() : Promise.reject(new Error(`HTTP ${r.status}`))))
      .then((d: ApiResponse) => { if (!ctrl.signal.aborted) setData(d); })
      .catch((e) => { if (!ctrl.signal.aborted) setError(e.message); });
    return () => ctrl.abort();
  }, [level, boundaryOnly]);

  const rows = useMemo(() => {
    if (!data) return [];
    const q = search.trim().toLowerCase();
    if (!q) return data.data;
    return data.data.filter(
      (r) => r.name.toLowerCase().includes(q) || r.attackId.toLowerCase().includes(q),
    );
  }, [data, search]);

  return (
    <>
      <PageHeader
        title="ICS Assets"
        subtitle="The equipment ATT&CK for ICS describes — controllers, historians, gateways and the network kit between them — with the techniques that target each, and where it sits in the Purdue model."
        actions={
          <Link
            href="/frameworks/purdue"
            className="text-xs px-2.5 py-1.5 rounded border border-[var(--border-color)] text-[var(--text-secondary)] hover:text-[var(--text-primary)] hover:border-[var(--border-hover)] transition-colors"
          >
            View the Purdue model
          </Link>
        }
      />

      <div className="flex flex-wrap items-center gap-2 mb-4">
        <input
          type="search"
          value={search}
          onChange={(e) => setSearch(e.target.value)}
          placeholder="Search assets"
          aria-label="Search assets by name or ID"
          className="text-sm px-2.5 py-1.5 rounded border border-[var(--border-color)] bg-[var(--surface-card)] text-[var(--text-primary)] placeholder:text-[var(--text-secondary)] focus:outline-none focus:border-[var(--border-hover)] min-w-[12rem]"
        />
        <select
          value={level}
          onChange={(e) => setLevel(e.target.value)}
          aria-label="Filter by Purdue level"
          className="text-sm px-2.5 py-1.5 rounded border border-[var(--border-color)] bg-[var(--surface-card)] text-[var(--text-primary)] focus:outline-none focus:border-[var(--border-hover)]"
        >
          {LEVELS.map((l) => <option key={l.key} value={l.key}>{l.label}</option>)}
        </select>
        <label className="flex items-center gap-1.5 text-xs text-[var(--text-secondary)] cursor-pointer">
          <input
            type="checkbox"
            checked={boundaryOnly}
            onChange={(e) => setBoundaryOnly(e.target.checked)}
            className="accent-[var(--accent-yellow)]"
          />
          IT/OT boundary only
        </label>
        {data && (
          <span className="text-xs text-[var(--text-secondary)] ml-auto font-mono tabular-nums">
            {rows.length} of {data.pagination.total}
          </span>
        )}
      </div>

      {error && <p className="text-sm text-[var(--accent-orange)]">Could not load assets: {error}</p>}
      {!data && !error && <p className="text-sm text-[var(--text-secondary)]">Loading…</p>}

      {data && rows.length === 0 && (
        <p className="text-sm text-[var(--text-secondary)]">
          No assets match these filters. Clear the search or choose another level.
        </p>
      )}

      {rows.length > 0 && (
        <ul className="divide-y divide-[var(--border-color)] border border-[var(--border-color)] rounded overflow-hidden">
          {rows.map((a) => (
            <li key={a.attackId}>
              <Link
                href={`/assets/${a.attackId}`}
                className="grid grid-cols-[auto_1fr_auto_auto] items-center gap-3 px-3 py-2.5 hover:bg-[var(--hover-overlay)] transition-colors"
              >
                <span className="font-mono text-xs text-[var(--text-secondary)] w-12">{a.attackId}</span>
                <span className="min-w-0">
                  <span className="block text-sm text-[var(--text-primary)] truncate">{a.name}</span>
                  <span className="block text-[11px] text-[var(--text-secondary)] truncate">
                    {a.spansLevels.map(fmtLevel).join(' · ')}
                    {a.sectors.length > 0 && ` — ${a.sectors.join(', ')}`}
                  </span>
                </span>
                {a.isBoundary && (
                  <span
                    className="text-[10px] uppercase tracking-wider px-1.5 py-0.5 rounded border bg-[var(--yellow-faint)] text-[var(--accent-yellow)] border-[var(--yellow-dim)]"
                    title="Present in the industrial DMZ — where OT meets IT"
                  >
                    boundary
                  </span>
                )}
                <span className="flex items-center gap-2 justify-end">
                  {a.zone && (
                    <span className={`text-[10px] uppercase tracking-wider px-1.5 py-0.5 rounded border ${ZONE_CHIP[a.zone]}`}>
                      {a.primaryLevel ? fmtLevel(a.primaryLevel) : a.zone}
                    </span>
                  )}
                  <span className="text-xs font-mono tabular-nums text-[var(--text-secondary)] w-16 text-right">
                    {a.techniqueCount} tech
                  </span>
                </span>
              </Link>
            </li>
          ))}
        </ul>
      )}
    </>
  );
}
