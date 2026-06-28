'use client';

import { useState, useMemo } from 'react';
import { useQuery } from '@tanstack/react-query';
import { apiFetch } from '../lib/api';
import { PageHeader } from '../components/layout/PageHeader';
import { Badge } from '../components/shared/Badge';
import { EntityLink } from '../components/shared/EntityLink';
import { DiamondLoader } from '../components/shared/FoldingDiamond';

interface IsoTechnique { attackId: string; name: string }
interface IsoControl { control: string; techniques: IsoTechnique[] }
interface IsoThemeGroup { theme: string; controls: IsoControl[] }
interface IsoResponse { data: IsoThemeGroup[]; totalControls: number; totalTechniques: number }

export function Iso27001Framework() {
  const [filter, setFilter] = useState('');
  const [expanded, setExpanded] = useState<string | null>(null);

  const { data, isLoading } = useQuery({
    queryKey: ['iso27001-list'],
    queryFn: () => apiFetch<IsoResponse>('/frameworks/iso27001'),
    staleTime: 10 * 60 * 1000,
  });

  const filteredGroups = useMemo(() => {
    const groups = data?.data ?? [];
    const q = filter.toLowerCase().trim();
    if (!q) return groups;
    return groups
      .map((g) => ({
        ...g,
        controls: g.controls.filter((c) =>
          c.control.toLowerCase().includes(q) ||
          c.techniques.some((t) => t.attackId.toLowerCase().includes(q) || t.name.toLowerCase().includes(q)),
        ),
      }))
      .filter((g) => g.controls.length > 0);
  }, [data, filter]);

  if (isLoading) return <DiamondLoader text="Loading ISO/IEC 27001:2022..." />;

  const visibleControls = filteredGroups.reduce((n, g) => n + g.controls.length, 0);

  return (
    <div className="space-y-4">
      <PageHeader
        title="ISO/IEC 27001:2022"
        subtitle="ISO 27001:2022 Annex A controls and mandatory clauses mapped to ATT&CK techniques via the NIST CSF v2 crosswalk (ISO ↔ CSF ↔ ATT&CK)"
        actions={
          <span className="text-[var(--text-secondary)] text-sm">
            {visibleControls} of {data?.totalControls ?? 0} controls · {data?.totalTechniques ?? 0} techniques
          </span>
        }
      />

      <div className="rounded-md border border-[var(--border-color)] bg-[var(--surface-card)] px-3 py-2 text-[12px] text-[var(--text-secondary)]">
        Indirect crosswalk: each ISO control is linked through the NIST CSF v2
        subcategories that reference it, then to the ATT&CK techniques those
        subcategories map to. Indicative coverage for detection/monitoring — not
        a certification or audit assertion.
      </div>

      <input
        type="text"
        value={filter}
        onChange={(e) => setFilter(e.target.value)}
        placeholder="Filter by control (e.g. 8.9) or technique…"
        className="w-full sm:w-80 px-3 py-1.5 text-sm rounded-md border border-[var(--border-color)] bg-[var(--surface-deep)] text-[var(--text-primary)]"
      />

      {filteredGroups.map((group) => (
        <section key={group.theme} className="space-y-2">
          <h2 className="text-sm font-semibold text-[var(--text-primary)]">
            {group.theme} <span className="text-[var(--text-secondary)] font-normal">({group.controls.length})</span>
          </h2>
          <div className="grid grid-cols-1 gap-1.5">
            {group.controls.map((c) => {
              const key = `${group.theme}:${c.control}`;
              const isOpen = expanded === key;
              return (
                <div key={key} className="rounded-md border border-[var(--border-color)] bg-[var(--surface-card)]">
                  <button
                    type="button"
                    onClick={() => setExpanded(isOpen ? null : key)}
                    className="w-full flex items-center justify-between gap-2 px-3 py-2 text-left"
                    aria-expanded={isOpen}
                  >
                    <span className="font-mono text-sm text-[var(--text-primary)]">{c.control}</span>
                    <span className="flex items-center gap-2">
                      <Badge label={`${c.techniques.length} tech`} variant="teal" />
                      <span className="text-[var(--text-secondary)] text-xs">{isOpen ? '▴' : '▾'}</span>
                    </span>
                  </button>
                  {isOpen && (
                    <div className="px-3 pb-3 pt-1 flex flex-wrap gap-1.5 border-t border-[var(--border-color)]">
                      {c.techniques.map((t) => (
                        <EntityLink key={t.attackId} type="technique" attackId={t.attackId} name={t.name} useMap />
                      ))}
                    </div>
                  )}
                </div>
              );
            })}
          </div>
        </section>
      ))}

      {filteredGroups.length === 0 && (
        <p className="text-sm text-[var(--text-secondary)]">No controls match “{filter}”.</p>
      )}
    </div>
  );
}
