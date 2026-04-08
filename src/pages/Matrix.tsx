import { useCallback, useEffect, useMemo, useState } from 'react';
import { useSearchParams } from 'react-router-dom';
import { useQueries, useQuery } from '@tanstack/react-query';
import { useMatrix, useGroups } from '../hooks/useApi';
import { apiFetch } from '../lib/api';
import { useSector } from '../contexts/SectorContext';
import { useDomain } from '../contexts/DomainContext';
import { PageHeader } from '../components/layout/PageHeader';
import { MatrixGrid } from '../components/matrix/MatrixGrid';
import { MatrixActorSelector, ACTOR_COLORS } from '../components/matrix/MatrixActorSelector';
import type { ActorOverlay } from '../components/matrix/MatrixGrid';
import type { SelectedActor } from '../components/matrix/MatrixActorSelector';
import type { Group } from '../lib/types';
import { exportMatrixHtml } from '../lib/exportMatrix';
import { getParentId } from '../lib/getParentId';
import { useTheme } from '../contexts/ThemeContext';
import { DiamondLoader } from '../components/shared/FoldingDiamond';

export function Matrix() {
  const [searchParams] = useSearchParams();
  const { sectorParam, sector } = useSector();
  const { domain, domainParam } = useDomain();
  const { theme } = useTheme();
  const isAllDomains = domain === 'all';
  const { data, isLoading, error } = useMatrix(isAllDomains ? sectorParam : { ...sectorParam, ...domainParam });
  const [inputValue, setInputValue] = useState('');
  const [filterText, setFilterText] = useState('');
  const [selectedActors, setSelectedActors] = useState<SelectedActor[]>([]);

  // Fetch all groups for the actor selector (respects sector filter)
  const groupsParams = useMemo(() => ({ limit: '5000', ...sectorParam, ...domainParam }), [sectorParam, domainParam]);
  const { data: groupsData } = useGroups(groupsParams);
  const groups = useMemo<Group[]>(() => groupsData?.data ?? [], [groupsData]);

  useEffect(() => {
    const timer = setTimeout(() => setFilterText(inputValue), 200);
    return () => clearTimeout(timer);
  }, [inputValue]);

  // Entity highlight: fetch techniques for a given entity and hide non-matching cells
  // Works for all entity types including groups (from 360 View Matrix button)
  const actorParam = searchParams.get('actor');
  const highlightEntity = searchParams.get('entity') ?? actorParam ?? null;
  const highlightType = searchParams.get('type') ?? (actorParam ? 'group' : null);

  const { data: highlightData } = useQuery({
    queryKey: ['matrix-highlight', highlightType, highlightEntity],
    queryFn: async () => {
      if (highlightType === 'group') {
        const d = await apiFetch<{ techniques?: Array<{ attackId: string }> }>(`/groups/${highlightEntity}`);
        return d.techniques?.map((t) => t.attackId) ?? [];
      }
      if (highlightType === 'software') {
        const d = await apiFetch<{ techniques?: Array<{ attackId: string }> }>(`/software/${highlightEntity}`);
        return d.techniques?.map((t) => t.attackId) ?? [];
      }
      if (highlightType === 'application') {
        const d = await apiFetch<{ techniques: Array<{ attackId: string }> }>(`/applications/${highlightEntity}`);
        return d.techniques.map((t) => t.attackId);
      }
      if (highlightType === 'campaign') {
        const d = await apiFetch<{ techniques?: Array<{ attackId: string }> }>(`/campaigns/${highlightEntity}`);
        return d.techniques?.map((t) => t.attackId) ?? [];
      }
      if (highlightType === 'mitigation') {
        const d = await apiFetch<{ techniques?: Array<{ attackId: string }> }>(`/mitigations/${highlightEntity}`);
        return d.techniques?.map((t) => t.attackId) ?? [];
      }
      if (highlightType === 'sector') {
        const d = await apiFetch<{ techniques?: Array<{ attackId: string }> }>(`/sectors/${highlightEntity}/relationships`);
        return d.techniques?.map((t) => t.attackId) ?? [];
      }
      if (highlightType === 'data_source') {
        const d = await apiFetch<{ techniques?: Array<{ attackId: string }> }>(`/data-sources/${highlightEntity}`);
        return d.techniques?.map((t) => t.attackId) ?? [];
      }
      if (highlightType === 'owasp') {
        const d = await apiFetch<{ techniques?: Array<{ attackId: string }> }>(`/frameworks/owasp/${highlightEntity}`);
        return d.techniques?.map((t) => t.attackId) ?? [];
      }
      return [];
    },
    enabled: Boolean(highlightEntity) && Boolean(highlightType),
    staleTime: 5 * 60 * 1000,
  });

  const highlightIds = useMemo(() => {
    if (!highlightData?.length) return undefined;
    return new Set(highlightData.map((id) => getParentId(id)));
  }, [highlightData]);

  const highlightLabel = searchParams.get('label')
    ?? (actorParam ? groups.find((g) => g.attackId === actorParam)?.name ?? actorParam : null);

  // Fetch full group details for selected actors (techniques)
  const groupQueries = useQueries({
    queries: selectedActors.map((actor) => ({
      queryKey: ['group', actor.attackId],
      queryFn: () => apiFetch<Group>(`/groups/${actor.attackId}`),
      enabled: Boolean(actor.attackId),
    })),
  });

  // Stable reference to group query data (avoids useQueries array reference churn)
  // Use dataUpdatedAt timestamps as dependency — these are primitives that change only when data changes
  const groupQueryData = useMemo(
    () => groupQueries.map((q) => q.data),
    // eslint-disable-next-line react-hooks/exhaustive-deps
    [groupQueries.map((q) => q.dataUpdatedAt).join(',')],
  );

  // Build the actor overlay lookup map (only when all queries are loaded)
  const allQueriesLoaded = groupQueries.every((q) => !q.isLoading);
  const actorOverlay = useMemo<ActorOverlay | undefined>(() => {
    if (selectedActors.length === 0 || !allQueriesLoaded) return undefined;

    // Build a color array indexed by colorIndex (sparse but max 3)
    const colors: string[] = [];
    selectedActors.forEach((a) => { colors[a.colorIndex] = ACTOR_COLORS[a.colorIndex].css; });

    const lookup = new Map<string, Set<number>>();

    groupQueryData.forEach((data, idx) => {
      if (!data?.techniques) return;
      const colorIdx = selectedActors[idx].colorIndex;
      for (const t of data.techniques) {
        const parentId = getParentId(t.attackId);
        const existing = lookup.get(parentId);
        if (existing) {
          existing.add(colorIdx);
        } else {
          lookup.set(parentId, new Set([colorIdx]));
        }
      }
    });

    return { colors, lookup };
  }, [selectedActors, groupQueryData]);

  // Compute legend counts (parent techniques in the current matrix view)
  const matrixAttackIds = useMemo(() => {
    const ids = new Set<string>();
    (data ?? []).forEach((col) => col.techniques.forEach((t) => ids.add(t.attackId)));
    return ids;
  }, [data]);

  const legendCounts = useMemo(() => {
    return groupQueryData.map((data) => {
      if (!data?.techniques) return 0;
      const parentIds = new Set(data.techniques.map((t) => getParentId(t.attackId)));
      let count = 0;
      parentIds.forEach((id) => { if (matrixAttackIds.has(id)) count++; });
      return count;
    });
  }, [groupQueryData, matrixAttackIds]);

  const totalTechniques = useMemo(
    () => (data ?? []).reduce((sum, col) => sum + col.techniques.length, 0),
    [data]
  );

  const handleSelectActor = useCallback((actor: { attackId: string; name: string }) => {
    setSelectedActors((prev) => {
      if (prev.length >= 3) return prev;
      if (prev.some((a) => a.attackId === actor.attackId)) return prev;
      const usedSlots = new Set(prev.map((a) => a.colorIndex));
      let colorIndex = 0;
      while (usedSlots.has(colorIndex)) colorIndex++;
      return [...prev, { ...actor, colorIndex }];
    });
  }, []);

  const handleRemoveActor = useCallback((attackId: string) => {
    setSelectedActors((prev) => prev.filter((a) => a.attackId !== attackId));
  }, []);

  const handleExport = useCallback(() => {
    if (!data) return;
    // Resolve CSS variables to actual hex for standalone HTML
    const root = document.documentElement;
    const style = getComputedStyle(root);
    const resolveColor = (cssVar: string) => {
      const match = cssVar.match(/var\(--(.+?)\)/);
      if (!match) return cssVar;
      return style.getPropertyValue(`--${match[1]}`).trim() || cssVar;
    };
    const resolvedActorColors = actorOverlay?.colors?.map((c) => resolveColor(c));
    const html = exportMatrixHtml(data, {
      domain,
      sector: sector ?? undefined,
      actors: selectedActors.map((a) => ({ name: a.name, color: resolveColor(ACTOR_COLORS[a.colorIndex].css) })),
      actorLookup: actorOverlay?.lookup,
      actorColors: resolvedActorColors,
      theme,
      highlightIds,
      highlightLabel: highlightLabel ?? undefined,
    });
    const blob = new Blob([html], { type: 'text/html' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `mitre-matrix-${domain.replace('-attack', '')}-${new Date().toISOString().split('T')[0]}.html`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  }, [data, domain, sector, selectedActors, actorOverlay, theme]);

  return (
    <div className="space-y-4">
      <PageHeader
        title={domain === 'atlas-attack' ? 'ATLAS Matrix' : 'ATT&CK Matrix'}
        titleAction={data && (
          <span className="inline-flex items-center gap-2 ml-3">
            {highlightLabel && highlightIds && (
              <span className="inline-flex items-center gap-1.5 px-2 py-1 rounded text-[10px] font-medium bg-[var(--teal-faint)] text-[var(--accent-teal)] border border-[var(--teal-dim)]">
                {highlightLabel} ({highlightIds.size})
              </span>
            )}
            <button
              type="button"
              onClick={handleExport}
              className="inline-flex items-center gap-1 px-2 py-1 rounded text-[10px] font-medium bg-[var(--surface-alt)] border border-[var(--border-color)] text-[var(--text-secondary)] hover:text-[var(--accent-teal)] hover:border-[var(--accent-teal)] transition-colors"
              title="Export matrix as HTML file"
            >
              <svg className="w-3.5 h-3.5" fill="none" stroke="currentColor" strokeWidth={2} viewBox="0 0 24 24" aria-hidden="true">
                <path strokeLinecap="round" strokeLinejoin="round" d="M3 16.5v2.25A2.25 2.25 0 005.25 21h13.5A2.25 2.25 0 0021 18.75V16.5M16.5 12L12 16.5m0 0L7.5 12m4.5 4.5V3" />
              </svg>
              Export HTML
            </button>
          </span>
        )}
        subtitle={isAllDomains
          ? 'Showing all techniques across Enterprise, ICS, and Mobile — select a specific domain for domain-scoped tactics'
          : 'Techniques organized by tactic, filtered by domain, sector or actor — click any cell to view details'}
        actions={
          <div className="flex items-center gap-3">
            <span className="text-[var(--text-secondary)] text-sm">
              {totalTechniques} techniques across {(data ?? []).length} tactics
            </span>
          </div>
        }
      />

      {/* Controls bar */}
      {!isLoading && !error && data && (
        <div className="flex items-center gap-3 justify-between">
          {/* Left: technique filter + actor search side by side */}
          <div className="flex items-center gap-2">
            <div className="relative">
              <svg
                className="absolute left-3 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-[var(--text-secondary)]"
                fill="none"
                stroke="currentColor"
                strokeWidth={2}
                viewBox="0 0 24 24"
                aria-hidden="true"
              >
                <path strokeLinecap="round" strokeLinejoin="round" d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z" />
              </svg>
              <input
                type="search"
                placeholder="Technique name filter..."
                value={inputValue}
                onChange={(e) => setInputValue(e.target.value)}
                className="w-[200px] pl-8 pr-3 py-1.5 rounded-md text-sm bg-[var(--surface-card)] border border-[var(--border-color)] text-[var(--text-primary)] placeholder-[var(--text-secondary)] focus:outline-none focus:border-[var(--accent-teal)] transition-colors"
              />
            </div>
            {inputValue && (
              <button
                type="button"
                onClick={() => { setInputValue(''); setFilterText(''); }}
                className="text-xs text-[var(--text-secondary)] hover:text-[var(--text-primary)] transition-colors"
              >
                Clear
              </button>
            )}
            <MatrixActorSelector
              groups={groups}
              selected={selectedActors}
              onSelect={handleSelectActor}
              onRemove={handleRemoveActor}
            />
          </div>

          {/* Right: actor pills + legend */}
          {selectedActors.length > 0 && (
            <div className="flex items-center gap-3 text-xs">
              {selectedActors.map((actor, idx) => (
                <span key={actor.attackId} className="inline-flex items-center gap-1.5 text-[var(--text-secondary)]">
                  <span className="w-2.5 h-2.5 rounded-full shrink-0" style={{ backgroundColor: ACTOR_COLORS[actor.colorIndex].css }} />
                  <span className="text-[var(--text-primary)] font-medium">{actor.name}</span>
                  <span>
                    ({groupQueries[idx]?.isLoading ? '...' : `${legendCounts[idx]} techniques`})
                  </span>
                </span>
              ))}
              <span className="inline-flex items-center gap-1.5 text-[var(--text-secondary)]">
                <span className="w-2.5 h-2.5 rounded-full shrink-0 bg-[var(--accent-teal)]" />
                <span>Shared</span>
              </span>
            </div>
          )}
        </div>
      )}

      {isLoading && (
        <DiamondLoader text="Loading matrix..." />
      )}

      {error && (
        <div className="flex items-center justify-center h-64 text-[var(--accent-orange)]">
          Failed to load matrix data.
        </div>
      )}

      {!isLoading && !error && data && (
        <MatrixGrid data={data} filterText={filterText} actorOverlay={actorOverlay} highlightIds={highlightIds} />
      )}
    </div>
  );
}
