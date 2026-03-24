import { useCallback, useEffect, useMemo, useState } from 'react';
import { useQueries } from '@tanstack/react-query';
import { useMatrix, useGroups } from '../hooks/useApi';
import { apiFetch } from '../lib/api';
import { useSector } from '../contexts/SectorContext';
import { PageHeader } from '../components/layout/PageHeader';
import { MatrixGrid } from '../components/matrix/MatrixGrid';
import { MatrixActorSelector, ACTOR_COLORS } from '../components/matrix/MatrixActorSelector';
import type { ActorOverlay } from '../components/matrix/MatrixGrid';
import type { SelectedActor } from '../components/matrix/MatrixActorSelector';
import type { Group } from '../lib/types';

export function Matrix() {
  const { sectorParam } = useSector();
  const { data, isLoading, error } = useMatrix(sectorParam);
  const [inputValue, setInputValue] = useState('');
  const [filterText, setFilterText] = useState('');
  const [selectedActors, setSelectedActors] = useState<SelectedActor[]>([]);

  // Fetch all groups for the actor selector (respects sector filter)
  const groupsParams = useMemo(() => ({ limit: '5000', ...sectorParam }), [sectorParam]);
  const { data: groupsData } = useGroups(groupsParams);
  const groups = useMemo<Group[]>(() => groupsData?.data ?? [], [groupsData]);

  useEffect(() => {
    const timer = setTimeout(() => setFilterText(inputValue), 200);
    return () => clearTimeout(timer);
  }, [inputValue]);

  // Fetch full group details for selected actors (techniques)
  const groupQueries = useQueries({
    queries: selectedActors.map((actor) => ({
      queryKey: ['group', actor.attackId],
      queryFn: () => apiFetch<Group>(`/groups/${actor.attackId}`),
      enabled: Boolean(actor.attackId),
    })),
  });

  // Stable reference to group query data (avoids useQueries array reference churn)
  const groupQueryData = useMemo(
    () => groupQueries.map((q) => q.data),
    [groupQueries.map((q) => q.data).join(',')],
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
        const parentId = t.attackId.split('.')[0];
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
      const parentIds = new Set(data.techniques.map((t) => t.attackId.split('.')[0]));
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

  return (
    <div className="space-y-4">
      <PageHeader
        title="ATT&CK Matrix"
        subtitle="Techniques organized by tactic — click any cell to view details"
        actions={
          <span className="text-[var(--text-secondary)] text-sm">
            {totalTechniques} techniques across {(data ?? []).length} tactics
          </span>
        }
      />

      {/* Controls bar */}
      {!isLoading && !error && data && (
        <div className="flex items-center gap-3 justify-between">
          {/* Left: text filter */}
          <div className="flex items-center gap-2 max-w-sm">
            <div className="relative flex-1">
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
                placeholder="Filter techniques by name or ID..."
                value={inputValue}
                onChange={(e) => setInputValue(e.target.value)}
                className="w-full pl-8 pr-3 py-1.5 rounded-md text-sm bg-[var(--surface-card)] border border-[var(--border-color)] text-[var(--text-primary)] placeholder-[var(--text-secondary)] focus:outline-none focus:border-[var(--accent-teal)] transition-colors"
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
          </div>

          {/* Right: actor selector */}
          <MatrixActorSelector
            groups={groups}
            selected={selectedActors}
            onSelect={handleSelectActor}
            onRemove={handleRemoveActor}
          />
        </div>
      )}

      {/* Actor legend strip */}
      {selectedActors.length > 0 && (
        <div className="flex items-center gap-4 text-xs">
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

      {isLoading && (
        <div className="flex items-center justify-center h-64 text-[var(--text-secondary)]">
          <span className="inline-block w-5 h-5 border-2 border-[var(--teal-dim)] border-t-[var(--accent-teal)] rounded-full animate-spin mr-2" />
          Loading matrix...
        </div>
      )}

      {error && (
        <div className="flex items-center justify-center h-64 text-[var(--accent-orange)]">
          Failed to load matrix data.
        </div>
      )}

      {!isLoading && !error && data && (
        <MatrixGrid data={data} filterText={filterText} actorOverlay={actorOverlay} />
      )}
    </div>
  );
}
