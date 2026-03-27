import { useState, useCallback, useRef, useEffect, useMemo } from 'react';
import { usePageTitle } from '../hooks/usePageTitle';
import { useSearchParams } from 'react-router-dom';
import { useQuery } from '@tanstack/react-query';
import Fuse from 'fuse.js';
import { useRelationships } from '../hooks/useApi';
import { apiFetch } from '../lib/api';
import { PageHeader } from '../components/layout/PageHeader';
import { ForceGraph, type ForceGraphHandle } from '../components/graph/ForceGraph';
import { Badge } from '../components/shared/Badge';
import { ActorProfileView } from '../components/relationships/ActorProfileView';
import { TechniqueMapView } from '../components/relationships/TechniqueMapView';
import { SoftwareMapView } from '../components/relationships/SoftwareMapView';
import { MitigationMapView } from '../components/relationships/MitigationMapView';
import { DataSourceMapView } from '../components/relationships/DataSourceMapView';
import { TacticMapView } from '../components/relationships/TacticMapView';
import { SectorMapView } from '../components/relationships/SectorMapView';
import type { GraphNode, GraphData } from '../lib/types';

interface EntityEntry {
  attackId: string;
  name: string;
  type: string;
  domain: string | null;
}

// ── Entity type → badge variant ───────────────────────────────────────────────

const TYPE_VARIANT: Record<string, 'teal' | 'orange' | 'purple' | 'blue' | 'green' | 'pink' | 'yellow' | 'neutral'> = {
  technique: 'teal',
  group: 'orange',
  software: 'purple',
  campaign: 'blue',
  mitigation: 'green',
  data_source: 'pink',
  tactic: 'yellow',
  external_actor: 'neutral',
  sector: 'green',
};

/** Human-readable label for entity types */
const TYPE_LABEL: Record<string, string> = {
  external_actor: 'Non-MITRE',
  data_source: 'data source',
  sector: 'sector',
};

function typeLabel(type: string): string {
  return TYPE_LABEL[type] ?? type.replaceAll('_', ' ');
}

// ── Tab definitions ────────────────────────────────────────────────────────────

type TabId = 'graph' | 'actor' | 'technique-map' | 'software-map' | 'mitigation-map' | 'data-source-map' | 'tactic-map' | 'sector-map';

interface TabDef {
  id: TabId;
  label: string;
  /** Which entity types show this tab. Undefined means always visible. */
  forTypes?: string[];
}

const TABS: TabDef[] = [
  { id: 'actor', label: 'Threat Actor Profile', forTypes: ['group', 'campaign', 'external_actor'] },
  { id: 'technique-map', label: 'Technique Map', forTypes: ['technique'] },
  { id: 'software-map', label: 'Software Map', forTypes: ['software'] },
  { id: 'mitigation-map', label: 'Mitigation Map', forTypes: ['mitigation'] },
  { id: 'data-source-map', label: 'Data Source Map', forTypes: ['data_source'] },
  { id: 'tactic-map', label: 'Tactic Map', forTypes: ['tactic'] },
  { id: 'sector-map', label: 'Sector Map', forTypes: ['sector'] },
  { id: 'graph', label: 'Graph' },
];

/** Map entity type → best default tab */
const TAB_FOR_TYPE: Record<string, TabId> = {
  group: 'actor', campaign: 'actor', external_actor: 'actor',
  technique: 'technique-map',
  software: 'software-map',
  mitigation: 'mitigation-map',
  data_source: 'data-source-map',
  tactic: 'tactic-map',
  sector: 'sector-map',
};

/** Derive the entity type from the graph center node or from search suggestions */
function inferEntityType(
  graphCenter: GraphNode | undefined,
  suggestions: Array<{ attackId: string; type: string }>,
  selectedId: string,
): string | null {
  if (graphCenter?.type) return graphCenter.type;
  const match = suggestions.find((s) => s.attackId === selectedId);
  return match?.type ?? null;
}

// ── Page component ─────────────────────────────────────────────────────────────

export function Relationships() {
  usePageTitle('360 Views');

  const [searchParams, setSearchParams] = useSearchParams();
  const entityParam = searchParams.get('entity') ?? '';
  const tabParam = (searchParams.get('tab') ?? 'graph') as TabId;

  const [selectedId, setSelectedId] = useState<string>(entityParam);
  const [searchInput, setSearchInput] = useState(entityParam);
  const [showSuggestions, setShowSuggestions] = useState(false);
  const [activeTab, setActiveTab] = useState<TabId>(tabParam);
  const graphRef = useRef<ForceGraphHandle>(null);
  const containerRef = useRef<HTMLDivElement>(null);
  const blurTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null);

  /** Keep selectedId in sync with URL param */
  useEffect(() => {
    if (entityParam && entityParam !== selectedId) {
      setSelectedId(entityParam);
      setSearchInput(entityParam);
    }
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [entityParam]);

  /** Keep tab in sync with URL param */
  useEffect(() => {
    if (tabParam && tabParam !== activeTab) {
      setActiveTab(tabParam);
    }
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [tabParam]);

  /** Clear blur timer on unmount */
  useEffect(() => {
    return () => {
      if (blurTimerRef.current !== null) clearTimeout(blurTimerRef.current);
    };
  }, []);

  const { data: graphData, isLoading, error } = useRelationships(
    (tabParam === 'sector-map' || !selectedId) ? '' : selectedId,
  );

  /** Load ALL entity names cross-domain for Fuse.js — shared cache with SearchBar */
  const { data: allEntities } = useQuery({
    queryKey: ['entities-all-cross'],
    queryFn: () => apiFetch<{ data: EntityEntry[] }>('/entities').then(r => r.data),
    staleTime: 60 * 60 * 1000, // 1 hour
    gcTime: 60 * 60 * 1000,
  });

  /** Build Fuse index (memoized — only rebuilds when entities load) */
  const fuse = useMemo(() => {
    if (!allEntities?.length) return null;
    return new Fuse(allEntities, {
      keys: ['name', 'attackId'],
      threshold: 0.3,
      distance: 100,
      minMatchCharLength: 2,
    });
  }, [allEntities]);

  /** Fuzzy search — instant, client-side */
  const suggestions = useMemo(() => {
    if (!fuse || !searchInput.trim() || searchInput.trim().length < 2) return [];
    return fuse.search(searchInput.trim(), { limit: 12 }).map(r => r.item);
  }, [fuse, searchInput]);

  // Infer entity type from graph center or suggestions; fall back to tab hint for non-graph entities
  const TAB_TYPE_HINT: Record<string, string> = { 'sector-map': 'sector' };
  const entityType = inferEntityType(graphData?.center, suggestions, selectedId)
    ?? TAB_TYPE_HINT[tabParam]
    ?? null;

  const isSector = entityType === 'sector';

  /** Sector relationships — fetch only for sectors, build graph from it */
  const { data: sectorRel } = useQuery({
    queryKey: ['sector-relationships', selectedId],
    queryFn: () => apiFetch<{
      name: string;
      groups: Array<{ attackId: string; name: string }>;
      campaigns: Array<{ attackId: string; name: string }>;
      software: Array<{ attackId: string; name: string }>;
    }>(`/sectors/${selectedId}/relationships`),
    enabled: isSector && Boolean(selectedId),
    staleTime: 2 * 60 * 1000,
  });

  const sectorGraphData = useMemo<GraphData | null>(() => {
    if (!isSector || !sectorRel) return null;
    const center: GraphNode = { id: selectedId, label: sectorRel.name, type: 'sector', attackId: selectedId };
    const nodes: GraphNode[] = [];
    const edges: GraphData['edges'] = [];
    for (const g of sectorRel.groups) {
      nodes.push({ id: g.attackId, label: g.name, type: 'group', attackId: g.attackId });
      edges.push({ source: selectedId, target: g.attackId, relationship: 'targets' });
    }
    for (const c of sectorRel.campaigns) {
      nodes.push({ id: c.attackId, label: c.name, type: 'campaign', attackId: c.attackId });
      edges.push({ source: selectedId, target: c.attackId, relationship: 'campaign' });
    }
    for (const s of sectorRel.software.slice(0, 30)) {
      nodes.push({ id: s.attackId, label: s.name, type: 'software', attackId: s.attackId });
      edges.push({ source: selectedId, target: s.attackId, relationship: 'uses' });
    }
    return { center, nodes, edges, truncated: sectorRel.software.length > 30 };
  }, [isSector, sectorRel, selectedId]);

  const effectiveGraphData = isSector ? sectorGraphData : graphData;
  const graphReady = isSector ? Boolean(sectorGraphData) : (!isLoading && !error && Boolean(graphData));

  /** Determine which tabs are visible for the current entity */
  const visibleTabs = TABS.filter(
    (tab) => !tab.forTypes || (entityType && tab.forTypes.includes(entityType))
  );

  /** When entity type changes, auto-select the best tab (unless URL explicitly set one) */
  useEffect(() => {
    // Don't override if URL has an explicit tab and entity data hasn't loaded yet
    if (tabParam && !entityType) return;
    const isVisible = visibleTabs.some((t) => t.id === activeTab);
    if (!isVisible && visibleTabs.length > 0) {
      const bestTab = visibleTabs[0]?.id ?? 'graph';
      setActiveTab(bestTab);
      setSearchParams((prev) => {
        const next = new URLSearchParams(prev);
        next.set('tab', bestTab);
        return next;
      });
    }
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [entityType, activeTab]);

  const selectEntity = useCallback(
    (attackId: string, knownType?: string) => {
      setSelectedId(attackId);
      setSearchInput(attackId);
      setShowSuggestions(false);

      // Immediately pick the best tab based on known type
      const bestTab: TabId = (knownType && TAB_FOR_TYPE[knownType]) || 'graph';
      setActiveTab(bestTab);

      setSearchParams((prev) => {
        const next = new URLSearchParams(prev);
        next.set('entity', attackId);
        next.set('tab', bestTab);
        return next;
      });
    },
    [setSearchParams]
  );

  const selectTab = useCallback(
    (tabId: TabId) => {
      setActiveTab(tabId);
      setSearchParams((prev) => {
        const next = new URLSearchParams(prev);
        next.set('tab', tabId);
        return next;
      });
    },
    [setSearchParams]
  );

  const handleNodeClick = useCallback((node: GraphNode) => {
    if (node.attackId) selectEntity(node.attackId, node.type);
  }, [selectEntity]);

  return (
    <div className="space-y-4">
      <PageHeader
        title="Relationships Map"
        subtitle="Map 360 Views for every entity type — select an entity to start, domain filtered search"
        actions={
          selectedId ? (
            <button
              type="button"
              data-print-hide
              onClick={() => window.print()}
              className="px-3 py-1.5 text-xs rounded-md border border-[var(--border-color)] text-[var(--text-secondary)] hover:text-[var(--accent-teal)] hover:border-[var(--teal-dim)] transition-colors"
              title="Export current view as PDF (Ctrl+P)"
            >
              Export PDF
            </button>
          ) : undefined
        }
      />

      {/* Entity search — combobox with autocomplete dropdown */}
      <div className="relative max-w-2xl" ref={containerRef}>
        <div className={`flex items-center gap-2 px-4 py-2.5 rounded-lg bg-[var(--surface-card)] border transition-colors ${showSuggestions && suggestions.length > 0 ? 'border-[var(--accent-teal)] rounded-b-none' : 'border-[var(--border-color)]'} focus-within:border-[var(--accent-teal)]`}>
          <svg className="w-4 h-4 text-[var(--text-secondary)] flex-shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z" />
          </svg>
          {selectedId && !showSuggestions && graphData?.center && (
            <Badge
              label={typeLabel(graphData.center.type)}
              variant={TYPE_VARIANT[graphData.center.type] ?? 'neutral'}
            />
          )}
          <input
            type="text"
            value={searchInput}
            onChange={(e) => {
              setSearchInput(e.target.value);
              setShowSuggestions(true);
            }}
            onFocus={() => {
              setShowSuggestions(true);
              if (selectedId) setSearchInput('');
            }}
            onBlur={() => {
              blurTimerRef.current = setTimeout(() => {
                setShowSuggestions(false);
                if (!searchInput && selectedId && graphData?.center) {
                  setSearchInput(graphData?.center?.label ?? '');
                }
              }, 200);
            }}
            onKeyDown={(e) => {
              if (e.key === 'Escape') {
                setShowSuggestions(false);
                (e.target as HTMLInputElement).blur();
              }
              if (e.key === 'Enter' && suggestions.length > 0) {
                selectEntity(suggestions[0].attackId, suggestions[0].type);
              }
            }}
            placeholder={selectedId ? 'Search for another entity...' : 'Phishing, APT29, PowerShell, T1059...'}
            className="flex-1 bg-transparent text-sm text-[var(--text-primary)] placeholder-[var(--text-secondary)] focus:outline-none"
          />
          {searchInput && (
            <button
              type="button"
              onClick={() => { setSearchInput(''); setShowSuggestions(false); }}
              className="text-[var(--text-secondary)] hover:text-[var(--text-primary)] text-xs"
            >
              Clear
            </button>
          )}
        </div>

        {showSuggestions && suggestions.length > 0 && (
          <div className="absolute top-full w-full z-50 bg-[var(--surface-card)] border border-t-0 border-[var(--accent-teal)] rounded-b-lg shadow-2xl overflow-hidden max-h-80 overflow-y-auto">
            <div className="px-3 py-1.5 text-[10px] uppercase tracking-wider text-[var(--text-secondary)] bg-[var(--surface-deep)]">
              {suggestions.length} results — click to explore
            </div>
            {suggestions.map((s, i) => (
              <button
                key={s.attackId}
                type="button"
                onMouseDown={() => selectEntity(s.attackId, s.type)}
                className={`w-full flex items-center gap-3 px-4 py-2.5 hover:bg-[var(--teal-ghost)] transition-colors text-left ${i === 0 ? 'bg-[var(--hover-subtle)]' : ''}`}
              >
                <Badge
                  label={typeLabel(s.type)}
                  variant={TYPE_VARIANT[s.type] ?? 'neutral'}
                />
                {s.type !== 'sector' && (
                  <span className="font-mono text-xs text-[var(--accent-teal)] w-20 flex-shrink-0">{s.attackId}</span>
                )}
                <span className="text-sm text-[var(--text-primary)] truncate">{s.name}</span>
                {s.type !== 'group' && s.domain && (
                  <span className="text-[9px] font-medium text-[var(--text-secondary)] uppercase shrink-0">
                    {s.domain.replace('-attack', '').replace('enterprise', 'ent')}
                  </span>
                )}
              </button>
            ))}
          </div>
        )}

        {showSuggestions && searchInput.length >= 2 && suggestions.length === 0 && (
          <div className="absolute top-full w-full z-50 bg-[var(--surface-card)] border border-t-0 border-[var(--accent-teal)] rounded-b-lg shadow-2xl p-4 text-center text-sm text-[var(--text-secondary)]">
            No results for &ldquo;{searchInput}&rdquo;
          </div>
        )}
      </div>

      {/* Instructions when nothing selected */}
      {!selectedId && (
        <div className="flex items-center justify-center h-[500px] text-center">
          <div>
            <svg
              className="w-12 h-12 text-[var(--text-secondary)] mx-auto mb-4"
              fill="none"
              stroke="currentColor"
              strokeWidth={1.5}
              viewBox="0 0 24 24"
              aria-hidden="true"
            >
              <path strokeLinecap="round" strokeLinejoin="round" d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z" />
            </svg>
            <div className="text-4xl font-light text-[var(--text-secondary)] mb-3">
              Select an entity
            </div>
            <p className="text-sm text-[var(--text-secondary)] max-w-sm">
              Search for any technique, group, software, mitigation, data source, or tactic to explore
              its relationships across dedicated map views and the graph.
            </p>
          </div>
        </div>
      )}

      {/* Loading */}
      {selectedId && isLoading && (
        <div className="flex items-center justify-center h-20 text-[var(--text-secondary)]">
          <span className="inline-block w-5 h-5 border-2 border-[var(--teal-dim)] border-t-[var(--accent-teal)] rounded-full animate-spin mr-2" />
          Loading...
        </div>
      )}

      {/* Error — only show for graph-backed entities, not sectors */}
      {selectedId && error && !isSector && (
        <div className="flex items-center justify-center h-20 text-[var(--accent-orange)]">
          Failed to load relationships.
        </div>
      )}

      {/* Tab bar — shown once entity is selected and data is ready */}
      {selectedId && graphReady && (
        <div className="border-b border-[var(--border-color)]">
          <div className="flex gap-1">
            {visibleTabs.map((tab) => (
              <button
                key={tab.id}
                type="button"
                onClick={() => selectTab(tab.id)}
                className={`
                  px-4 py-2 text-sm font-medium whitespace-nowrap transition-colors duration-150
                  border-b-2 -mb-px
                  ${activeTab === tab.id
                    ? 'text-[var(--accent-teal)] border-[var(--accent-teal)]'
                    : 'text-[var(--text-secondary)] border-transparent hover:text-[var(--text-primary)]'
                  }
                `}
              >
                {tab.label}
              </button>
            ))}
          </div>
        </div>
      )}

      {/* Tab content */}
      {selectedId && graphReady && (
        <div>
          {/* Graph tab */}
          {activeTab === 'graph' && effectiveGraphData && (
            <div className="space-y-3">
              {/* Stats bar */}
              <div className="flex items-center gap-4 text-xs text-[var(--text-secondary)]">
                <span>
                  <span className="text-[var(--text-primary)] font-medium">{effectiveGraphData.nodes.length}</span> nodes
                </span>
                <span>
                  <span className="text-[var(--text-primary)] font-medium">{effectiveGraphData.edges.length}</span> edges
                </span>
                {effectiveGraphData.truncated && (
                  <Badge label="Truncated — too many connections" variant="yellow" />
                )}
                <button
                  type="button"
                  onClick={() => graphRef.current?.reset()}
                  className="ml-auto px-3 py-1 text-xs rounded-md border border-[var(--teal-dim)] text-[var(--accent-teal)] bg-[var(--teal-ghost)] hover:bg-[var(--teal-faint)] transition-colors"
                >
                  Re-layout
                </button>
              </div>

              <ForceGraph
                ref={graphRef}
                data={effectiveGraphData!}
                onNodeClick={handleNodeClick}
                height={800}
              />

              {/* Legend */}
              <div className="flex flex-wrap items-center gap-2 pt-2">
                <span className="text-xs text-[var(--text-secondary)] font-semibold mr-1">Node types:</span>
                {Object.entries(TYPE_VARIANT).map(([type, variant]) => (
                  <Badge
                    key={type}
                    label={typeLabel(type)}
                    variant={variant}
                  />
                ))}
              </div>
            </div>
          )}

          {/* Actor Profile tab */}
          {activeTab === 'actor' && entityType && (entityType === 'group' || entityType === 'campaign' || entityType === 'external_actor') && (
            <ActorProfileView attackId={selectedId} entityType={entityType as 'group' | 'campaign' | 'external_actor'} />
          )}

          {/* Technique Map tab */}
          {activeTab === 'technique-map' && entityType === 'technique' && (
            <TechniqueMapView attackId={selectedId} />
          )}

          {/* Software Map tab */}
          {activeTab === 'software-map' && entityType === 'software' && (
            <SoftwareMapView attackId={selectedId} />
          )}

          {/* Mitigation Map tab */}
          {activeTab === 'mitigation-map' && entityType === 'mitigation' && (
            <MitigationMapView attackId={selectedId} />
          )}

          {/* Data Source Map tab */}
          {activeTab === 'data-source-map' && entityType === 'data_source' && (
            <DataSourceMapView attackId={selectedId} />
          )}

          {/* Tactic Map tab */}
          {activeTab === 'tactic-map' && entityType === 'tactic' && (
            <TacticMapView attackId={selectedId} />
          )}

          {/* Sector Map tab */}
          {activeTab === 'sector-map' && entityType === 'sector' && (
            <SectorMapView sectorSlug={selectedId} />
          )}
        </div>
      )}
    </div>
  );
}
