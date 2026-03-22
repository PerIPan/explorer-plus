import { useState, useCallback, useRef, useEffect, useMemo } from 'react';
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
import type { GraphNode } from '../lib/types';

interface EntityEntry {
  attackId: string;
  name: string;
  type: string;
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
};

// ── Tab definitions ────────────────────────────────────────────────────────────

type TabId = 'graph' | 'actor' | 'technique-map';

interface TabDef {
  id: TabId;
  label: string;
  /** Which entity types show this tab. Undefined means always visible. */
  forTypes?: string[];
}

const TABS: TabDef[] = [
  { id: 'actor', label: 'Threat Actor Profile', forTypes: ['group', 'campaign', 'external_actor'] },
  { id: 'technique-map', label: 'Technique Map', forTypes: ['technique'] },
  { id: 'graph', label: 'Graph' },
];

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
  const [searchParams, setSearchParams] = useSearchParams();
  const entityParam = searchParams.get('entity') ?? '';
  const tabParam = (searchParams.get('tab') ?? 'graph') as TabId;

  const [selectedId, setSelectedId] = useState<string>(entityParam);
  const [searchInput, setSearchInput] = useState(entityParam);
  const [showSuggestions, setShowSuggestions] = useState(false);
  const [activeTab, setActiveTab] = useState<TabId>(tabParam);
  const graphRef = useRef<ForceGraphHandle>(null);
  const containerRef = useRef<HTMLDivElement>(null);

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

  const { data: graphData, isLoading, error } = useRelationships(selectedId);

  /** Load all entity names once for Fuse.js fuzzy search */
  const { data: allEntities } = useQuery({
    queryKey: ['entities-all'],
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

  const entityType = inferEntityType(graphData?.center, suggestions, selectedId);

  /** Determine which tabs are visible for the current entity */
  const visibleTabs = TABS.filter(
    (tab) => !tab.forTypes || (entityType && tab.forTypes.includes(entityType))
  );

  /** When entity type changes, auto-select the best tab */
  useEffect(() => {
    const isVisible = visibleTabs.some((t) => t.id === activeTab);
    if (!isVisible && visibleTabs.length > 0) {
      // Pick the first type-specific tab, or fall back to graph
      const bestTab = visibleTabs[0]?.id ?? 'graph';
      setActiveTab(bestTab);
      setSearchParams((prev) => {
        const next = new URLSearchParams(prev);
        next.set('tab', bestTab);
        return next;
      });
    }
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [entityType]);

  const selectEntity = useCallback(
    (attackId: string, knownType?: string) => {
      setSelectedId(attackId);
      setSearchInput(attackId);
      setShowSuggestions(false);

      // Immediately pick the best tab based on known type
      const bestTab: TabId = knownType === 'group' || knownType === 'campaign' || knownType === 'external_actor'
        ? 'actor'
        : knownType === 'technique'
          ? 'technique-map'
          : 'graph';
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
        title="Relationships Explorer"
        subtitle="Graph, Actor Profile, and Technique Map views — select an entity to start"
        actions={
          selectedId ? (
            <button
              type="button"
              data-print-hide
              onClick={() => window.print()}
              className="px-3 py-1.5 text-xs rounded-md border border-[#2a2a4a] text-[#8892b0] hover:text-[#64ffda] hover:border-[#64ffda33] transition-colors"
              title="Export current view as PDF (Ctrl+P)"
            >
              Export PDF
            </button>
          ) : undefined
        }
      />

      {/* Entity search — combobox with autocomplete dropdown */}
      <div className="relative max-w-2xl" ref={containerRef}>
        <div className={`flex items-center gap-2 px-4 py-2.5 rounded-lg bg-[#16213e] border transition-colors ${showSuggestions && suggestions.length > 0 ? 'border-[#64ffda] rounded-b-none' : 'border-[#2a2a4a]'} focus-within:border-[#64ffda]`}>
          <svg className="w-4 h-4 text-[#8892b0] flex-shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z" />
          </svg>
          {selectedId && !showSuggestions && graphData?.center && (
            <Badge
              label={graphData.center.type.replace('_', ' ')}
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
            onBlur={() => setTimeout(() => {
              setShowSuggestions(false);
              if (!searchInput && selectedId && graphData?.center) {
                setSearchInput(graphData?.center?.label ?? '');
              }
            }, 200)}
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
            className="flex-1 bg-transparent text-sm text-[#ccd6f6] placeholder-[#8892b0] focus:outline-none"
          />
          {searchInput && (
            <button
              type="button"
              onClick={() => { setSearchInput(''); setShowSuggestions(false); }}
              className="text-[#8892b0] hover:text-[#ccd6f6] text-xs"
            >
              Clear
            </button>
          )}
        </div>

        {showSuggestions && suggestions.length > 0 && (
          <div className="absolute top-full w-full z-50 bg-[#16213e] border border-t-0 border-[#64ffda] rounded-b-lg shadow-2xl overflow-hidden max-h-80 overflow-y-auto">
            <div className="px-3 py-1.5 text-[10px] uppercase tracking-wider text-[#8892b0] bg-[#0a0a1a]">
              {suggestions.length} results — click to explore
            </div>
            {suggestions.map((s, i) => (
              <button
                key={s.attackId}
                type="button"
                onMouseDown={() => selectEntity(s.attackId, s.type)}
                className={`w-full flex items-center gap-3 px-4 py-2.5 hover:bg-[#64ffda10] transition-colors text-left ${i === 0 ? 'bg-[#ffffff05]' : ''}`}
              >
                <Badge
                  label={s.type.replace('_', ' ')}
                  variant={TYPE_VARIANT[s.type] ?? 'neutral'}
                />
                <span className="font-mono text-xs text-[#64ffda] w-20 flex-shrink-0">{s.attackId}</span>
                <span className="text-sm text-[#ccd6f6] truncate">{s.name}</span>
              </button>
            ))}
          </div>
        )}

        {showSuggestions && searchInput.length >= 2 && suggestions.length === 0 && (
          <div className="absolute top-full w-full z-50 bg-[#16213e] border border-t-0 border-[#64ffda] rounded-b-lg shadow-2xl p-4 text-center text-sm text-[#8892b0]">
            No results for &ldquo;{searchInput}&rdquo;
          </div>
        )}
      </div>

      {/* Instructions when nothing selected */}
      {!selectedId && (
        <div className="flex items-center justify-center h-[500px] text-center">
          <div>
            <svg
              className="w-12 h-12 text-[#4a4a6a] mx-auto mb-4"
              fill="none"
              stroke="currentColor"
              strokeWidth={1.5}
              viewBox="0 0 24 24"
              aria-hidden="true"
            >
              <path strokeLinecap="round" strokeLinejoin="round" d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z" />
            </svg>
            <div className="text-4xl font-light text-[#4a4a6a] mb-3">
              Select an entity
            </div>
            <p className="text-sm text-[#8892b0] max-w-sm">
              Search for any technique, group, software, or campaign to explore
              its relationships across graph, actor profile, and technique map views.
            </p>
          </div>
        </div>
      )}

      {/* Loading */}
      {selectedId && isLoading && (
        <div className="flex items-center justify-center h-20 text-[#8892b0]">
          <span className="inline-block w-5 h-5 border-2 border-[#64ffda33] border-t-[#64ffda] rounded-full animate-spin mr-2" />
          Loading...
        </div>
      )}

      {/* Error */}
      {selectedId && error && (
        <div className="flex items-center justify-center h-20 text-[#f97316]">
          Failed to load relationships.
        </div>
      )}

      {/* Tab bar — shown once entity is selected and graph has loaded */}
      {selectedId && !isLoading && !error && graphData && (
        <div className="border-b border-[#2a2a4a]">
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
                    ? 'text-[#64ffda] border-[#64ffda]'
                    : 'text-[#8892b0] border-transparent hover:text-[#ccd6f6]'
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
      {selectedId && !isLoading && !error && graphData && (
        <div>
          {/* Graph tab */}
          {activeTab === 'graph' && (
            <div className="space-y-3">
              {/* Stats bar */}
              <div className="flex items-center gap-4 text-xs text-[#8892b0]">
                <span>
                  <span className="text-[#ccd6f6] font-medium">{graphData.nodes.length}</span> nodes
                </span>
                <span>
                  <span className="text-[#ccd6f6] font-medium">{graphData.edges.length}</span> edges
                </span>
                {graphData.truncated && (
                  <Badge label="Truncated — too many connections" variant="yellow" />
                )}
                <button
                  type="button"
                  onClick={() => graphRef.current?.reset()}
                  className="ml-auto px-3 py-1 text-xs rounded-md border border-[#64ffda33] text-[#64ffda] bg-[#64ffda0a] hover:bg-[#64ffda18] transition-colors"
                >
                  Re-layout
                </button>
              </div>

              <ForceGraph
                ref={graphRef}
                data={graphData}
                onNodeClick={handleNodeClick}
                height={800}
              />

              {/* Legend */}
              <div className="flex flex-wrap items-center gap-2 pt-2">
                <span className="text-xs text-[#8892b0] font-semibold mr-1">Node types:</span>
                {Object.entries(TYPE_VARIANT).map(([type, variant]) => (
                  <Badge
                    key={type}
                    label={type.replace('_', ' ')}
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
        </div>
      )}
    </div>
  );
}
