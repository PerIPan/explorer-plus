import { useState, useCallback, useRef, useEffect, useMemo } from 'react';
import { useSearchParams, useNavigate } from 'react-router-dom';
import { useQuery } from '@tanstack/react-query';
import Fuse from 'fuse.js';
import { useRelationships } from '../hooks/useApi';
import { apiFetch } from '../lib/api';
import { useDomain } from '../contexts/DomainContext';
import { PageHeader } from '../components/layout/PageHeader';
import dynamic from 'next/dynamic';
import type { ForceGraphHandle } from '../components/graph/ForceGraph';

const ForceGraph = dynamic(
  () => import('../components/graph/ForceGraph').then(m => ({ default: m.ForceGraph })),
  { ssr: false }
);
import { Badge } from '../components/shared/Badge';
import { ActorProfileView } from '../components/relationships/ActorProfileView';
import { TechniqueMapView } from '../components/relationships/TechniqueMapView';
import { SoftwareMapView } from '../components/relationships/SoftwareMapView';
import { MitigationMapView } from '../components/relationships/MitigationMapView';
import { DataSourceMapView } from '../components/relationships/DataSourceMapView';
import { TacticMapView } from '../components/relationships/TacticMapView';
import { SectorMapView } from '../components/relationships/SectorMapView';
import { ApplicationMapView } from '../components/relationships/ApplicationMapView';
import { OwaspMapView } from '../components/relationships/OwaspMapView';
import type { GraphNode, GraphData } from '../lib/types';
import { DiamondLoader } from '../components/shared/FoldingDiamond';

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
  data_source: 'neutral',
  tactic: 'yellow',
  external_actor: 'neutral',
  sector: 'neutral',
  application: 'blue',
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

type TabId = 'graph' | 'actor' | 'technique-map' | 'software-map' | 'mitigation-map' | 'data-source-map' | 'tactic-map' | 'sector-map' | 'application-map' | 'owasp-map';

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
  { id: 'application-map', label: 'Application Map', forTypes: ['application'] },
  { id: 'owasp-map', label: 'OWASP Map', forTypes: ['owasp'] },
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
  application: 'application-map',
  owasp: 'owasp-map',
};

const TAB_TYPE_HINT: Record<string, string> = { 'sector-map': 'sector', 'application-map': 'application', 'owasp-map': 'owasp' };

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

  const navigate = useNavigate();
  const { domain } = useDomain();
  const [searchParams, setSearchParams] = useSearchParams();
  const entityParam = searchParams.get('entity') ?? '';
  const tabParam = (searchParams.get('tab') ?? 'graph') as TabId;

  const [selectedId, setSelectedId] = useState<string>(entityParam);
  const [selectedName, setSelectedName] = useState<string>(entityParam);
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
      setSelectedName(entityParam);
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
    (tabParam === 'sector-map' || tabParam === 'application-map' || tabParam === 'owasp-map' || !selectedId) ? '' : selectedId,
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

  /** Fuzzy search — instant, client-side, filtered by active domain */
  const suggestions = useMemo(() => {
    if (!fuse || !searchInput.trim() || searchInput.trim().length < 2) return [];
    const results = fuse.search(searchInput.trim(), { limit: 30 }).map(r => r.item);
    if (domain === 'all') return results.slice(0, 12);
    // Filter by domain: include entities matching the active domain + domain-agnostic entities (groups, sectors, apps, external actors)
    return results
      .filter(s => !s.domain || s.domain === domain || ['group', 'sector', 'application', 'external_actor', 'owasp'].includes(s.type))
      .slice(0, 12);
  }, [fuse, searchInput, domain]);

  // Infer entity type from graph center or suggestions; fall back to tab hint for non-graph entities
  const entityType = inferEntityType(graphData?.center, suggestions, selectedId)
    ?? TAB_TYPE_HINT[tabParam]
    ?? null;

  const isSector = entityType === 'sector';
  const isNonGraphEntity = isSector || entityType === 'application' || entityType === 'owasp';

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

  /** Application graph — build from application detail API */
  const isApp = entityType === 'application';
  const { data: appDetail } = useQuery({
    queryKey: ['application-detail', selectedId],
    queryFn: () => apiFetch<{
      vendor: string; product: string;
      techniques: Array<{ attackId: string; name: string }>;
      groups: Array<{ attackId: string; name: string }>;
    }>(`/applications/${selectedId}`),
    enabled: isApp && Boolean(selectedId),
    staleTime: 2 * 60 * 1000,
  });

  // Resolve display name for non-graph entities when API data arrives
  useEffect(() => {
    if (isApp && appDetail) {
      const name = `${appDetail.vendor} / ${appDetail.product}`;
      setSelectedName(name);
      setSearchInput(name);
    }
  }, [isApp, appDetail]);
  useEffect(() => {
    if (isSector && sectorRel) {
      setSelectedName(sectorRel.name);
      setSearchInput(sectorRel.name);
    }
  }, [isSector, sectorRel]);

  const appGraphData = useMemo<GraphData | null>(() => {
    if (!isApp || !appDetail) return null;
    const label = `${appDetail.vendor} / ${appDetail.product}`;
    const center: GraphNode = { id: selectedId, label, type: 'application', attackId: selectedId };
    const nodes: GraphNode[] = [];
    const edges: GraphData['edges'] = [];
    for (const t of appDetail.techniques.slice(0, 30)) {
      nodes.push({ id: t.attackId, label: t.name, type: 'technique', attackId: t.attackId });
      edges.push({ source: selectedId, target: t.attackId, relationship: 'exploits' });
    }
    for (const g of appDetail.groups.slice(0, 30)) {
      nodes.push({ id: g.attackId, label: g.name, type: 'group', attackId: g.attackId });
      edges.push({ source: selectedId, target: g.attackId, relationship: 'targeted_by' });
    }
    return { center, nodes, edges, truncated: appDetail.techniques.length > 30 || appDetail.groups.length > 30 };
  }, [isApp, appDetail, selectedId]);

  const effectiveGraphData = isSector ? sectorGraphData : isApp ? appGraphData : graphData;
  const isOwasp = entityType === 'owasp';
  const graphReady = isOwasp ? true : isNonGraphEntity ? Boolean(isSector ? sectorGraphData : appGraphData) : (!isLoading && !error && Boolean(graphData));

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
    (attackId: string, knownType?: string, name?: string) => {
      setSelectedId(attackId);
      setSelectedName(name ?? attackId);
      setSearchInput(name ?? attackId);
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
    if (node.attackId) selectEntity(node.attackId, node.type, node.label);
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
      <div className="relative w-full max-w-2xl" ref={containerRef}>
        <div className={`flex items-center gap-2 px-4 py-2.5 rounded-lg bg-[var(--surface-card)] border transition-colors ${showSuggestions && suggestions.length > 0 ? 'border-[var(--accent-teal)] rounded-b-none' : 'border-[var(--border-color)]'} focus-within:border-[var(--accent-teal)]`}>
          <svg className="w-4 h-4 text-[var(--text-secondary)] flex-shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z" />
          </svg>
          {selectedId && !showSuggestions && (graphData?.center || isNonGraphEntity) && entityType && (
            <Badge
              label={typeLabel(graphData?.center?.type ?? entityType)}
              variant={TYPE_VARIANT[graphData?.center?.type ?? entityType] ?? 'neutral'}
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
                if (!searchInput && selectedId) {
                  setSearchInput(selectedName || graphData?.center?.label || selectedId);
                }
              }, 200);
            }}
            onKeyDown={(e) => {
              if (e.key === 'Escape') {
                setShowSuggestions(false);
                (e.target as HTMLInputElement).blur();
              }
              if (e.key === 'Enter' && suggestions.length > 0) {
                selectEntity(suggestions[0].attackId, suggestions[0].type, suggestions[0].name);
              }
            }}
            placeholder={selectedId ? 'Search for another entity...' : 'Phishing, APT29, PowerShell, T1059, Linux 7...'}
            className="flex-1 bg-transparent text-[16px] md:text-sm text-[var(--text-primary)] placeholder-[var(--text-secondary)] focus:outline-none"
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
                onMouseDown={() => selectEntity(s.attackId, s.type, s.name)}
                className={`w-full flex items-center gap-3 px-4 py-2.5 hover:bg-[var(--teal-ghost)] transition-colors text-left ${i === 0 ? 'bg-[var(--hover-subtle)]' : ''}`}
              >
                <Badge
                  label={typeLabel(s.type)}
                  variant={TYPE_VARIANT[s.type] ?? 'neutral'}
                />
                {s.type !== 'sector' && s.type !== 'application' && (
                  <span className="font-mono text-xs text-[var(--accent-teal)] w-20 flex-shrink-0">{s.attackId}</span>
                )}
                <span className="text-sm text-[var(--text-primary)] truncate">{s.name}</span>
                {s.type !== 'group' && s.domain && (
                  <Badge label={s.domain.replace('-attack', '')} variant="neutral" />
                )}
              </button>
            ))}
          </div>
        )}

        {showSuggestions && searchInput.length >= 2 && suggestions.length === 0 && (
          <div className="absolute top-full w-full z-50 bg-[var(--surface-card)] border border-t-0 border-[var(--accent-teal)] rounded-b-lg shadow-2xl p-4 text-center text-sm text-[var(--text-secondary)]">
            No results for &ldquo;{searchInput}&rdquo;{domain !== 'all' && ` in ${domain.replace('-attack', '')} domain`}
          </div>
        )}
      </div>

      {/* Instructions when nothing selected */}
      {!selectedId && (
        <>
        <div className="text-center mt-10 md:mt-[74px] mb-2 max-w-2xl px-4">
          <div className="text-lg md:text-xl font-light text-[var(--text-secondary)] mb-1">
            Select an entity
          </div>
          <p className="text-xs md:text-sm text-[var(--text-secondary)] opacity-70 mx-auto max-w-md">
            Search for any Technique, Actor, Software, Campaign, Mitigation,
            Data Source, Tactic, Sector, Application, or OWASP category to explore its relationships.
          </p>
        </div>
        {/* Small centered diamond on mobile */}
        {/* Mobile diamond — centered below text, no labels */}
        <div className="flex md:hidden justify-center mt-12 opacity-40 pointer-events-none">
          <img src="/diamond-favicon.svg" alt="" width={140} height={140} />
        </div>

        <div className="relative h-[calc(100vh-420px)] overflow-hidden rounded-lg hidden md:block">

          {/* Diamond + corner labels — desktop only */}
          <div className="absolute bottom-[calc(10%+80px)] right-[22%] pointer-events-none select-none"
               style={{ width: 210, height: 210 }}>
            <img src="/diamond-favicon.svg" alt="" width={210} height={210} className="opacity-[0.55]" />

            {/* Labels at diamond corners */}
            <div className="absolute -top-10 left-1/2 -translate-x-1/2 text-center">
              <div className="text-xs font-medium text-[var(--accent-orange)] opacity-50">actor</div>
              <div className="text-xs font-medium text-[var(--accent-orange)] opacity-50">adversary</div>
            </div>
            <div className="absolute -bottom-10 left-1/2 -translate-x-1/2 text-center">
              <div className="text-xs font-medium text-[var(--text-secondary)] opacity-50">sector</div>
              <div className="text-xs font-medium text-[var(--text-secondary)] opacity-50">victim</div>
            </div>
            <div className="absolute top-1/2 -left-20 -translate-y-1/2 text-right">
              <div className="text-xs font-medium text-[var(--accent-teal)] opacity-50">technique</div>
              <div className="text-xs font-medium text-[var(--accent-teal)] opacity-50">capability</div>
            </div>
            <div className="absolute top-1/2 -right-24 -translate-y-1/2 text-center">
              <div className="text-xs font-medium text-[var(--accent-blue)] opacity-50">application</div>
              <div className="text-xs font-medium text-[var(--accent-blue)] opacity-50">infrastructure</div>
            </div>
          </div>
        </div>
        </>
      )}

      {/* Loading */}
      {selectedId && !isNonGraphEntity && isLoading && (
        <DiamondLoader text="Loading..." />
      )}

      {/* Error — only show for graph-backed entities, not sectors */}
      {selectedId && error && !isNonGraphEntity && (
        <div className="flex items-center justify-center h-20 text-[var(--accent-orange)]">
          Failed to load relationships.
        </div>
      )}

      {/* Tab bar — shown once entity is selected and data is ready */}
      {selectedId && graphReady && (
        <div className="border-b border-[var(--border-color)] overflow-x-auto">
          <div className="flex gap-1 min-w-max">
            {visibleTabs.map((tab) => (
              <button
                key={tab.id}
                type="button"
                onClick={() => selectTab(tab.id)}
                className={`
                  px-3 md:px-4 py-3 text-sm font-medium whitespace-nowrap transition-colors duration-150
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
            {entityType && entityType !== 'technique' && (
              <button
                type="button"
                onClick={() => {
                  if (entityType === 'group') {
                    navigate(`/matrix?actor=${selectedId}`);
                  } else {
                    navigate(`/matrix?type=${entityType}&entity=${encodeURIComponent(selectedId)}&label=${encodeURIComponent(selectedName || selectedId)}`);
                  }
                }}
                className="px-4 py-2 text-sm font-medium whitespace-nowrap transition-colors duration-150 border-b-2 -mb-px text-[var(--text-secondary)] border-transparent hover:text-[var(--text-primary)]"
              >
                Matrix ↗
              </button>
            )}
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
                height={typeof window !== 'undefined' ? Math.min(800, window.innerHeight - 200) : 600}
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

          {/* Application Map tab */}
          {activeTab === 'application-map' && entityType === 'application' && (
            <ApplicationMapView appSlug={selectedId} />
          )}

          {/* OWASP Map tab */}
          {activeTab === 'owasp-map' && entityType === 'owasp' && (
            <OwaspMapView categoryId={selectedId} />
          )}
        </div>
      )}
    </div>
  );
}
