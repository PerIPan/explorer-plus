'use client';
import { useState, useCallback, useRef, useEffect, useMemo } from 'react';
import { useSearchParams, useRouter } from 'next/navigation';
import { useUpdateParams } from '../hooks/useUpdateParams';
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
import { RecentAffectedCard } from '../components/home/RecentAffectedCard';
import { RecentReportsCard } from '../components/home/RecentReportsCard';
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
  owasp: 'green',
  cwe: 'blue',
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
  { id: 'software-map', label: 'Malware Map', forTypes: ['software'] },
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

/** OWASP category ID pattern — A01, ML01, LLM01, etc. */
const OWASP_ID_RE = /^(A|ML|LLM)\d{2}$/i;
function isOwaspId(id: string): boolean {
  return OWASP_ID_RE.test(id);
}

/** Application slug pattern — `<vendor>/<product>`. Matches the URL shape used
 *  by /applications/[...slug] routes. Applications are the only entity type
 *  whose selectedId contains a '/', so this is a safe discriminator. */
const APP_SLUG_RE = /^[a-z0-9][a-z0-9._-]*\/[a-z0-9][a-z0-9._-]*$/i;
function isApplicationSlug(id: string): boolean {
  return APP_SLUG_RE.test(id);
}

/** Derive the entity type from the graph center node or from search suggestions */
function inferEntityType(
  graphCenter: GraphNode | undefined,
  suggestions: Array<{ attackId: string; type: string }>,
  selectedId: string,
): string | null {
  if (graphCenter?.type) return graphCenter.type;
  if (isOwaspId(selectedId)) return 'owasp';
  // Application slugs may not appear in /entities (capped at ~500 for Fuse),
  // so we need a direct pattern check for direct-URL loads to work.
  if (isApplicationSlug(selectedId)) return 'application';
  const match = suggestions.find((s) => s.attackId === selectedId);
  return match?.type ?? null;
}

// ── Page component ─────────────────────────────────────────────────────────────

// The desktop diamond hero is kept (it took effort) but hidden for now — there
// isn't enough empty space above the landing tables to place it without pushing
// content down. Flip to true to re-enable, or swap in a static image later.
const SHOW_DESKTOP_DIAMOND = false;

export function Relationships() {

  const router = useRouter();
  const { domain } = useDomain();
  const searchParams = useSearchParams();
  const updateParams = useUpdateParams();
  const entityParam = searchParams.get('entity') ?? '';
  const tabParam = (searchParams.get('tab') ?? 'graph') as TabId;

  const [selectedId, setSelectedId] = useState<string>(entityParam);
  const [selectedName, setSelectedName] = useState<string>(entityParam);
  const [searchInput, setSearchInput] = useState(entityParam);
  const [showSuggestions, setShowSuggestions] = useState(false);
  const [activeTab, setActiveTab] = useState<TabId>(tabParam);
  const graphRef = useRef<ForceGraphHandle>(null);
  const containerRef = useRef<HTMLDivElement>(null);
  const inputRef = useRef<HTMLInputElement>(null);
  const blurTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null);

  /** Autofocus the search input on landing (nothing selected yet). Skip on
   *  touch devices so we don't pop the keyboard. */
  useEffect(() => {
    if (entityParam) return;
    const isTouch = typeof window !== 'undefined' && window.matchMedia?.('(hover: none)').matches;
    if (isTouch) return;
    inputRef.current?.focus({ preventScroll: true });
  }, [entityParam]);

  // SSR-safe viewport height sampler. Direct `window.innerHeight` during render
  // would throw ReferenceError on the server.
  const [viewportHeight, setViewportHeight] = useState(900);
  useEffect(() => {
    const update = () => setViewportHeight(window.innerHeight);
    update();
    window.addEventListener('resize', update);
    return () => window.removeEventListener('resize', update);
  }, []);

  /** Keep selectedId in sync with URL param */
  useEffect(() => {
    if (entityParam && entityParam !== selectedId) {
      setSelectedId(entityParam);
      setSelectedName(entityParam);
      setSearchInput(entityParam);
    }
  }, [entityParam, selectedId]);

  /** Keep tab in sync with URL param */
  useEffect(() => {
    if (tabParam && tabParam !== activeTab) {
      setActiveTab(tabParam);
    }
  }, [tabParam, activeTab]);

  /** Clear blur timer on unmount */
  useEffect(() => {
    return () => {
      if (blurTimerRef.current !== null) clearTimeout(blurTimerRef.current);
    };
  }, []);

  const { data: graphData, isLoading, error } = useRelationships(
    (tabParam === 'sector-map' || tabParam === 'application-map' || tabParam === 'owasp-map' || isOwaspId(selectedId) || isApplicationSlug(selectedId) || !selectedId) ? '' : selectedId,
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

  // Infer entity type from graph center or suggestions; fall back to tab hint for non-graph entities.
  // Tab hint takes PRIORITY over suggestion matches — otherwise typing in the search box
  // while viewing a framework entity would flip entityType and unmount the view mid-session.
  const tabHintType = TAB_TYPE_HINT[tabParam] ?? null;
  const entityType = tabHintType
    ?? inferEntityType(graphData?.center, suggestions, selectedId)
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

  /** OWASP graph — build from OWASP category detail API */
  const isOwasp = entityType === 'owasp';
  const { data: owaspDetail } = useQuery({
    queryKey: ['owasp-detail', selectedId],
    queryFn: () => apiFetch<{
      categoryId: string;
      name: string;
      framework: string;
      cwes: string[];
      techniques: Array<{ attackId: string; name: string; cweId: string }>;
      atlasTechniques: Array<{ attackId: string; name: string }>;
      relatedCategories: Array<{ categoryId: string; name: string; framework: string }>;
      applications: Array<{ normalized: string; vendor: string; product: string; cveCount: number }>;
    }>(`/frameworks/owasp/${selectedId}`),
    enabled: isOwasp && Boolean(selectedId),
    staleTime: 5 * 60 * 1000,
  });

  // Resolve display name for OWASP entities when detail arrives
  useEffect(() => {
    if (isOwasp && owaspDetail) {
      setSelectedName(owaspDetail.name);
      setSearchInput(owaspDetail.name);
    }
  }, [isOwasp, owaspDetail]);

  const owaspGraphData = useMemo<GraphData | null>(() => {
    if (!isOwasp || !owaspDetail) return null;
    const center: GraphNode = {
      id: selectedId,
      label: `${owaspDetail.categoryId}: ${owaspDetail.name}`,
      type: 'owasp',
      attackId: selectedId,
    };
    const nodes: GraphNode[] = [];
    const edges: GraphData['edges'] = [];

    // Dedup technique attackIds across ATT&CK + ATLAS
    const seen = new Set<string>();
    for (const t of owaspDetail.techniques) {
      if (seen.has(t.attackId)) continue;
      seen.add(t.attackId);
      nodes.push({ id: t.attackId, label: t.name, type: 'technique', attackId: t.attackId });
      edges.push({ source: selectedId, target: t.attackId, relationship: 'maps_to' });
    }
    for (const t of owaspDetail.atlasTechniques) {
      if (seen.has(t.attackId)) continue;
      seen.add(t.attackId);
      nodes.push({ id: t.attackId, label: t.name, type: 'technique', attackId: t.attackId });
      edges.push({ source: selectedId, target: t.attackId, relationship: 'maps_to' });
    }
    // Affected applications (cap 20 — CVEs/CWEs omitted to keep graph readable)
    for (const a of owaspDetail.applications.slice(0, 20)) {
      const appId = a.normalized;
      if (seen.has(appId)) continue;
      seen.add(appId);
      nodes.push({
        id: appId,
        label: `${a.vendor} / ${a.product}`,
        type: 'application',
        attackId: appId,
      });
      edges.push({ source: selectedId, target: appId, relationship: 'affects' });
    }
    // Related OWASP categories across frameworks
    for (const rc of owaspDetail.relatedCategories) {
      if (seen.has(rc.categoryId)) continue;
      seen.add(rc.categoryId);
      nodes.push({ id: rc.categoryId, label: rc.name, type: 'owasp', attackId: rc.categoryId });
      edges.push({ source: selectedId, target: rc.categoryId, relationship: 'related' });
    }

    return {
      center,
      nodes,
      edges,
      truncated: owaspDetail.applications.length > 20,
    };
  }, [isOwasp, owaspDetail, selectedId]);

  const effectiveGraphData = isSector
    ? sectorGraphData
    : isApp
      ? appGraphData
      : isOwasp
        ? owaspGraphData
        : graphData;
  const graphReady = isOwasp
    ? Boolean(owaspGraphData)
    : isNonGraphEntity
      ? Boolean(isSector ? sectorGraphData : appGraphData)
      : (!isLoading && !error && Boolean(graphData));

  /** Determine which tabs are visible for the current entity */
  const visibleTabs = useMemo(
    () =>
      TABS.filter(
        (tab) => !tab.forTypes || (entityType && tab.forTypes.includes(entityType)),
      ),
    [entityType],
  );

  /** When entity type changes, auto-select the best tab (unless URL explicitly set one) */
  useEffect(() => {
    // Don't override if URL has an explicit tab and entity data hasn't loaded yet
    if (tabParam && !entityType) return;
    const isVisible = visibleTabs.some((t) => t.id === activeTab);
    if (!isVisible && visibleTabs.length > 0) {
      const bestTab = visibleTabs[0]?.id ?? 'graph';
      setActiveTab(bestTab);
      updateParams({ tab: bestTab });
    }
  }, [entityType, activeTab, tabParam, visibleTabs, updateParams]);

  const selectEntity = useCallback(
    (attackId: string, knownType?: string, name?: string) => {
      setSelectedId(attackId);
      setSelectedName(name ?? attackId);
      setSearchInput(name ?? attackId);
      setShowSuggestions(false);

      // Immediately pick the best tab based on known type
      const bestTab: TabId = (knownType && TAB_FOR_TYPE[knownType]) || 'graph';
      setActiveTab(bestTab);

      updateParams({ entity: attackId, tab: bestTab });
    },
    [updateParams]
  );

  const selectTab = useCallback(
    (tabId: TabId) => {
      setActiveTab(tabId);
      updateParams({ tab: tabId });
    },
    [updateParams]
  );

  const handleNodeClick = useCallback((node: GraphNode) => {
    if (node.attackId) selectEntity(node.attackId, node.type, node.label);
  }, [selectEntity]);

  return (
    <div className="space-y-4">
      <PageHeader
        title="Diamond Entities"
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

      {/* Entity search — combobox with autocomplete dropdown.
          When nothing is selected (landing state), the bar is sized up on
          desktop and gets a subtle teal glow to signal it's the entry point. */}
      <div className={`relative w-full max-w-2xl ${!selectedId ? 'md:max-w-3xl' : ''}`} ref={containerRef}>
        <div className={`flex items-center gap-2 px-4 py-2.5 ${!selectedId ? 'md:px-5 md:py-3' : ''} rounded-lg bg-[var(--surface-card)] border transition-all ${showSuggestions && suggestions.length > 0 ? 'border-[var(--accent-teal)] rounded-b-none' : 'border-[var(--border-color)]'} focus-within:border-[var(--accent-teal)] focus-within:md:shadow-[0_0_0_3px_var(--teal-ghost)]`}>
          <svg className={`${!selectedId ? 'w-4 h-4 md:w-[18px] md:h-[18px]' : 'w-4 h-4'} text-[var(--text-secondary)] flex-shrink-0`} fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z" />
          </svg>
          {selectedId && !showSuggestions && (graphData?.center || isNonGraphEntity) && entityType && (
            <Badge
              label={typeLabel(graphData?.center?.type ?? entityType)}
              variant={TYPE_VARIANT[graphData?.center?.type ?? entityType] ?? 'neutral'}
            />
          )}
          <input
            ref={inputRef}
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
            className={`flex-1 bg-transparent text-[16px] ${!selectedId ? 'md:text-base' : 'md:text-sm'} text-[var(--text-primary)] placeholder-[var(--text-secondary)] ${!selectedId ? 'placeholder:opacity-50' : ''} focus:outline-none`}
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
          {!selectedId && !searchInput && (
            <span
              aria-hidden="true"
              className="hidden md:inline-flex items-center gap-1 flex-shrink-0 text-[10px] font-semibold uppercase tracking-[0.2em] text-[var(--accent-teal)] pointer-events-none"
            >
              <span className="inline-block animate-start-here-wiggle">←</span>
              <span>Start here</span>
            </span>
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
                  <Badge
                    label={(Array.isArray(s.domain) ? s.domain : [s.domain as unknown as string])
                      .map((d: string) => d.replace('-attack', '')).join(', ')}
                    variant="neutral"
                  />
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
        <div className="mt-8 md:mt-12">
          <p className="text-sm md:text-base text-[var(--text-secondary)] leading-relaxed mb-12 md:mb-16">
            Search for any{' '}
            <span className="font-medium text-[var(--text-primary)]">Technique</span>,{' '}
            <span className="font-medium text-[var(--text-primary)]">Actor</span>,{' '}
            <span className="font-medium text-[var(--text-primary)]">Malware</span>,{' '}
            <span className="font-medium text-[var(--text-primary)]">Campaign</span>,{' '}
            <span className="font-medium text-[var(--text-primary)]">Mitigation</span>,{' '}
            <span className="font-medium text-[var(--text-primary)]">Tactic</span>,{' '}
            <span className="font-medium text-[var(--text-primary)]">Sector</span>,{' '}
            <span className="font-medium text-[var(--text-primary)]">Application</span>, or{' '}
            <span className="font-medium text-[var(--text-primary)]">OWASP category</span>{' '}
            to explore its relationships.
          </p>

          {/* Latest CTI reports — full width above the affected tables */}
          <RecentReportsCard />

          {/* Recently affected Applications + Packages — last 10 days */}
          <RecentAffectedCard />

          {/* Diamond — desktop with labels. Kept but hidden (SHOW_DESKTOP_DIAMOND). */}
          {SHOW_DESKTOP_DIAMOND && (
          <div className="hidden md:flex justify-center pt-24 pb-16 pointer-events-none select-none">
            <div className="relative" style={{ width: 210, height: 210 }}>
              <img src="/diamond-favicon.svg" alt="" width={210} height={210} className="opacity-[0.55]" />

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
          )}

          {/* Mobile diamond — with labels */}
          <div className="flex md:hidden justify-center mt-10 pb-10 pointer-events-none select-none">
            <div className="relative" style={{ width: 140, height: 140 }}>
              <img src="/diamond-favicon.svg" alt="" width={140} height={140} className="opacity-[0.55]" />

              <div className="absolute -top-8 left-1/2 -translate-x-1/2 text-center">
                <div className="text-[10px] font-medium text-[var(--accent-orange)] opacity-60 leading-tight">actor</div>
                <div className="text-[10px] font-medium text-[var(--accent-orange)] opacity-60 leading-tight">adversary</div>
              </div>
              <div className="absolute -bottom-8 left-1/2 -translate-x-1/2 text-center">
                <div className="text-[10px] font-medium text-[var(--text-secondary)] opacity-60 leading-tight">sector</div>
                <div className="text-[10px] font-medium text-[var(--text-secondary)] opacity-60 leading-tight">victim</div>
              </div>
              <div className="absolute top-1/2 -left-16 -translate-y-1/2 text-right">
                <div className="text-[10px] font-medium text-[var(--accent-teal)] opacity-60 leading-tight">technique</div>
                <div className="text-[10px] font-medium text-[var(--accent-teal)] opacity-60 leading-tight">capability</div>
              </div>
              <div className="absolute top-1/2 -right-[72px] -translate-y-1/2 text-left">
                <div className="text-[10px] font-medium text-[var(--accent-blue)] opacity-60 leading-tight">application</div>
                <div className="text-[10px] font-medium text-[var(--accent-blue)] opacity-60 leading-tight">infra</div>
              </div>
            </div>
          </div>
        </div>
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
          <div role="tablist" aria-label="Entity views" className="flex gap-1 min-w-max">
            {visibleTabs.map((tab) => {
              const isActive = activeTab === tab.id;
              return (
                <button
                  key={tab.id}
                  id={`rel-tab-${tab.id}`}
                  type="button"
                  role="tab"
                  aria-selected={isActive}
                  aria-controls={`rel-tabpanel-${tab.id}`}
                  tabIndex={isActive ? 0 : -1}
                  onClick={() => selectTab(tab.id)}
                  className={`
                    px-3 md:px-4 py-3 text-sm font-medium whitespace-nowrap transition-colors duration-150
                    border-b-2 -mb-px
                    ${isActive
                      ? 'text-[var(--accent-teal)] border-[var(--accent-teal)]'
                      : 'text-[var(--text-secondary)] border-transparent hover:text-[var(--text-primary)]'
                    }
                  `}
                >
                  {tab.label}
                </button>
              );
            })}
            {entityType && entityType !== 'technique' && (
              <button
                type="button"
                onClick={() => {
                  if (entityType === 'group') {
                    router.push(`/matrix?actor=${selectedId}`);
                  } else {
                    router.push(`/matrix?type=${entityType}&entity=${encodeURIComponent(selectedId)}&label=${encodeURIComponent(selectedName || selectedId)}`);
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
                height={Math.min(800, viewportHeight - 200)}
              />

              {/* Legend — data_source intentionally omitted from the landing surface */}
              <div className="flex flex-wrap items-center gap-2 pt-2">
                <span className="text-xs text-[var(--text-secondary)] font-semibold mr-1">Node types:</span>
                {Object.entries(TYPE_VARIANT)
                  .filter(([type]) => type !== 'data_source')
                  .map(([type, variant]) => (
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
