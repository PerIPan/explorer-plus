import { useState, useCallback, useRef, useEffect } from 'react';
import { useSearchParams } from 'react-router-dom';
import { useRelationships, useSearch } from '../hooks/useApi';
import { PageHeader } from '../components/layout/PageHeader';
import { ForceGraph, type ForceGraphHandle } from '../components/graph/ForceGraph';
import { Badge } from '../components/shared/Badge';
import type { GraphNode } from '../lib/types';

/** Entity type → badge variant */
const TYPE_VARIANT: Record<string, 'teal' | 'orange' | 'purple' | 'blue' | 'green' | 'pink' | 'yellow' | 'neutral'> = {
  technique: 'teal',
  group: 'orange',
  software: 'purple',
  campaign: 'blue',
  mitigation: 'green',
  data_source: 'pink',
  tactic: 'yellow',
};

export function Relationships() {
  const [searchParams, setSearchParams] = useSearchParams();
  const entityParam = searchParams.get('entity') ?? '';

  const [selectedId, setSelectedId] = useState<string>(entityParam);
  const [searchInput, setSearchInput] = useState(entityParam);
  const [showSuggestions, setShowSuggestions] = useState(false);
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

  const { data: graphData, isLoading, error } = useRelationships(selectedId);

  /** Search suggestions (reuse useSearch) */
  const { data: searchData } = useSearch(
    showSuggestions && searchInput.trim().length >= 3 ? searchInput : ''
  );

  const suggestions = [
    ...(searchData?.techniques ?? []).slice(0, 5).map((t) => ({
      attackId: t.attackId,
      name: t.name,
      type: 'technique',
    })),
    ...(searchData?.groups ?? []).slice(0, 5).map((g) => ({
      attackId: g.attackId,
      name: g.name,
      type: 'group',
    })),
    ...(searchData?.software ?? []).slice(0, 3).map((s) => ({
      attackId: s.attackId,
      name: s.name,
      type: 'software',
    })),
    ...(searchData?.campaigns ?? []).slice(0, 3).map((c) => ({
      attackId: c.attackId,
      name: c.name,
      type: 'campaign',
    })),
  ].slice(0, 12);

  const selectEntity = useCallback(
    (attackId: string) => {
      setSelectedId(attackId);
      setSearchInput(attackId);
      setShowSuggestions(false);
      setSearchParams((prev) => {
        const next = new URLSearchParams(prev);
        next.set('entity', attackId);
        return next;
      });
    },
    [setSearchParams]
  );

  const handleNodeClick = useCallback((node: GraphNode) => {
    if (node.attackId) selectEntity(node.attackId);
  }, [selectEntity]);

  return (
    <div className="space-y-4">
      <PageHeader
        title="Relationship Explorer"
        subtitle="D3 force graph — click a node to expand its connections"
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
                setSearchInput(graphData.center.name);
              }
            }, 200)}
            onKeyDown={(e) => {
              if (e.key === 'Escape') {
                setShowSuggestions(false);
                (e.target as HTMLInputElement).blur();
              }
              if (e.key === 'Enter' && suggestions.length > 0) {
                selectEntity(suggestions[0].attackId);
              }
            }}
            placeholder={selectedId ? 'Search for another entity...' : 'Type to search: APT29, PowerShell, T1059...'}
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
                onMouseDown={() => selectEntity(s.attackId)}
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

        {showSuggestions && searchInput.length >= 3 && suggestions.length === 0 && (
          <div className="absolute top-full w-full z-50 bg-[#16213e] border border-t-0 border-[#64ffda] rounded-b-lg shadow-2xl p-4 text-center text-sm text-[#8892b0]">
            No results for "{searchInput}"
          </div>
        )}
      </div>

      {/* Instructions when nothing selected */}
      {!selectedId && (
        <div className="flex items-center justify-center h-[500px] text-center">
          <div>
            {/* Search icon for visual anchoring */}
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
              Search for any technique, group, software, or campaign to visualize
              its relationships as a force-directed graph.
            </p>
          </div>
        </div>
      )}

      {/* Loading */}
      {selectedId && isLoading && (
        <div className="flex items-center justify-center h-[500px] text-[#8892b0]">
          <span className="inline-block w-5 h-5 border-2 border-[#64ffda33] border-t-[#64ffda] rounded-full animate-spin mr-2" />
          Loading graph...
        </div>
      )}

      {/* Error */}
      {selectedId && error && (
        <div className="flex items-center justify-center h-[500px] text-[#f97316]">
          Failed to load relationships.
        </div>
      )}

      {/* Graph */}
      {selectedId && !isLoading && !error && graphData && (
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
              className="ml-auto text-xs text-[#64ffda] hover:underline"
            >
              Re-layout
            </button>
          </div>

          <ForceGraph
            ref={graphRef}
            data={graphData}
            onNodeClick={handleNodeClick}
            height={580}
          />

          {/* Legend */}
          <div className="flex flex-wrap gap-2 pt-2">
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
    </div>
  );
}
