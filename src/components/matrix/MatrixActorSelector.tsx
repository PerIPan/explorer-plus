import { useState, useRef, useEffect, useMemo } from 'react';
import type { Group } from '../../lib/types';
import { useFuseFilter } from '../../hooks/useFuseFilter';

const ACTOR_COLORS = [
  { css: 'var(--accent-orange)', label: 'orange' },
  { css: 'var(--accent-purple)', label: 'purple' },
  { css: 'var(--accent-pink)', label: 'pink' },
];

interface SelectedActor {
  attackId: string;
  name: string;
  /** Stable color slot index assigned at selection time */
  colorIndex: number;
}

interface MatrixActorSelectorProps {
  groups: Group[];
  selected: SelectedActor[];
  onSelect: (actor: { attackId: string; name: string }) => void;
  onRemove: (attackId: string) => void;
  maxActors?: number;
}

export function MatrixActorSelector({ groups, selected, onSelect, onRemove, maxActors = 3 }: MatrixActorSelectorProps) {
  const [query, setQuery] = useState('');
  const [open, setOpen] = useState(false);
  const [highlightIdx, setHighlightIdx] = useState(0);
  const inputRef = useRef<HTMLInputElement>(null);
  const dropdownRef = useRef<HTMLDivElement>(null);

  const selectedIds = new Set(selected.map((a) => a.attackId));
  const atMax = selected.length >= maxActors;

  // Exclude already-selected groups before fuzzy search
  const availableGroups = useMemo(
    () => groups.filter((g) => !selectedIds.has(g.attackId)),
    [groups, selectedIds],
  );
  const FUSE_KEYS = ['name', 'aliases'];
  const fuseResults = useFuseFilter(availableGroups, FUSE_KEYS, query, { limit: 8, threshold: 0.3 });
  const filtered = query.trim().length >= 2 ? fuseResults.slice(0, 8) : [];

  useEffect(() => setHighlightIdx(0), [query]);

  useEffect(() => {
    const handler = (e: MouseEvent) => {
      if (dropdownRef.current && !dropdownRef.current.contains(e.target as Node)) setOpen(false);
    };
    document.addEventListener('mousedown', handler);
    return () => document.removeEventListener('mousedown', handler);
  }, []);

  function handleKeyDown(e: React.KeyboardEvent) {
    if (e.key === 'ArrowDown') { e.preventDefault(); setHighlightIdx((i) => filtered.length > 0 ? Math.min(i + 1, filtered.length - 1) : 0); }
    else if (e.key === 'ArrowUp') { e.preventDefault(); setHighlightIdx((i) => Math.max(i - 1, 0)); }
    else if (e.key === 'Enter' && filtered[highlightIdx]) { e.preventDefault(); selectActor(filtered[highlightIdx]); }
    else if (e.key === 'Escape') { setOpen(false); setQuery(''); }
    else if (e.key === 'Backspace' && query === '' && selected.length > 0) { onRemove(selected[selected.length - 1].attackId); }
  }

  function selectActor(g: Group) {
    onSelect({ attackId: g.attackId, name: g.name });
    setQuery('');
    setOpen(false);
    inputRef.current?.focus();
  }

  return (
    <div ref={dropdownRef} className="relative">
      <div className="flex items-center gap-1.5 flex-wrap">
        {selected.map((actor, i) => (
          <span
            key={actor.attackId}
            className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-[11px] font-medium border border-[var(--border-color)] bg-[var(--surface-card)]"
          >
            <span className="w-2 h-2 rounded-full shrink-0" style={{ backgroundColor: ACTOR_COLORS[actor.colorIndex].css }} />
            <span className="text-[var(--text-primary)] max-w-[120px] truncate">{actor.name}</span>
            <button
              type="button"
              onClick={() => onRemove(actor.attackId)}
              className="text-[var(--text-secondary)] hover:text-[var(--text-primary)] ml-0.5"
              aria-label={`Remove ${actor.name}`}
            >
              ×
            </button>
          </span>
        ))}
        <input
          ref={inputRef}
          type="text"
          placeholder={atMax ? 'Max 3 actors' : 'Compare actors\u2026'}
          disabled={atMax}
          value={query}
          onChange={(e) => { setQuery(e.target.value); setOpen(true); }}
          onFocus={() => { if (query.trim()) setOpen(true); }}
          onKeyDown={handleKeyDown}
          role="combobox"
          aria-expanded={open && filtered.length > 0}
          aria-autocomplete="list"
          aria-controls="actor-selector-listbox"
          aria-activedescendant={open && filtered[highlightIdx] ? `actor-option-${filtered[highlightIdx].attackId}` : undefined}
          className="w-[200px] px-3 py-1.5 rounded-md text-sm bg-[var(--surface-card)] border border-[var(--border-color)] text-[var(--text-primary)] placeholder-[var(--text-secondary)] focus:outline-none focus:border-[var(--accent-teal)] transition-colors disabled:opacity-50"
        />
      </div>

      {open && filtered.length > 0 && (
        <div id="actor-selector-listbox" role="listbox" aria-label="Threat actor suggestions" className="absolute top-full mt-1 right-0 w-64 bg-[var(--surface-card)] border border-[var(--border-color)] rounded-lg shadow-xl z-50 max-h-48 overflow-y-auto">
          {filtered.map((g, i) => (
            <button
              key={g.attackId}
              id={`actor-option-${g.attackId}`}
              role="option"
              aria-selected={i === highlightIdx}
              type="button"
              onMouseDown={() => selectActor(g)}
              className={`w-full text-left px-3 py-2 text-xs transition-colors ${
                i === highlightIdx
                  ? 'bg-[var(--teal-ghost)] text-[var(--accent-teal)]'
                  : 'text-[var(--text-primary)] hover:bg-[var(--hover-overlay)]'
              }`}
            >
              <div className="font-medium">{g.name}</div>
              {g.aliases && g.aliases.length > 0 && (
                <div className="text-[10px] text-[var(--text-secondary)] truncate">
                  {g.aliases.slice(0, 3).join(', ')}
                </div>
              )}
            </button>
          ))}
        </div>
      )}
    </div>
  );
}

export { ACTOR_COLORS };
export type { SelectedActor };
