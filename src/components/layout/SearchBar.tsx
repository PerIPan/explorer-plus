import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { useQuery } from '@tanstack/react-query';
import Fuse from 'fuse.js';
import { apiFetch } from '../../lib/api';
import { Badge } from '../shared/Badge';

interface EntityEntry {
  attackId: string;
  name: string;
  type: string;
}

const TYPE_VARIANT: Record<string, 'teal' | 'orange' | 'purple' | 'blue' | 'green' | 'pink' | 'yellow' | 'neutral'> = {
  technique: 'teal',
  group: 'orange',
  software: 'purple',
  campaign: 'blue',
  mitigation: 'green',
  data_source: 'pink',
  tactic: 'yellow',
};

export function SearchBar() {
  const [value, setValue] = useState('');
  const [showDropdown, setShowDropdown] = useState(false);
  const inputRef = useRef<HTMLInputElement>(null);
  const navigate = useNavigate();

  /** Load all entities for Fuse.js */
  const { data: allEntities } = useQuery({
    queryKey: ['entities-all'],
    queryFn: () => apiFetch<{ data: EntityEntry[] }>('/entities').then(r => r.data),
    staleTime: 60 * 60 * 1000,
    gcTime: 60 * 60 * 1000,
  });

  const fuse = useMemo(() => {
    if (!allEntities?.length) return null;
    return new Fuse(allEntities, {
      keys: ['name', 'attackId'],
      threshold: 0.3,
      distance: 100,
      minMatchCharLength: 2,
    });
  }, [allEntities]);

  const suggestions = useMemo(() => {
    if (!fuse || !value.trim() || value.trim().length < 2) return [];
    return fuse.search(value.trim(), { limit: 8 }).map(r => r.item);
  }, [fuse, value]);

  /** Cleanup on unmount */
  useEffect(() => {
    return () => {};
  }, []);

  /** Focus on `/` keypress */
  useEffect(() => {
    function handleKeyDown(e: KeyboardEvent) {
      const tag = (e.target as HTMLElement).tagName.toLowerCase();
      if (e.key === '/' && tag !== 'input' && tag !== 'textarea') {
        e.preventDefault();
        inputRef.current?.focus();
      }
      if (e.key === 'Escape') {
        inputRef.current?.blur();
        setShowDropdown(false);
      }
    }
    document.addEventListener('keydown', handleKeyDown);
    return () => document.removeEventListener('keydown', handleKeyDown);
  }, []);

  function navigateToEntity(attackId: string, type: string) {
    setShowDropdown(false);
    setValue('');
    // External actors navigate to list with search filter (no detail page)
    if (type === 'external_actor') {
      navigate(`/external-actors?search=${encodeURIComponent(attackId)}`);
      return;
    }
    const typeRoutes: Record<string, string> = {
      technique: 'techniques',
      group: 'groups',
      software: 'software',
      campaign: 'campaigns',
      mitigation: 'mitigations',
      tactic: 'tactics',
      data_source: 'data-sources',
    };
    const route = typeRoutes[type] ?? 'techniques';
    navigate(`/${route}/${attackId}`);
  }

  const handleSubmit = useCallback(
    (e: React.FormEvent) => {
      e.preventDefault();
      const trimmed = value.trim();
      if (suggestions.length > 0) {
        navigateToEntity(suggestions[0].attackId, suggestions[0].type);
      } else if (trimmed.length >= 3) {
        navigate(`/search?q=${encodeURIComponent(trimmed)}`);
        setShowDropdown(false);
        setValue('');
      }
    },
    [value, suggestions, navigate]
  );

  return (
    <form onSubmit={handleSubmit} role="search" className="relative w-full max-w-xl">
      {/* Search icon */}
      <span aria-hidden="true" className="absolute left-3 top-1/2 -translate-y-1/2 text-[#8892b0] pointer-events-none">
        <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
          <circle cx="11" cy="11" r="8" />
          <path d="m21 21-4.35-4.35" />
        </svg>
      </span>

      <input
        ref={inputRef}
        type="search"
        value={value}
        onChange={(e) => { setValue(e.target.value); setShowDropdown(true); }}
        onFocus={() => setShowDropdown(true)}
        onBlur={() => setTimeout(() => setShowDropdown(false), 200)}
        placeholder="Search techniques, groups, software..."
        aria-label="Search MITRE ATT&CK entities"
        className="
          w-full pl-9 pr-16 py-2 rounded-md text-sm
          bg-[#16213e] border border-[#2a2a4a]
          text-[#ccd6f6] placeholder-[#8892b0]
          focus:outline-none focus:border-[#64ffda] focus:ring-1 focus:ring-[#64ffda33]
          transition-colors duration-150
        "
      />

      {/* Keyboard hint */}
      <span aria-hidden="true" className="absolute right-3 top-1/2 -translate-y-1/2 text-[#8892b0] text-xs border border-[#2a2a4a] rounded px-1 py-0.5 font-mono">
        /
      </span>

      {/* Fuse.js dropdown */}
      {showDropdown && suggestions.length > 0 && (
        <div className="absolute top-full mt-1 w-full z-50 bg-[#16213e] border border-[#2a2a4a] rounded-lg shadow-2xl overflow-hidden max-h-80 overflow-y-auto">
          <div className="px-3 py-1.5 text-[10px] uppercase tracking-wider text-[#8892b0] bg-[#0a0a1a]">
            {suggestions.length} results
          </div>
          {suggestions.map((s, i) => (
            <button
              key={s.attackId}
              type="button"
              onMouseDown={() => navigateToEntity(s.attackId, s.type)}
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
    </form>
  );
}
