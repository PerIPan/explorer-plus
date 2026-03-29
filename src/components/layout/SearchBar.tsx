import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { useQuery } from '@tanstack/react-query';
import Fuse from 'fuse.js';
import { apiFetch } from '../../lib/api';
import { useDomain } from '../../contexts/DomainContext';
import { Badge } from '../shared/Badge';

const DOMAIN_SHORT: Record<string, string> = {
  'enterprise-attack': 'Enterprise',
  'mobile-attack': 'Mobile',
  'ics-attack': 'ICS',
  'atlas-attack': 'ATLAS',
};

interface EntityEntry {
  attackId: string;
  name: string;
  type: string;
  domain: string | null;
}

const TYPE_VARIANT: Record<string, 'teal' | 'orange' | 'purple' | 'blue' | 'green' | 'pink' | 'yellow' | 'neutral'> = {
  technique: 'teal',
  group: 'orange',
  software: 'purple',
  campaign: 'blue',
  mitigation: 'green',
  data_source: 'pink',
  tactic: 'yellow',
  sector: 'green',
  application: 'blue',
};

export function SearchBar() {
  const [value, setValue] = useState('');
  const [showDropdown, setShowDropdown] = useState(false);
  const inputRef = useRef<HTMLInputElement>(null);
  const blurTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  const navigate = useNavigate();
  const { domain, setDomain } = useDomain();

  /** Load ALL entities cross-domain for Fuse.js */
  const { data: allEntities } = useQuery({
    queryKey: ['entities-all-cross'],
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

  /** Cleanup blur timer on unmount */
  useEffect(() => {
    return () => {
      if (blurTimerRef.current !== null) clearTimeout(blurTimerRef.current);
    };
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

  const navigateToEntity = useCallback(
    (entity: EntityEntry) => {
      setShowDropdown(false);
      setValue('');
      // External actors navigate to list with search filter (no detail page)
      if (entity.type === 'external_actor') {
        navigate(`/external-actors?search=${encodeURIComponent(entity.attackId)}`);
        return;
      }
      // Sectors and applications navigate to the 360 View
      if (entity.type === 'sector') {
        navigate(`/?entity=${encodeURIComponent(entity.attackId)}&tab=sector-map`);
        return;
      }
      if (entity.type === 'application') {
        navigate(`/?entity=${encodeURIComponent(entity.attackId)}&tab=application-map`);
        return;
      }
      // Auto-switch domain when selecting an entity outside current domain
      if (entity.domain && entity.domain !== domain && domain !== 'all') {
        setDomain('all');
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
      const route = typeRoutes[entity.type] ?? 'techniques';
      navigate(`/${route}/${entity.attackId}`);
    },
    [domain, setDomain, navigate],
  );

  const handleSubmit = useCallback(
    (e: React.FormEvent) => {
      e.preventDefault();
      const trimmed = value.trim();
      if (suggestions.length > 0) {
        navigateToEntity(suggestions[0]);
      } else if (trimmed.length >= 3) {
        navigate(`/search?q=${encodeURIComponent(trimmed)}`);
        setShowDropdown(false);
        setValue('');
      }
    },
    [value, suggestions, navigate, navigateToEntity]
  );

  return (
    <form onSubmit={handleSubmit} role="search" className="relative w-full max-w-xl">
      {/* Search icon */}
      <span aria-hidden="true" className="absolute left-3 top-1/2 -translate-y-1/2 text-[var(--text-secondary)] pointer-events-none">
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
        onBlur={() => {
          blurTimerRef.current = setTimeout(() => setShowDropdown(false), 200);
        }}
        placeholder="Search techniques, groups, software, applications — all domains..."
        aria-label="Search MITRE ATT&CK entities"
        className="
          w-full pl-9 pr-16 py-2 rounded-md text-sm
          bg-[var(--surface-card)] border border-[var(--border-color)]
          text-[var(--text-primary)] placeholder-[var(--text-secondary)]
          focus:outline-none focus:border-[var(--accent-teal)] focus:ring-1 focus:ring-[#64ffda33]
          transition-colors duration-150
        "
      />

      {/* Keyboard hint */}
      <span aria-hidden="true" className="absolute right-3 top-1/2 -translate-y-1/2 text-[var(--text-secondary)] text-xs border border-[var(--border-color)] rounded px-1 py-0.5 font-mono">
        /
      </span>

      {/* Fuse.js dropdown */}
      {showDropdown && suggestions.length > 0 && (
        <div className="absolute top-full mt-1 w-full z-50 bg-[var(--surface-card)] border border-[var(--border-color)] rounded-lg shadow-2xl overflow-hidden max-h-80 overflow-y-auto">
          <div className="px-3 py-1.5 text-[10px] uppercase tracking-wider text-[var(--text-secondary)] bg-[var(--surface-deep)]">
            {suggestions.length} results
          </div>
          {suggestions.map((s, i) => (
            <button
              key={`${s.type}-${s.attackId}`}
              type="button"
              onMouseDown={() => navigateToEntity(s)}
              className={`w-full flex items-center gap-3 px-4 py-2.5 hover:bg-[var(--teal-ghost)] transition-colors text-left ${i === 0 ? 'bg-[var(--hover-subtle)]' : ''}`}
            >
              <Badge
                label={s.type.replace('_', ' ')}
                variant={TYPE_VARIANT[s.type] ?? 'neutral'}
              />
              {s.type !== 'sector' && s.type !== 'application' && (
                <span className="font-mono text-xs text-[var(--accent-teal)] w-20 flex-shrink-0">{s.attackId}</span>
              )}
              <span className="text-sm text-[var(--text-primary)] truncate">{s.name}</span>
              {s.type !== 'group' && s.domain && DOMAIN_SHORT[s.domain] && (
                <Badge label={DOMAIN_SHORT[s.domain]} variant="neutral" />
              )}
            </button>
          ))}
        </div>
      )}
    </form>
  );
}
