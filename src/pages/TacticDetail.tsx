import { useState, useMemo } from 'react';
import { useParams } from 'react-router-dom';
import { useTactic } from '../hooks/useApi';
import { PageHeader } from '../components/layout/PageHeader';
import { EntityLink } from '../components/shared/EntityLink';
import { sanitize, sanitizeMarkdown } from '../lib/sanitize';

export function TacticDetail() {
  const { attackId } = useParams<{ attackId: string }>();
  const { data, isLoading, error } = useTactic(attackId ?? '');
  const [techFilter, setTechFilter] = useState('');

  if (isLoading) {
    return (
      <div className="flex items-center justify-center h-64 text-[#8892b0]">
        <span className="inline-block w-5 h-5 border-2 border-[#64ffda33] border-t-[#64ffda] rounded-full animate-spin mr-2" />
        Loading...
      </div>
    );
  }

  if (error || !data) {
    return (
      <div className="flex items-center justify-center h-64 text-[#f97316]">
        Tactic not found.
      </div>
    );
  }

  const description = data.description
    ? sanitize(sanitizeMarkdown(data.description))
    : null;

  const allTechniques = data?.techniques ?? [];

  /** Filter + sort alphabetically (FIX 41) */
  const techniques = useMemo(() => {
    const normalized = techFilter.trim().toLowerCase();
    const filtered = normalized
      ? allTechniques.filter(
          (t) =>
            t.name.toLowerCase().includes(normalized) ||
            t.attackId.toLowerCase().includes(normalized)
        )
      : allTechniques;
    return [...filtered].sort((a, b) => a.name.localeCompare(b.name));
  }, [allTechniques, techFilter]);

  return (
    <div className="space-y-6">
      <PageHeader
        title={data.name}
        breadcrumb={[
          { label: 'Tactics', href: '/tactics' },
          { label: data.attackId },
        ]}
        actions={
          <span className="font-mono text-xs text-[#fbbf24] bg-[#fbbf2418] border border-[#fbbf2433] px-2 py-1 rounded">
            {data.attackId}
          </span>
        }
      />

      {description && (
        <div className="bg-[#16213e] border border-[#2a2a4a] rounded-lg p-5">
          <h3 className="text-sm font-semibold text-[#8892b0] uppercase tracking-wider mb-3">
            Description
          </h3>
          <p className="text-[#ccd6f6] text-sm leading-relaxed whitespace-pre-wrap">
            {description}
          </p>
        </div>
      )}

      {/* Techniques list with search filter */}
      <div className="bg-[#16213e] border border-[#2a2a4a] rounded-lg p-5">
        <div className="flex items-center justify-between gap-4 mb-4 flex-wrap">
          <h3 className="text-sm font-semibold text-[#8892b0] uppercase tracking-wider">
            Techniques
            {!isLoading && (
              <span className="ml-2 text-[#64ffda] font-semibold normal-case text-sm">
                ({techniques.length}{techFilter ? ` of ${allTechniques.length}` : ''})
              </span>
            )}
          </h3>
          {!isLoading && allTechniques.length > 0 && (
            <input
              type="search"
              placeholder="Filter techniques..."
              value={techFilter}
              onChange={(e) => setTechFilter(e.target.value)}
              className="min-w-[200px] px-3 py-1.5 rounded-md text-sm bg-[#0a0a1a] border border-[#2a2a4a] text-[#ccd6f6] placeholder-[#8892b0] focus:outline-none focus:border-[#64ffda]"
            />
          )}
        </div>

        {isLoading ? (
          <div className="flex items-center text-[#8892b0] text-sm">
            <span className="inline-block w-4 h-4 border-2 border-[#64ffda33] border-t-[#64ffda] rounded-full animate-spin mr-2" />
            Loading techniques...
          </div>
        ) : techniques.length > 0 ? (
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-2">
            {techniques.map((t) => (
              <EntityLink
                key={t.attackId}
                type="technique"
                attackId={t.attackId}
                name={t.name}
              />
            ))}
          </div>
        ) : (
          <p className="text-[#8892b0] text-sm">
            {techFilter ? 'No techniques match your filter.' : 'No techniques found for this tactic.'}
          </p>
        )}
      </div>
    </div>
  );
}
