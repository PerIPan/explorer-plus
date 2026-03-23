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

  const allTechniques = data?.techniques ?? [];

  /** Filter + sort alphabetically — must be before early returns (Rules of Hooks) */
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

  if (isLoading) {
    return (
      <div className="flex items-center justify-center h-64 text-[var(--text-secondary)]">
        <span className="inline-block w-5 h-5 border-2 border-[var(--teal-dim)] border-t-[var(--accent-teal)] rounded-full animate-spin mr-2" />
        Loading...
      </div>
    );
  }

  if (error || !data) {
    return (
      <div className="flex items-center justify-center h-64 text-[var(--accent-orange)]">
        Tactic not found.
      </div>
    );
  }

  const description = data.description
    ? sanitize(sanitizeMarkdown(data.description))
    : null;

  return (
    <div className="space-y-6">
      <PageHeader
        title={data.name}
        breadcrumb={[
          { label: 'Tactics', href: '/tactics' },
          { label: data.attackId },
        ]}
        actions={
          <span className="font-mono text-xs text-[var(--accent-yellow)] bg-[var(--yellow-faint)] border border-[var(--yellow-dim)] px-2 py-1 rounded">
            {data.attackId}
          </span>
        }
      />

      {description && (
        <div className="bg-[var(--surface-card)] border border-[var(--border-color)] rounded-lg p-5">
          <h3 className="text-sm font-semibold text-[var(--text-secondary)] uppercase tracking-wider mb-3">
            Description
          </h3>
          <p className="text-[var(--text-primary)] text-sm leading-relaxed whitespace-pre-wrap">
            {description}
          </p>
        </div>
      )}

      {/* Techniques list with search filter */}
      <div className="bg-[var(--surface-card)] border border-[var(--border-color)] rounded-lg p-5">
        <div className="flex items-center justify-between gap-4 mb-4 flex-wrap">
          <h3 className="text-sm font-semibold text-[var(--text-secondary)] uppercase tracking-wider">
            Techniques
            {!isLoading && (
              <span className="ml-2 text-[var(--accent-teal)] font-semibold normal-case text-sm">
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
              className="min-w-[200px] px-3 py-1.5 rounded-md text-sm bg-[var(--surface-deep)] border border-[var(--border-color)] text-[var(--text-primary)] placeholder-[var(--text-secondary)] focus:outline-none focus:border-[var(--accent-teal)]"
            />
          )}
        </div>

        {isLoading ? (
          <div className="flex items-center text-[var(--text-secondary)] text-sm">
            <span className="inline-block w-4 h-4 border-2 border-[var(--teal-dim)] border-t-[var(--accent-teal)] rounded-full animate-spin mr-2" />
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
          <p className="text-[var(--text-secondary)] text-sm">
            {techFilter ? 'No techniques match your filter.' : 'No techniques found for this tactic.'}
          </p>
        )}
      </div>
    </div>
  );
}
