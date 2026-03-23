import { useEffect, useMemo, useState } from 'react';
import { useMatrix } from '../hooks/useApi';
import { useSector } from '../contexts/SectorContext';
import { PageHeader } from '../components/layout/PageHeader';
import { MatrixGrid } from '../components/matrix/MatrixGrid';

export function Matrix() {
  const { sectorParam } = useSector();
  const { data, isLoading, error } = useMatrix(sectorParam);
  const [inputValue, setInputValue] = useState('');
  const [filterText, setFilterText] = useState('');

  useEffect(() => {
    const timer = setTimeout(() => setFilterText(inputValue), 200);
    return () => clearTimeout(timer);
  }, [inputValue]);

  const totalTechniques = useMemo(
    () => (data ?? []).reduce((sum, col) => sum + col.techniques.length, 0),
    [data]
  );

  return (
    <div className="space-y-4">
      <PageHeader
        title="ATT&CK Matrix"
        subtitle="Techniques organized by tactic — click any cell to view details"
        actions={
          <span className="text-[var(--text-secondary)] text-sm">
            {totalTechniques} techniques across {(data ?? []).length} tactics
          </span>
        }
      />

      {/* Search/filter bar */}
      {!isLoading && !error && data && (
        <div className="flex items-center gap-2 max-w-sm">
          <div className="relative flex-1">
            <svg
              className="absolute left-3 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-[var(--text-secondary)]"
              fill="none"
              stroke="currentColor"
              strokeWidth={2}
              viewBox="0 0 24 24"
              aria-hidden="true"
            >
              <path strokeLinecap="round" strokeLinejoin="round" d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z" />
            </svg>
            <input
              type="search"
              placeholder="Filter techniques by name or ID..."
              value={inputValue}
              onChange={(e) => setInputValue(e.target.value)}
              className="w-full pl-8 pr-3 py-1.5 rounded-md text-sm bg-[var(--surface-card)] border border-[var(--border-color)] text-[var(--text-primary)] placeholder-[var(--text-secondary)] focus:outline-none focus:border-[var(--accent-teal)] transition-colors"
            />
          </div>
          {inputValue && (
            <button
              type="button"
              onClick={() => { setInputValue(''); setFilterText(''); }}
              className="text-xs text-[var(--text-secondary)] hover:text-[var(--text-primary)] transition-colors"
            >
              Clear
            </button>
          )}
        </div>
      )}

      {isLoading && (
        <div className="flex items-center justify-center h-64 text-[var(--text-secondary)]">
          <span className="inline-block w-5 h-5 border-2 border-[var(--teal-dim)] border-t-[var(--accent-teal)] rounded-full animate-spin mr-2" />
          Loading matrix...
        </div>
      )}

      {error && (
        <div className="flex items-center justify-center h-64 text-[var(--accent-orange)]">
          Failed to load matrix data.
        </div>
      )}

      {!isLoading && !error && data && (
        <MatrixGrid data={data} filterText={filterText} />
      )}
    </div>
  );
}
