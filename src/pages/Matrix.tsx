import { useEffect, useMemo, useState } from 'react';
import { useMatrix } from '../hooks/useApi';
import { PageHeader } from '../components/layout/PageHeader';
import { MatrixGrid } from '../components/matrix/MatrixGrid';

export function Matrix() {
  const { data, isLoading, error } = useMatrix();
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
          <span className="text-[#8892b0] text-sm">
            {totalTechniques} techniques across {(data ?? []).length} tactics
          </span>
        }
      />

      {/* Search/filter bar */}
      {!isLoading && !error && data && (
        <div className="flex items-center gap-2 max-w-sm">
          <div className="relative flex-1">
            <svg
              className="absolute left-3 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-[#8892b0]"
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
              className="w-full pl-8 pr-3 py-1.5 rounded-md text-sm bg-[#16213e] border border-[#2a2a4a] text-[#ccd6f6] placeholder-[#8892b0] focus:outline-none focus:border-[#64ffda] transition-colors"
            />
          </div>
          {inputValue && (
            <button
              type="button"
              onClick={() => { setInputValue(''); setFilterText(''); }}
              className="text-xs text-[#8892b0] hover:text-[#ccd6f6] transition-colors"
            >
              Clear
            </button>
          )}
        </div>
      )}

      {isLoading && (
        <div className="flex items-center justify-center h-64 text-[#8892b0]">
          <span className="inline-block w-5 h-5 border-2 border-[#64ffda33] border-t-[#64ffda] rounded-full animate-spin mr-2" />
          Loading matrix...
        </div>
      )}

      {error && (
        <div className="flex items-center justify-center h-64 text-[#f97316]">
          Failed to load matrix data.
        </div>
      )}

      {!isLoading && !error && data && (
        <MatrixGrid data={data} filterText={filterText} />
      )}
    </div>
  );
}
