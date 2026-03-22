import { useState, useMemo } from 'react';
import { useMatrix } from '../hooks/useApi';
import { PageHeader } from '../components/layout/PageHeader';
import { MatrixGrid } from '../components/matrix/MatrixGrid';

const PLATFORMS = [
  'Windows',
  'Linux',
  'macOS',
  'Cloud',
  'Azure',
  'Google Workspace',
  'SaaS',
  'Network',
  'IaaS',
  'Containers',
];

export function Matrix() {
  const { data, isLoading, error } = useMatrix();
  const [platformFilter, setPlatformFilter] = useState('');

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
          <div className="flex items-center gap-3 text-sm">
            <span className="text-[#8892b0]">
              {totalTechniques} techniques across {(data ?? []).length} tactics
            </span>
            <select
              value={platformFilter}
              onChange={(e) => setPlatformFilter(e.target.value)}
              className="px-3 py-1.5 rounded-md text-sm bg-[#16213e] border border-[#2a2a4a] text-[#ccd6f6] focus:outline-none focus:border-[#64ffda]"
              aria-label="Filter by platform"
            >
              <option value="">All Platforms</option>
              {PLATFORMS.map((p) => (
                <option key={p} value={p}>{p}</option>
              ))}
            </select>
          </div>
        }
      />

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
        <MatrixGrid data={data} platformFilter={platformFilter} />
      )}
    </div>
  );
}
