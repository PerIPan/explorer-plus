import { useMemo } from 'react';
import { useMatrix } from '../hooks/useApi';
import { PageHeader } from '../components/layout/PageHeader';
import { MatrixGrid } from '../components/matrix/MatrixGrid';

export function Matrix() {
  const { data, isLoading, error } = useMatrix();

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
        <MatrixGrid data={data} />
      )}
    </div>
  );
}
