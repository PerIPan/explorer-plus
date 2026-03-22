import { useMemo } from 'react';
import type { MatrixData } from '../../lib/types';
import { MatrixCell } from './MatrixCell';
import { MatrixLegend } from './MatrixLegend';

interface MatrixGridProps {
  data: MatrixData;
  /** Live filter text — dims non-matching cells, highlights matches */
  filterText?: string;
}

/**
 * Full ATT&CK matrix — tactics as columns, techniques as cells.
 * groupUsageCount uses subTechniques.length as a proxy for cell "richness".
 */
export function MatrixGrid({ data, filterText = '' }: MatrixGridProps) {
  const normalizedFilter = filterText.trim().toLowerCase();

  /** Compute max sub-technique count for color scaling */
  const maxUsage = useMemo(() => {
    let max = 0;
    data.forEach((col) =>
      col.techniques.forEach((t) => {
        if (t.subTechniques.length > max) max = t.subTechniques.length;
      })
    );
    return max || 1;
  }, [data]);

  return (
    <div className="space-y-3">
      <MatrixLegend />

      {/* max-h container enables sticky tactic headers during vertical scroll */}
      <div className="max-h-[70vh] overflow-auto">
        <div className="overflow-x-auto">
          <div
            className="inline-flex gap-1 min-w-max pb-2"
            role="grid"
            aria-label="ATT&CK Matrix"
          >
            {data.map((col) => (
              <div
                key={col.tactic.attackId}
                className="w-[140px] flex-shrink-0"
                role="columnheader"
              >
                {/* Tactic header — sticky within scrollable container */}
                <div
                  className="
                    bg-[#0a0a1a] border border-[#2a2a4a] rounded-t px-2 py-2 mb-1
                    text-center text-[11px] font-semibold text-[#fbbf24] uppercase tracking-wide
                    sticky top-0 z-10
                  "
                >
                  <div>{col.tactic.name}</div>
                  <div className="text-[9px] text-[#8892b0] font-normal font-mono mt-0.5">
                    {col.tactic.attackId}
                  </div>
                </div>

                {/* Technique cells */}
                <div className="flex flex-col gap-0.5">
                  {col.techniques.map((tech) => {
                    const isMatch =
                      normalizedFilter === '' ||
                      tech.name.toLowerCase().includes(normalizedFilter) ||
                      tech.attackId.toLowerCase().includes(normalizedFilter);

                    return (
                      <div
                        key={tech.attackId}
                        className={[
                          'transition-opacity duration-150',
                          normalizedFilter && !isMatch ? 'opacity-20' : '',
                          normalizedFilter && isMatch ? 'ring-1 ring-[#64ffda] rounded' : '',
                        ].join(' ')}
                      >
                        <MatrixCell
                          technique={tech}
                          groupUsageCount={tech.subTechniques.length}
                          maxUsage={maxUsage}
                        />
                      </div>
                    );
                  })}
                </div>
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
}
