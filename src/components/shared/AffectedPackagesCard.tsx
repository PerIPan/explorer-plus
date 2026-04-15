import Link from 'next/link';
import { useQuery } from '@tanstack/react-query';
import { apiFetch } from '../../lib/api';
import { Badge } from './Badge';

interface AffectedPackage {
  packageId: string;
  ecosystem: string;
  packageName: string;
  advisoryCount: number;
  severityTop: string | null;
}

interface Response {
  packages: AffectedPackage[];
}

const SEVERITY_VARIANTS: Record<string, 'pink' | 'orange' | 'yellow' | 'blue' | 'neutral'> = {
  CRITICAL: 'pink',
  HIGH: 'orange',
  MEDIUM: 'yellow',
  LOW: 'blue',
};

export function useAffectedPackages(
  fetchPath: string,
  queryKey: (string | number)[],
  enabled = true,
) {
  return useQuery({
    queryKey: ['affected-packages', ...queryKey],
    queryFn: () => apiFetch<Response>(fetchPath),
    enabled,
    staleTime: 5 * 60 * 1000,
  });
}

/** Package chip list (no wrapper). Consumers provide their own MapCard/section. */
export function PackageChipList({
  packages,
  limit = 30,
}: {
  packages: AffectedPackage[];
  limit?: number;
}) {
  if (packages.length === 0) return null;
  const shown = packages.slice(0, limit);
  const more = packages.length - shown.length;
  return (
    <ul
      role="list"
      aria-label="Affected packages"
      className="flex flex-wrap gap-1.5 max-h-48 overflow-y-auto list-none m-0 p-0"
    >
      {shown.map((p) => (
        <li key={p.packageId} role="listitem">
          <Link
            href={`/packages/${p.ecosystem}/${encodeURIComponent(p.packageName)}`}
            className="inline-flex items-center gap-1.5 px-2 py-0.5 rounded-md text-xs font-medium border text-[var(--accent-blue)] bg-[var(--blue-faint)] border-[var(--blue-dim)] hover:brightness-125 transition-all duration-150"
            title={`${p.advisoryCount} advisor${p.advisoryCount === 1 ? 'y' : 'ies'}`}
          >
            <span className="opacity-70">{p.ecosystem}/</span>
            <span className="font-mono">{p.packageName}</span>
            <span className="opacity-60">({p.advisoryCount})</span>
            {p.severityTop && (
              <Badge label={p.severityTop} variant={SEVERITY_VARIANTS[p.severityTop] ?? 'neutral'} />
            )}
          </Link>
        </li>
      ))}
      {more > 0 && (
        <li role="listitem" className="text-xs text-[var(--text-secondary)] self-center ml-1">
          +{more} more
        </li>
      )}
    </ul>
  );
}
