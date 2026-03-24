import { useQuery } from '@tanstack/react-query';
import { apiFetch } from '../../lib/api';
import { useSector } from '../../contexts/SectorContext';

interface SectorOption {
  name: string;
  slug: string | null;
  groupCount: number;
}

export function SectorDropdown() {
  const { sector, setSector } = useSector();

  const { data } = useQuery({
    queryKey: ['sectors-dropdown'],
    queryFn: () => apiFetch<{ data: SectorOption[] }>('/sectors'),
    staleTime: 60 * 60 * 1000,
  });

  const sectors = data?.data ?? [];

  return (
    <div className="flex items-center gap-2">
      <span className="text-[10px] font-semibold text-[var(--text-secondary)] uppercase tracking-wider w-12 shrink-0">Sector</span>
      <div className="relative flex-1">
        <select
          value={sector ?? ''}
          onChange={(e) => setSector(e.target.value || null)}
          className={`
            w-full appearance-none pl-2 pr-5 py-1 rounded text-[11px] cursor-pointer
            border transition-colors focus:outline-none focus:ring-1 focus:ring-[var(--accent-teal)]
            ${sector
              ? 'border-[var(--accent-teal)] text-[var(--accent-teal)] bg-[var(--teal-ghost)] font-medium'
              : 'border-[var(--border-color)] text-[var(--text-primary)] bg-[var(--surface-base)]'}
          `}
          title="Filter by industry sector"
        >
          <option value="" className="bg-[var(--surface-deep)] text-[var(--text-primary)]">All</option>
          {sectors.map((s) => (
            <option
              key={s.slug ?? s.name}
              value={s.slug ?? ''}
              className="bg-[var(--surface-deep)] text-[var(--text-primary)]"
            >
              {s.name}
            </option>
          ))}
        </select>
        <svg
          className="absolute right-1.5 top-1/2 -translate-y-1/2 w-2.5 h-2.5 text-[var(--text-secondary)] pointer-events-none"
          fill="none" stroke="currentColor" strokeWidth={2} viewBox="0 0 24 24" aria-hidden="true"
        >
          <path strokeLinecap="round" strokeLinejoin="round" d="M19 9l-7 7-7-7" />
        </svg>
      </div>
    </div>
  );
}
