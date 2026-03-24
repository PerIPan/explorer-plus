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
    <label className="flex flex-col gap-1">
      <span className="text-[10px] font-semibold text-[var(--text-secondary)] uppercase tracking-wider">Sector</span>
      <div className="relative flex items-center">
        <select
          value={sector ?? ''}
          onChange={(e) => setSector(e.target.value || null)}
          className={`
            w-full appearance-none pl-3 pr-7 py-1.5 rounded-md text-xs cursor-pointer
            border transition-colors focus:outline-none focus:ring-1 focus:ring-[var(--accent-teal)]
            ${sector
              ? 'border-[var(--accent-teal)] text-[var(--accent-teal)] bg-[var(--teal-ghost)] font-medium'
              : 'border-[var(--border-color)] text-[var(--text-primary)] bg-[var(--surface-base)]'}
          `}
          title="Filter by industry sector"
        >
          <option value="" className="bg-[var(--surface-deep)] text-[var(--text-primary)]">All Sectors</option>
          {sectors.map((s) => (
            <option
              key={s.slug ?? s.name}
              value={s.slug ?? ''}
              className="bg-[var(--surface-deep)] text-[var(--text-primary)]"
            >
              {s.name} ({s.groupCount})
            </option>
          ))}
        </select>
        <svg
          className="absolute right-2 top-1/2 -translate-y-1/2 w-3 h-3 text-[var(--text-secondary)] pointer-events-none"
          fill="none" stroke="currentColor" strokeWidth={2} viewBox="0 0 24 24" aria-hidden="true"
        >
          <path strokeLinecap="round" strokeLinejoin="round" d="M19 9l-7 7-7-7" />
        </svg>
      </div>
    </label>
  );
}
