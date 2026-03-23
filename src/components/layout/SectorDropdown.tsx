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
    <div className="relative flex items-center gap-1.5">
      <svg
        className="w-4 h-4 text-[var(--text-secondary)] flex-shrink-0"
        fill="none"
        stroke="currentColor"
        strokeWidth={2}
        viewBox="0 0 24 24"
        aria-hidden="true"
      >
        <path strokeLinecap="round" strokeLinejoin="round" d="M3.75 21h16.5M4.5 3h15M5.25 3v18m13.5-18v18M9 6.75h1.5m-1.5 3h1.5m-1.5 3h1.5m3-6H15m-1.5 3H15m-1.5 3H15M9 21v-3.375c0-.621.504-1.125 1.125-1.125h3.75c.621 0 1.125.504 1.125 1.125V21" />
      </svg>
      <select
        value={sector ?? ''}
        onChange={(e) => setSector(e.target.value || null)}
        className={`
          appearance-none bg-transparent text-xs pr-5 py-1 cursor-pointer
          border-none focus:outline-none focus:ring-0
          ${sector ? 'text-[var(--accent-teal)] font-medium' : 'text-[var(--text-secondary)]'}
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
      {sector && (
        <button
          type="button"
          onClick={() => setSector(null)}
          className="text-[var(--accent-teal)] hover:text-[var(--accent-teal-light)] text-xs"
          title="Clear sector filter"
        >
          ✕
        </button>
      )}
    </div>
  );
}
