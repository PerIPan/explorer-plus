import { useDomain } from '../../contexts/DomainContext';

const DEFAULT_DOMAIN = 'enterprise-attack';

export function DomainDropdown() {
  const { domain, setDomain, domains } = useDomain();
  const isNonDefault = domain !== DEFAULT_DOMAIN;

  return (
    <div className="relative flex items-center gap-1.5">
      {/* Shield icon — distinct from the building icon used by SectorDropdown */}
      <svg
        className="w-4 h-4 text-[var(--text-secondary)] flex-shrink-0"
        fill="none"
        stroke="currentColor"
        strokeWidth={2}
        viewBox="0 0 24 24"
        aria-hidden="true"
      >
        <path
          strokeLinecap="round"
          strokeLinejoin="round"
          d="M9 12.75L11.25 15 15 9.75m-3-7.036A11.959 11.959 0 013.598 6 11.99 11.99 0 003 9.749c0 5.592 3.824 10.29 9 11.623 5.176-1.332 9-6.03 9-11.622 0-1.31-.21-2.571-.598-3.751h-.152c-3.196 0-6.1-1.248-8.25-3.285z"
        />
      </svg>
      <select
        value={domain}
        onChange={(e) => setDomain(e.target.value)}
        className={`
          appearance-none bg-transparent text-xs pr-5 py-1 cursor-pointer
          border-none focus:outline-none focus:ring-0
          ${isNonDefault ? 'text-[var(--accent-teal)] font-medium' : 'text-[var(--text-secondary)]'}
        `}
        title="Switch ATT&CK domain"
      >
        {domains.map((d) => (
          <option
            key={d.value}
            value={d.value}
            className="bg-[var(--surface-deep)] text-[var(--text-primary)]"
          >
            {d.label}
          </option>
        ))}
      </select>
    </div>
  );
}
