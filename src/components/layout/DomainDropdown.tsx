import { useDomain, DEFAULT_DOMAIN } from '../../contexts/DomainContext';

export function DomainDropdown() {
  const { domain, setDomain, domains } = useDomain();
  const isNonDefault = domain !== DEFAULT_DOMAIN;
  const currentLabel = domains.find((d) => d.value === domain)?.short ?? 'Enterprise';

  return (
    <label className="flex flex-col gap-1">
      <span className="text-[10px] font-semibold text-[var(--text-secondary)] uppercase tracking-wider">Domain</span>
      <div className="relative">
        <select
          value={domain}
          onChange={(e) => setDomain(e.target.value)}
          className={`
            w-full appearance-none pl-3 pr-7 py-1.5 rounded-md text-xs cursor-pointer
            border transition-colors focus:outline-none focus:ring-1 focus:ring-[var(--accent-teal)]
            ${isNonDefault
              ? 'border-[var(--accent-teal)] text-[var(--accent-teal)] bg-[var(--teal-ghost)] font-medium'
              : 'border-[var(--border-color)] text-[var(--text-primary)] bg-[var(--surface-base)]'}
          `}
          title="Switch ATT&CK domain"
        >
          {domains.map((d) => (
            <option key={d.value} value={d.value} className="bg-[var(--surface-deep)] text-[var(--text-primary)]">
              {d.label}
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
