import { useDomain, DEFAULT_DOMAIN } from '../../contexts/DomainContext';

export function DomainDropdown() {
  const { domain, setDomain, domains } = useDomain();
  const isNonDefault = domain !== DEFAULT_DOMAIN && domain !== 'all';

  return (
    <div className="flex items-center gap-2">
      <span className="text-[10px] font-semibold text-[var(--accent-teal)] uppercase tracking-wider w-12 shrink-0">Domain</span>
      <div className="relative flex-1">
        <select
          value={domain}
          onChange={(e) => setDomain(e.target.value)}
          className={`
            w-full appearance-none pl-2 pr-5 py-0.5 rounded text-[11px] cursor-pointer
            border transition-colors focus:outline-none focus:ring-1 focus:ring-[var(--accent-teal)]
            ${isNonDefault
              ? 'border-[var(--accent-teal)] text-[var(--accent-teal)] bg-[var(--teal-ghost)] font-medium'
              : 'border-[var(--border-color)] text-[var(--text-primary)] bg-[var(--surface-base)]'}
          `}
          title="Switch ATT&CK domain"
        >
          {domains.map((d) => (
            <option key={d.value} value={d.value} className="bg-[var(--surface-deep)] text-[var(--text-primary)]">
              {d.short}
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
