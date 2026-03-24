import { useState } from 'react';
import { isSafeUrl } from '../../lib/urlSafety';

/** Collapsible references list with a chevron toggle. */
export function RefsChevron({ refs }: { refs: string[] }) {
  const [open, setOpen] = useState(false);
  return (
    <div>
      <button
        type="button"
        onClick={() => setOpen((v) => !v)}
        className="flex items-center gap-1.5 text-xs text-[var(--text-secondary)] hover:text-[var(--text-primary)] transition-colors"
        aria-expanded={open}
      >
        <svg
          className={`w-3 h-3 shrink-0 transition-transform duration-150 ${open ? 'rotate-90' : ''}`}
          fill="none"
          stroke="currentColor"
          strokeWidth={2}
          viewBox="0 0 24 24"
          aria-hidden="true"
        >
          <path strokeLinecap="round" strokeLinejoin="round" d="M9 5l7 7-7 7" />
        </svg>
        <span className="font-semibold uppercase tracking-wider text-[10px]">
          References ({refs.length})
        </span>
      </button>
      {open && (
        <div className="mt-1.5 ml-4 flex flex-wrap gap-2">
          {refs.map((ref) => (
            isSafeUrl(ref) ? (
              <a
                key={ref}
                href={ref}
                target="_blank"
                rel="noopener noreferrer"
                className="text-xs text-[var(--accent-teal)] hover:underline break-all"
              >
                {ref}
              </a>
            ) : (
              <span key={ref} className="text-xs text-[var(--text-secondary)] break-all">{ref}</span>
            )
          ))}
        </div>
      )}
    </div>
  );
}
