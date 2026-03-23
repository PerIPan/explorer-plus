import { Link } from 'react-router-dom';
import type { ReactNode } from 'react';

interface StatCardProps {
  label: string;
  value: number | string;
  /** Accent color class for the value. Defaults to teal. */
  accent?: string;
  description?: string;
  /** Optional icon rendered in the top-right corner. */
  icon?: ReactNode;
  /** If provided, card is rendered as a link to this path. */
  href?: string;
  /** Border color on hover (e.g. 'hover:border-[var(--accent-teal)]'). Used when href is set. */
  hoverBorder?: string;
  /** Subtle glow/bg tint on hover (e.g. 'hover:bg-[#64ffda06]'). */
  hoverBg?: string;
}

/**
 * Dashboard stat card — shows a large number with a label and optional icon.
 * Wrapped in a Link when href is provided, giving full-card click navigation.
 */
export function StatCard({
  label,
  value,
  accent = 'text-[var(--accent-teal)]',
  description,
  icon,
  href,
  hoverBorder = 'hover:border-[var(--accent-teal)]',
  hoverBg = '',
}: StatCardProps) {
  const inner = (
    <>
      <div className="flex items-start justify-between gap-2">
        <div className={`text-3xl font-bold tabular-nums leading-none ${accent}`}>
          {typeof value === 'number' ? value.toLocaleString() : value}
        </div>
        {icon && (
          <div className={`shrink-0 mt-0.5 opacity-40 ${accent}`}>
            {icon}
          </div>
        )}
      </div>
      <div className="text-sm font-medium text-[var(--text-primary)] mt-1">{label}</div>
      {description && (
        <div className="text-xs text-[var(--text-secondary)] mt-0.5">{description}</div>
      )}
      {href && (
        <div className="mt-2 text-xs text-[var(--text-secondary)] flex items-center gap-1 group-hover:text-[var(--text-primary)] transition-colors">
          View all
          <svg
            className="w-3 h-3 translate-x-0 group-hover:translate-x-0.5 transition-transform"
            fill="none"
            stroke="currentColor"
            strokeWidth={2}
            viewBox="0 0 24 24"
            aria-hidden="true"
          >
            <path strokeLinecap="round" strokeLinejoin="round" d="M9 5l7 7-7 7" />
          </svg>
        </div>
      )}
    </>
  );

  const baseClass = [
    'group bg-[var(--surface-card)] border border-[var(--border-color)] rounded-lg p-5',
    'flex flex-col transition-all duration-150',
    href ? `${hoverBorder} ${hoverBg} cursor-pointer` : '',
  ]
    .filter(Boolean)
    .join(' ');

  if (href) {
    return (
      <Link to={href} className={baseClass}>
        {inner}
      </Link>
    );
  }

  return <div className={baseClass}>{inner}</div>;
}
