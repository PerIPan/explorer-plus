interface BadgeProps {
  label: string;
  /** Optional color variant. Defaults to neutral. */
  variant?: 'teal' | 'orange' | 'purple' | 'green' | 'blue' | 'pink' | 'yellow' | 'neutral';
  className?: string;
}

const variantStyles: Record<NonNullable<BadgeProps['variant']>, string> = {
  teal: 'bg-[var(--teal-faint)] text-[var(--accent-teal)] border-[var(--teal-dim)]',
  orange: 'bg-[var(--orange-faint)] text-[var(--accent-orange)] border-[var(--orange-dim)]',
  purple: 'bg-[var(--purple-faint)] text-[var(--accent-purple)] border-[var(--purple-dim)]',
  green: 'bg-[var(--green-faint)] text-[var(--accent-green)] border-[var(--green-dim)]',
  blue: 'bg-[var(--blue-faint)] text-[var(--accent-blue)] border-[var(--blue-dim)]',
  pink: 'bg-[var(--pink-faint)] text-[var(--accent-pink)] border-[var(--pink-dim)]',
  yellow: 'bg-[var(--yellow-faint)] text-[var(--accent-yellow)] border-[var(--yellow-dim)]',
  neutral: 'bg-[var(--hover-overlay)] text-[var(--text-secondary)] border-[var(--border-color)]',
};

/**
 * Generic pill/tag badge. Used for platforms, sectors, tactic names, etc.
 */
export function Badge({ label, variant = 'neutral', className = '' }: BadgeProps) {
  return (
    <span
      className={`
        inline-flex items-center px-2 py-0.5 rounded-full text-xs font-medium
        border ${variantStyles[variant]} ${className}
      `}
    >
      {label}
    </span>
  );
}
