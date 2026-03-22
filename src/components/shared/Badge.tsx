interface BadgeProps {
  label: string;
  /** Optional color variant. Defaults to neutral. */
  variant?: 'teal' | 'orange' | 'purple' | 'green' | 'blue' | 'pink' | 'yellow' | 'neutral';
  className?: string;
}

const variantStyles: Record<NonNullable<BadgeProps['variant']>, string> = {
  teal: 'bg-[#64ffda18] text-[#64ffda] border-[#64ffda33]',
  orange: 'bg-[#f9731618] text-[#f97316] border-[#f9731633]',
  purple: 'bg-[#a78bfa18] text-[#a78bfa] border-[#a78bfa33]',
  green: 'bg-[#34d39918] text-[#34d399] border-[#34d39933]',
  blue: 'bg-[#60a5fa18] text-[#60a5fa] border-[#60a5fa33]',
  pink: 'bg-[#f472b618] text-[#f472b6] border-[#f472b633]',
  yellow: 'bg-[#fbbf2418] text-[#fbbf24] border-[#fbbf2433]',
  neutral: 'bg-[#ffffff08] text-[#8892b0] border-[#2a2a4a]',
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
