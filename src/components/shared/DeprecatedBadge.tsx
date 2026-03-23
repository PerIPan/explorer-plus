interface DeprecatedBadgeProps {
  /** If true shows "Revoked", otherwise "Deprecated" */
  isRevoked?: boolean;
}

/**
 * Warning badge for revoked or deprecated ATT&CK entities.
 */
export function DeprecatedBadge({ isRevoked = false }: DeprecatedBadgeProps) {
  return (
    <span
      className="
        inline-flex items-center gap-1 px-2 py-0.5 rounded text-xs font-medium
        bg-[#fbbf2410] text-[var(--accent-yellow)] border border-[var(--yellow-dim)]
        line-through decoration-[#fbbf2466]
      "
      aria-label={isRevoked ? 'This entity has been revoked' : 'This entity is deprecated'}
    >
      {isRevoked ? 'Revoked' : 'Deprecated'}
    </span>
  );
}
