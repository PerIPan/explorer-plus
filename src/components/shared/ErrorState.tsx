interface ErrorStateProps {
  message?: string;
  onRetry?: () => void;
}

/**
 * Page-level error display with warning icon and optional retry action.
 */
export function ErrorState({
  message = 'Something went wrong.',
  onRetry,
}: ErrorStateProps) {
  return (
    <div className="flex flex-col items-center justify-center h-64 gap-4">
      <svg
        className="w-10 h-10 text-[#f97316]"
        fill="none"
        stroke="currentColor"
        strokeWidth={1.5}
        viewBox="0 0 24 24"
        aria-hidden="true"
      >
        <path
          strokeLinecap="round"
          strokeLinejoin="round"
          d="M12 9v3.75m-9.303 3.376c-.866 1.5.217 3.374 1.948 3.374h14.71c1.73 0 2.813-1.874 1.948-3.374L13.949 3.378c-.866-1.5-3.032-1.5-3.898 0L2.697 16.126zM12 15.75h.007v.008H12v-.008z"
        />
      </svg>
      <p className="text-[#f97316] text-sm font-medium">{message}</p>
      {onRetry && (
        <button
          type="button"
          onClick={onRetry}
          className="px-4 py-1.5 text-xs rounded-md border border-[#64ffda33] text-[#64ffda] bg-[#64ffda0a] hover:bg-[#64ffda18] transition-colors"
        >
          Try again
        </button>
      )}
    </div>
  );
}
