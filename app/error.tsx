'use client';

export default function Error({ error, reset }: { error: Error; reset: () => void }) {
  return (
    <div className="flex items-center justify-center h-64">
      <div className="text-center">
        <div className="text-[var(--accent-orange)] text-xl font-medium mb-2">Something went wrong</div>
        <p className="text-[var(--text-secondary)] text-sm mb-4">{error.message}</p>
        <button
          onClick={reset}
          className="px-4 py-2 text-sm rounded-md border border-[var(--border-color)] text-[var(--text-primary)] hover:border-[var(--accent-teal)] transition-colors"
        >
          Try again
        </button>
      </div>
    </div>
  );
}
