'use client';

import { useEffect } from 'react';

type BoundaryError = Error & { digest?: string };

export default function Error({ error, reset }: { error: BoundaryError; reset: () => void }) {
  // Always log to the server-side Vercel logs so operators see the real cause
  // even when the user-facing message is redacted.
  useEffect(() => {
    console.error('App error boundary caught:', error);
  }, [error]);

  const isDev = process.env.NODE_ENV !== 'production';

  return (
    <div className="flex items-center justify-center h-64">
      <div className="text-center">
        <div className="text-[var(--accent-orange)] text-xl font-medium mb-2">Something went wrong</div>
        <p className="text-[var(--text-secondary)] text-sm mb-4">
          {isDev
            ? error.message
            : 'An unexpected error occurred. Please try again or contact support if the issue persists.'}
        </p>
        {error.digest && !isDev && (
          <p className="text-[var(--text-secondary)] text-[10px] font-mono mb-4">Ref: {error.digest}</p>
        )}
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
