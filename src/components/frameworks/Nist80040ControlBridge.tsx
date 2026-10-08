'use client';

import Link from 'next/link';
import { useQueries } from '@tanstack/react-query';
import { apiFetch } from '../../lib/api';
import { SP800_53_CONTROLS } from '../../lib/nist-800-40.mjs';

/**
 * The only bridge SP 800-40r4 has to ATT&CK, drawn from two sourced hops:
 * NIST's own appendix names eight SP 800-53 controls, and CTID's 800-53 ->
 * ATT&CK mappings (already on /frameworks/nist) take each control to
 * techniques. Counts are live, from the same endpoint the NIST page uses.
 *
 * A zero is rendered as a zero, not hidden: RA-7, SR-2 and SR-3 carry no CTID
 * mapping, and a reader should see that NIST's list and CTID's mappings only
 * partly overlap rather than be shown the five that do.
 */
export function Nist80040ControlBridge() {
  const results = useQueries({
    queries: SP800_53_CONTROLS.map((c) => ({
      queryKey: ['nist-control-techniques', c.siteId],
      queryFn: () =>
        apiFetch<{ data: { attackId: string; name: string }[] }>(`/frameworks/nist/${c.siteId}/techniques`),
      staleTime: 60 * 60 * 1000,
    })),
  });

  return (
    <ul className="grid gap-2 sm:grid-cols-2">
      {SP800_53_CONTROLS.map((c, i) => {
        const r = results[i];
        const n = r.data?.data.length;
        return (
          <li key={c.id}>
            <Link
              href={`/frameworks/nist?search=${encodeURIComponent(c.siteId)}`}
              className="flex items-center gap-3 rounded-md border border-[var(--border-color)] bg-[var(--surface-card)] px-3 py-2 hover:border-[var(--border-hover)] hover:bg-[var(--hover-overlay)] transition-colors"
            >
              <span className="w-12 shrink-0 font-mono text-xs text-[var(--accent-orange)]">{c.id}</span>
              <span className="min-w-0 flex-1 text-sm text-[var(--text-primary)]">{c.title}</span>
              <span
                className="shrink-0 text-xs tabular-nums text-[var(--text-secondary)]"
                title="ATT&CK techniques CTID maps to this control"
              >
                {r.isPending ? '…' : r.isError ? 'n/a' : `${n} tech`}
              </span>
            </Link>
          </li>
        );
      })}
    </ul>
  );
}
