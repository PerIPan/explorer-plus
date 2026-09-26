'use client';

import { useEffect, useMemo, useState } from 'react';
import { useQuery, useQueryClient } from '@tanstack/react-query';
import { DiamondLoader } from '../shared/FoldingDiamond';
import { CopyButton } from './primitives';
import { DOCS_PROBE_HEADER, absoluteUrl } from '../../lib/api-catalog';

/**
 * Cap on the pretty-printed text we put in the DOM. Some list routes return 50
 * rows of long descriptions; `/entities` returns the whole search index. The
 * budget is the rendered string, not the response — the response is still read
 * in full so the byte count shown is honest.
 */
const MAX_RENDER = 20_000;

/** Above this, do not `JSON.parse` + re-stringify at all; show the raw head. */
const MAX_PARSE = 400_000;

interface RunResult {
  status: number;
  ok: boolean;
  bytes: number;
  text: string;
  /** Characters dropped from `text` by the render budget. */
  dropped: number;
  pretty: boolean;
  ms: number;
}

async function runEndpoint(example: string, signal: AbortSignal): Promise<RunResult> {
  const started = Date.now();
  /**
   * RELATIVE path, always. `SITE_URL` falls back to the production domain
   * because `NEXT_PUBLIC_SITE_URL` is unset in every `.env*`, so an absolute
   * fetch would leave localhost and hit production — and `middleware.ts` sets
   * `connect-src 'self'`, which would block it in the browser anyway. The
   * absolute URL is shown as copyable text only.
   */
  const res = await fetch(`/api/v1${example}`, {
    signal,
    // Read by middleware.ts, which then skips the api_usage tag. 61 of the 86
    // routes set no cacheTtl, so every Run is a CDN miss — without this the
    // docs page would be the top endpoint in our own API analytics.
    headers: { [DOCS_PROBE_HEADER]: '1' },
  });
  const raw = await res.text();
  const ms = Date.now() - started;

  let text = raw;
  let pretty = false;
  if (raw.length <= MAX_PARSE) {
    try {
      text = JSON.stringify(JSON.parse(raw), null, 2);
      pretty = true;
    } catch {
      // Not JSON (an HTML error page, say) — show it as it came.
    }
  }
  const dropped = Math.max(0, text.length - MAX_RENDER);
  return {
    status: res.status,
    ok: res.ok,
    bytes: raw.length,
    text: dropped > 0 ? text.slice(0, MAX_RENDER) : text,
    dropped,
    pretty,
    ms,
  };
}

function bytes(n: number): string {
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
  return `${(n / (1024 * 1024)).toFixed(1)} MB`;
}

/**
 * A real call against a real endpoint, on an explicit Run — never on open.
 * A pasted sample response goes stale in silence, and this repo's whole posture
 * is that a claim should be checkable; so the page checks it in front of you.
 */
export function LiveRun({ example }: { example: string }) {
  const queryClient = useQueryClient();
  const queryKey = useMemo(() => ['api-docs-run', example] as const, [example]);
  const [started, setStarted] = useState(false);

  const { data, error, isFetching, refetch, dataUpdatedAt } = useQuery({
    queryKey,
    queryFn: ({ signal }) => runEndpoint(example, signal),
    // Fires only from the button below. React Query's own dedupe means reopening
    // the same endpoint inside the stale window costs nothing.
    enabled: false,
    retry: false,
    staleTime: 5 * 60 * 1000,
    gcTime: 10 * 60 * 1000,
  });

  /* Abort an in-flight call when the modal closes. React Query aborts the signal
     it handed the queryFn, so the request is really cancelled, not just ignored. */
  useEffect(() => () => { void queryClient.cancelQueries({ queryKey }); }, [queryClient, queryKey]);

  const absolute = absoluteUrl(example);

  return (
    <div className="space-y-2">
      <div className="flex flex-wrap items-center gap-2">
        <button
          type="button"
          onClick={() => { setStarted(true); void refetch(); }}
          disabled={isFetching}
          className="rounded-md border border-[var(--teal-dim)] bg-[var(--teal-faint)] px-3 py-1.5 text-xs font-semibold text-[var(--accent-teal)] transition-colors hover:border-[var(--accent-teal)] disabled:opacity-50"
        >
          {isFetching ? 'running…' : data ? 'run again' : 'Run it'}
        </button>
        <code className="min-w-0 break-all font-mono text-[11px] text-[var(--text-secondary)]">GET {example}</code>
        <CopyButton value={`curl '${absolute}'`} label="copy curl" />
      </div>

      {isFetching && <DiamondLoader text={`calling ${example}`} />}

      {!isFetching && error && (
        <div className="rounded-md border border-[var(--orange-dim)] bg-[var(--orange-faint)] px-3 py-2 text-xs text-[var(--accent-orange)]">
          The call did not complete: {error instanceof Error ? error.message : String(error)}. The endpoint may be
          cold — try again.
        </div>
      )}

      {!isFetching && data && (
        <div className="space-y-1.5">
          <div className="flex flex-wrap items-center gap-x-3 gap-y-1 text-[11px] text-[var(--text-secondary)]">
            <span className={data.ok ? 'font-semibold text-[var(--accent-green)]' : 'font-semibold text-[var(--accent-orange)]'}>
              HTTP {data.status}
            </span>
            <span>{bytes(data.bytes)}</span>
            <span>{data.ms} ms</span>
            {!data.pretty && data.bytes > MAX_PARSE && <span>too large to pretty-print — shown raw</span>}
            <span className="opacity-70">
              {dataUpdatedAt ? `fetched ${new Date(dataUpdatedAt).toLocaleTimeString()}` : null}
            </span>
          </div>
          <pre className="max-h-[42vh] overflow-auto rounded-md border border-[var(--border-color)] bg-[var(--surface-card)] px-3 py-2.5 font-mono text-[11px] leading-relaxed text-[var(--text-primary)]">
            {data.text}
          </pre>
          {data.dropped > 0 && (
            <p className="text-[11px] text-[var(--text-secondary)]">
              Truncated for display — {data.dropped.toLocaleString()} more characters were returned. Run the curl
              above for the whole thing.
            </p>
          )}
        </div>
      )}

      {!started && !data && (
        <p className="text-[11px] text-[var(--text-secondary)]">
          Nothing is fetched until you press Run. The example sends a small <code>limit</code> where the endpoint
          paginates.
        </p>
      )}
    </div>
  );
}
