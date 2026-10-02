'use client';

import { useState } from 'react';
import Link from 'next/link';

interface DataSourceRow {
  attackId: string;
  name: string;
  techniquesCovered: number;
}

/**
 * Which ATT&CK data sources cover this tactic, ranked by how many of its
 * techniques each one touches.
 *
 * Ranking is what makes this worth showing. Unranked it is noise — Persistence
 * reaches 25 of the 42 data sources, so "the logs for Persistence" would be
 * 60% of everything we know about. Ranked it has a steep head (Process 77%,
 * File 57%, Windows Registry 31%, then a tail), which is an answer.
 *
 * Complements the CISA strip rather than repeating it: this names what to
 * COLLECT (ATT&CK telemetry classes), CISA names where to GO (products and
 * vantage points). For Initial Access CISA says email / web proxy / server
 * application logs / IDS-IPS where this says Process / Network Traffic / File
 * / Application Log — almost no overlap.
 *
 * The route already orders these, so this does not re-sort.
 */
export function TacticTelemetry({
  dataSources,
  techniqueCount,
}: {
  dataSources: DataSourceRow[];
  techniqueCount: number;
}) {
  const [open, setOpen] = useState(false);
  if (dataSources.length === 0 || techniqueCount === 0) return null;

  const top = dataSources[0];

  return (
    <div className="mb-6 rounded-md border border-[var(--border-color)] bg-[var(--surface-card)] p-4">
      <button
        type="button"
        onClick={() => setOpen((v) => !v)}
        className="flex items-center gap-1.5 text-[var(--text-secondary)] hover:text-[var(--text-primary)] transition-colors w-full text-left"
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
        <span className="text-xs font-semibold uppercase tracking-wider">
          Telemetry coverage
        </span>
        <span className="ml-auto text-[10px] text-[var(--text-secondary)] font-mono tabular-nums shrink-0">
          {dataSources.length} data sources · top: {top.name}{' '}
          {Math.round((100 * top.techniquesCovered) / techniqueCount)}%
        </span>
      </button>

      {open && (
        <div className="mt-3">
          <ul className="space-y-1">
            {dataSources.map((d) => {
              const pct = Math.round((100 * d.techniquesCovered) / techniqueCount);
              return (
                <li key={d.attackId} className="flex items-center gap-2 text-xs">
                  <Link
                    href={`/data-sources/${d.attackId}`}
                    prefetch={false}
                    className="text-[var(--text-primary)] hover:underline truncate w-40 shrink-0"
                  >
                    {d.name}
                  </Link>
                  {/* Bar is decorative; the number beside it carries the value. */}
                  <span
                    className="h-1.5 rounded-sm bg-[var(--border-color)] grow max-w-[12rem]"
                    aria-hidden="true"
                  >
                    <span
                      className="block h-full rounded-sm bg-[var(--text-secondary)]"
                      style={{ width: `${pct}%` }}
                    />
                  </span>
                  <span className="text-[var(--text-secondary)] font-mono tabular-nums shrink-0">
                    {d.techniquesCovered}/{techniqueCount} ({pct}%)
                  </span>
                </li>
              );
            })}
          </ul>
          <p className="mt-3 text-[10px] text-[var(--text-secondary)] leading-relaxed">
            Share of this tactic&rsquo;s {techniqueCount} live techniques whose
            ATT&amp;CK detection guidance names each data source. Revoked and
            deprecated techniques are excluded, so these counts match the list
            below.
          </p>
        </div>
      )}
    </div>
  );
}
