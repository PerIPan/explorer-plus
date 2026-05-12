'use client';

import { useEffect, useState } from 'react';
import Link from 'next/link';

interface FrameworkChip {
  framework_key: string;
  name: string;
  region: string;
  tier: number;
  license: string | null;
  controls: number;
  ref_ids: string[] | null;
  has_unresolved: boolean;
}

const REGION_LABEL: Record<string, string> = {
  global: 'Global', eu: 'EU', us: 'US', uk: 'UK', apac: 'APAC', mena: 'MENA', americas: 'Americas',
};

export function ComplianceFrameworksSection({ attackId }: { attackId: string }) {
  const [rows, setRows] = useState<FrameworkChip[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [includeAll, setIncludeAll] = useState(false);

  useEffect(() => {
    const url = `/api/v1/compliance/techniques/${encodeURIComponent(attackId)}${includeAll ? '?include_all=1' : ''}`;
    const ctrl = new AbortController();
    setRows(null);
    setError(null);
    fetch(url, { signal: ctrl.signal })
      .then((r) => (r.ok ? r.json() : Promise.reject(new Error(`HTTP ${r.status}`))))
      .then((d) => { if (!ctrl.signal.aborted) setRows(d.frameworks ?? []); })
      .catch((e) => { if (!ctrl.signal.aborted) setError(e.message); });
    return () => ctrl.abort();
  }, [attackId, includeAll]);

  if (error) {
    return (
      <section>
        <h3 className="text-sm font-semibold text-[var(--text-secondary)] uppercase tracking-wider mb-3">Compliance Frameworks</h3>
        <p className="text-xs text-[var(--accent-orange)]">Failed: {error}</p>
      </section>
    );
  }
  if (rows === null) {
    return (
      <section>
        <h3 className="text-sm font-semibold text-[var(--text-secondary)] uppercase tracking-wider mb-3">Compliance Frameworks</h3>
        <p className="text-xs text-[var(--text-secondary)]">Loading...</p>
      </section>
    );
  }
  if (rows.length === 0) {
    return null;
  }

  return (
    <section>
      <div className="flex items-baseline justify-between mb-3">
        <h3 className="text-sm font-semibold text-[var(--text-secondary)] uppercase tracking-wider">
          Compliance Frameworks ({rows.length})
        </h3>
        <label className="text-[10px] text-[var(--text-secondary)]">
          <input
            type="checkbox"
            checked={includeAll}
            onChange={(e) => setIncludeAll(e.target.checked)}
            className="mr-1.5 align-middle"
          />
          Show all tiers
        </label>
      </div>

      <ul className="space-y-1.5">
        {rows.map((r) => (
          <li key={r.framework_key} className="flex items-baseline gap-2 text-xs">
            <Link
              href={`/compliance/${r.framework_key}`}
              className="text-[var(--accent-teal)] hover:underline truncate max-w-[18rem]"
            >
              {r.name}
            </Link>
            <span className="text-[10px] uppercase text-[var(--text-secondary)] px-1 py-0.5 border border-[var(--border-color)] rounded">
              {REGION_LABEL[r.region] ?? r.region}
            </span>
            <span className="text-[var(--text-secondary)] font-mono ml-auto tabular-nums">
              {r.controls} ctrl
            </span>
            {r.ref_ids && r.ref_ids.length > 0 && (
              <span className="text-[var(--text-secondary)] truncate max-w-[14rem]" title={r.ref_ids.join(', ')}>
                {r.ref_ids.slice(0, 3).join(', ')}{r.ref_ids.length > 3 ? ` +${r.ref_ids.length - 3}` : ''}
              </span>
            )}
            {r.has_unresolved && (
              <span className="text-[10px] text-amber-400" title="Some SCF mappings reference ATT&CK IDs not in our v19 dataset">
                v19-drift
              </span>
            )}
          </li>
        ))}
      </ul>
      <div className="pt-3 flex items-baseline justify-between gap-3 flex-wrap">
        <Link href="/compliance" className="text-xs text-[var(--accent-teal)] hover:underline">
          Browse all compliance frameworks
        </Link>
        <span className="text-[10px] text-[var(--text-secondary)] italic">
          via <a href="https://www.securecontrolsframework.com/" target="_blank" rel="noopener noreferrer" className="hover:underline">SCF</a> — <a href="https://creativecommons.org/licenses/by/4.0/" target="_blank" rel="noopener noreferrer" className="hover:underline">CC BY 4.0</a>
        </span>
      </div>
    </section>
  );
}
