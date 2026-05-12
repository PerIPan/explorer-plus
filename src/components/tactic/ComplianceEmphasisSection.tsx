'use client';

import { useEffect, useState } from 'react';
import Link from 'next/link';

interface Row {
  framework_key: string;
  name: string;
  region: string;
  tier: number;
  techniques_ref: number;
  controls: number;
}

const REGION_LABEL: Record<string, string> = {
  global: 'Global', eu: 'EU', us: 'US', uk: 'UK', apac: 'APAC',
};

export function ComplianceEmphasisSection({ attackId }: { attackId: string }) {
  const [rows, setRows] = useState<Row[] | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    const ctrl = new AbortController();
    setRows(null);
    setError(null);
    fetch(`/api/v1/compliance/tactics/${encodeURIComponent(attackId)}`, { signal: ctrl.signal })
      .then((r) => (r.ok ? r.json() : Promise.reject(new Error(`HTTP ${r.status}`))))
      .then((d) => { if (!ctrl.signal.aborted) setRows(d.frameworks ?? []); })
      .catch((e) => { if (!ctrl.signal.aborted) setError(e.message); });
    return () => ctrl.abort();
  }, [attackId]);

  if (error || rows === null || rows.length === 0) return null;

  return (
    <div className="mb-6 rounded-md border border-[var(--border-color)] bg-[var(--surface-card)] p-4">
      <h3 className="text-xs font-semibold text-[var(--text-secondary)] uppercase tracking-wider mb-3">
        Compliance emphasis — top {rows.length} frameworks
      </h3>
      <ul className="space-y-1">
        {rows.map((r) => (
          <li key={r.framework_key} className="flex items-baseline gap-2 text-xs">
            <Link href={`/compliance/${r.framework_key}`} className="text-[var(--accent-teal)] hover:underline truncate max-w-[20rem]">
              {r.name}
            </Link>
            <span className="text-[10px] uppercase text-[var(--text-secondary)] px-1 py-0.5 border border-[var(--border-color)] rounded">
              {REGION_LABEL[r.region] ?? r.region}
            </span>
            <span className="ml-auto text-[var(--text-secondary)] font-mono tabular-nums">
              {r.techniques_ref} tech · {r.controls} ctrl
            </span>
          </li>
        ))}
      </ul>
      <p className="mt-3 text-[10px] text-[var(--text-secondary)]">
        Frameworks that most frequently reference techniques under this tactic. Mappings via{' '}
        <a href="https://www.securecontrolsframework.com/" target="_blank" rel="noopener noreferrer" className="hover:underline">SCF</a>{' '}
        — <a href="https://creativecommons.org/licenses/by/4.0/" target="_blank" rel="noopener noreferrer" className="hover:underline">CC BY 4.0</a>.
      </p>
    </div>
  );
}
