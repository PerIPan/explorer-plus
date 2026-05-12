'use client';

import { useEffect, useState } from 'react';
import Link from 'next/link';

interface Row {
  framework_key: string;
  name: string;
  region: string;
  tier: number;
  controls: number;
  techniques_ref: number;
}

const REGION_LABEL: Record<string, string> = {
  global: 'Global', eu: 'EU', us: 'US', uk: 'UK', apac: 'APAC',
};

interface Props {
  /** entityKind drives the API path: groups | software | sectors */
  kind: 'groups' | 'software' | 'sectors';
  /** ATT&CK id for groups/software, slug for sectors. */
  entityId: string;
  /** Title override (default: "Compliance shadow"). */
  title?: string;
}

export function ComplianceShadowSection({ kind, entityId, title }: Props) {
  const [rows, setRows] = useState<Row[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [includeAll, setIncludeAll] = useState(false);

  useEffect(() => {
    const url = `/api/v1/compliance/${kind}/${encodeURIComponent(entityId)}${includeAll ? '?include_all=1' : ''}`;
    const ctrl = new AbortController();
    setRows(null);
    setError(null);
    fetch(url, { signal: ctrl.signal })
      .then((r) => (r.ok ? r.json() : Promise.reject(new Error(`HTTP ${r.status}`))))
      .then((d) => { if (!ctrl.signal.aborted) setRows(d.frameworks ?? []); })
      .catch((e) => { if (!ctrl.signal.aborted) setError(e.message); });
    return () => ctrl.abort();
  }, [kind, entityId, includeAll]);

  if (error) return null;
  if (rows === null) {
    return (
      <div className="bg-[var(--surface-card)] border border-[var(--border-color)] rounded-lg p-5">
        <h3 className="text-sm font-semibold text-[var(--text-secondary)] uppercase tracking-wider mb-3">
          {title ?? 'Compliance shadow'}
        </h3>
        <p className="text-xs text-[var(--text-secondary)]">Loading...</p>
      </div>
    );
  }
  if (rows.length === 0) return null;

  return (
    <div className="bg-[var(--surface-card)] border border-[var(--border-color)] rounded-lg p-5">
      <div className="flex items-baseline justify-between mb-3">
        <h3 className="text-sm font-semibold text-[var(--text-secondary)] uppercase tracking-wider">
          {title ?? 'Compliance shadow'} ({rows.length})
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
            <Link href={`/compliance/${r.framework_key}`} className="text-[var(--accent-teal)] hover:underline truncate max-w-[18rem]">
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

      <p className="mt-3 text-[10px] text-[var(--text-secondary)] italic">
        Frameworks satisfied by addressing the techniques associated with this entity.
        Mappings via{' '}
        <a href="https://www.securecontrolsframework.com/" target="_blank" rel="noopener noreferrer" className="hover:underline">SCF</a>{' '}
        — <a href="https://creativecommons.org/licenses/by/4.0/" target="_blank" rel="noopener noreferrer" className="hover:underline">CC BY 4.0</a>.
      </p>
    </div>
  );
}
