'use client';

import { useEffect, useState } from 'react';
import Link from 'next/link';
import { PageHeader } from '../components/layout/PageHeader';

interface Level {
  levelKey: string;
  label: string;
  zone: 'ot' | 'dmz' | 'it';
  description: string;
  sortOrder: number;
  assetCount: number;
  techniqueCount: number;
  boundaryAssetCount: number;
}

interface PlacedAsset {
  attackId: string;
  name: string;
  primaryLevel: string;
  spansLevels: string[];
  isBoundary: boolean;
  rationale: string;
  techniqueCount: number;
}

interface FlowRule {
  fromLevel: string;
  toLevel: string;
  directAllowed: boolean;
  brokerLevel: string | null;
  note: string | null;
}

interface PurdueResponse {
  data: {
    levels: Level[];
    assets: PlacedAsset[];
    flowRules: FlowRule[];
    meta: { techniqueDomain: string; note: string };
  };
}

// Zone colour encodes what is at stake, rather than decorating the row:
// OT is where a breach moves physical things, the DMZ is the checkpoint,
// IT is the corporate network.
const ZONE_STYLE: Record<Level['zone'], { chip: string; rail: string; label: string }> = {
  ot:  { chip: 'bg-[var(--orange-faint)] text-[var(--accent-orange)] border-[var(--orange-dim)]',
         rail: 'bg-[var(--accent-orange)]', label: 'OT' },
  dmz: { chip: 'bg-[var(--yellow-faint)] text-[var(--accent-yellow)] border-[var(--yellow-dim)]',
         rail: 'bg-[var(--accent-yellow)]', label: 'DMZ' },
  it:  { chip: 'bg-[var(--blue-faint)] text-[var(--accent-blue)] border-[var(--blue-dim)]',
         rail: 'bg-[var(--accent-blue)]', label: 'IT' },
};

export function PurdueModel() {
  const [data, setData] = useState<PurdueResponse['data'] | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [activeLevel, setActiveLevel] = useState<string | null>(null);

  useEffect(() => {
    const ctrl = new AbortController();
    fetch('/api/v1/frameworks/purdue', { signal: ctrl.signal })
      .then((r) => (r.ok ? r.json() : Promise.reject(new Error(`HTTP ${r.status}`))))
      .then((d: PurdueResponse) => { if (!ctrl.signal.aborted) setData(d.data); })
      .catch((e) => { if (!ctrl.signal.aborted) setError(e.message); });
    return () => ctrl.abort();
  }, []);

  if (error) {
    return (
      <>
        <PageHeader title="Purdue Model" />
        <p className="text-sm text-[var(--accent-orange)]">Could not load the Purdue model: {error}</p>
      </>
    );
  }
  if (!data) {
    return (
      <>
        <PageHeader title="Purdue Model" />
        <p className="text-sm text-[var(--text-secondary)]">Loading…</p>
      </>
    );
  }

  // Drawn top-down the way an OT network diagram is drawn: enterprise at the
  // top, the physical process at the bottom.
  const stack = [...data.levels].sort((a, b) => b.sortOrder - a.sortOrder);
  const assetsAt = (key: string) => data.assets.filter((a) => a.spansLevels.includes(key));
  const orderedKeys = [...data.levels].sort((a, b) => a.sortOrder - b.sortOrder).map((l) => l.levelKey);
  const ruleFor = (f: string, t: string) => data.flowRules.find((r) => r.fromLevel === f && r.toLevel === t);

  return (
    <>
      <PageHeader
        title="Purdue Model"
        breadcrumb={[{ label: 'Frameworks', href: '/frameworks/owasp' }, { label: 'Purdue Model' }]}
        subtitle="Where each ATT&CK for ICS asset sits in the plant network, and which levels are allowed to talk to each other. Levels are curated from NIST SP 800-82r3 and ISA-95; assets and techniques come from MITRE."
      />

      {/* ── Signature: the level stack ─────────────────────────────────── */}
      <section aria-labelledby="stack-heading" className="mb-10">
        <h2 id="stack-heading" className="sr-only">Purdue levels</h2>
        <ol className="space-y-px">
          {stack.map((l) => {
            const z = ZONE_STYLE[l.zone];
            const here = assetsAt(l.levelKey);
            const open = activeLevel === l.levelKey;
            const isDmz = l.zone === 'dmz';
            return (
              <li key={l.levelKey}>
                <button
                  type="button"
                  onClick={() => setActiveLevel(open ? null : l.levelKey)}
                  aria-expanded={open}
                  className={`w-full text-left flex items-stretch gap-0 border transition-colors duration-150
                    ${isDmz ? 'border-[var(--yellow-dim)] bg-[var(--yellow-faint)]' : 'border-[var(--border-color)] bg-[var(--surface-card)]'}
                    hover:bg-[var(--hover-overlay)]`}
                >
                  <span className={`w-1 shrink-0 ${z.rail}`} aria-hidden="true" />
                  <span className="flex-1 min-w-0 px-3 py-2.5">
                    <span className="flex items-center gap-2 flex-wrap">
                      <span className="font-mono text-xs text-[var(--text-secondary)] w-10 shrink-0">
                        {l.levelKey.replace('_', '.').toUpperCase()}
                      </span>
                      <span className="text-sm font-medium text-[var(--text-primary)]">{l.label}</span>
                      <span className={`text-[10px] uppercase tracking-wider px-1.5 py-0.5 rounded border ${z.chip}`}>
                        {z.label}
                      </span>
                      {isDmz && (
                        <span className="text-[11px] text-[var(--accent-yellow)]">
                          everything between OT and IT terminates here
                        </span>
                      )}
                    </span>
                    <span className="block text-[11px] text-[var(--text-secondary)] mt-0.5">
                      {l.description}
                    </span>
                  </span>
                  <span className="shrink-0 px-3 py-2.5 text-right font-mono text-xs tabular-nums text-[var(--text-secondary)] self-center">
                    <span className="text-[var(--text-primary)]">{l.assetCount}</span> assets
                    <span className="mx-1 text-[var(--border-color)]">·</span>
                    <span className="text-[var(--text-primary)]">{l.techniqueCount}</span> tech
                  </span>
                </button>

                {open && (
                  <div className="border border-t-0 border-[var(--border-color)] bg-[var(--surface-alt)] px-4 py-3">
                    {here.length === 0 ? (
                      <p className="text-xs text-[var(--text-secondary)]">
                        No ATT&CK assets sit at this level. MITRE publishes an asset catalogue for ICS only,
                        so the enterprise levels are empty by design rather than unmapped.
                      </p>
                    ) : (
                      <ul className="flex flex-wrap gap-1.5">
                        {here.map((a) => (
                          <li key={a.attackId}>
                            <Link
                              href={`/assets/${a.attackId}`}
                              className="inline-flex items-center gap-1.5 text-xs px-2 py-1 rounded border border-[var(--border-color)] bg-[var(--surface-card)] hover:border-[var(--border-hover)] transition-colors"
                            >
                              <span className="font-mono text-[var(--text-secondary)]">{a.attackId}</span>
                              <span className="text-[var(--text-primary)]">{a.name}</span>
                              {a.primaryLevel !== l.levelKey && (
                                <span className="text-[10px] text-[var(--text-secondary)]" title={`Primarily at ${a.primaryLevel.replace('_', '.').toUpperCase()}, also present here`}>
                                  also here
                                </span>
                              )}
                            </Link>
                          </li>
                        ))}
                      </ul>
                    )}
                  </div>
                )}
              </li>
            );
          })}
        </ol>
        <p className="mt-2 text-[11px] text-[var(--text-secondary)]">
          Select a level to see the assets present at it. An asset can appear at more than one level —
          a historian sits in site operations and is replicated into the DMZ.
        </p>
      </section>

      {/* ── Flow matrix ───────────────────────────────────────────────── */}
      <section aria-labelledby="flow-heading" className="mb-8">
        <h2 id="flow-heading" className="text-sm font-medium text-[var(--text-primary)] mb-1">
          What may talk to what
        </h2>
        <p className="text-[11px] text-[var(--text-secondary)] mb-3">
          Read a row as the source. <strong className="text-[var(--accent-teal)]">Direct</strong> means a
          single network hop is permitted. <strong className="text-[var(--accent-yellow)]">Brokered</strong> means
          the only route is to terminate a session in the DMZ first — never read it as adjacency.
        </p>
        <div className="overflow-x-auto">
          <table className="text-xs border-collapse">
            <caption className="sr-only">Permitted flows between Purdue levels</caption>
            <thead>
              <tr>
                <th scope="col" className="p-1.5 text-left font-normal text-[var(--text-secondary)]">from → to</th>
                {orderedKeys.map((k) => (
                  <th key={k} scope="col" className="p-1.5 font-mono font-normal text-[var(--text-secondary)]">
                    {k.replace('_', '.').toUpperCase()}
                  </th>
                ))}
              </tr>
            </thead>
            <tbody>
              {orderedKeys.map((f) => (
                <tr key={f}>
                  <th scope="row" className="p-1.5 text-left font-mono font-normal text-[var(--text-secondary)] whitespace-nowrap">
                    {f.replace('_', '.').toUpperCase()}
                  </th>
                  {orderedKeys.map((t) => {
                    if (f === t) {
                      return <td key={t} className="p-1.5 text-center text-[var(--border-color)]" aria-label="same level">·</td>;
                    }
                    const r = ruleFor(f, t);
                    if (!r) return <td key={t} className="p-1.5 text-center">?</td>;
                    const label = r.directAllowed ? 'Direct' : r.brokerLevel ? `Brokered via ${r.brokerLevel.replace('_', '.').toUpperCase()}` : 'Denied';
                    const cls = r.directAllowed
                      ? 'bg-[var(--teal-faint)] text-[var(--accent-teal)]'
                      : r.brokerLevel
                        ? 'bg-[var(--yellow-faint)] text-[var(--accent-yellow)]'
                        : 'text-[var(--text-secondary)]';
                    return (
                      <td key={t} className={`p-1.5 text-center font-mono ${cls}`} title={`${label}${r.note ? ` — ${r.note}` : ''}`}>
                        {r.directAllowed ? '●' : r.brokerLevel ? '◐' : '○'}
                        <span className="sr-only">{label}</span>
                      </td>
                    );
                  })}
                </tr>
              ))}
            </tbody>
          </table>
        </div>
        <ul className="mt-2 flex flex-wrap gap-4 text-[11px] text-[var(--text-secondary)]">
          <li><span className="font-mono text-[var(--accent-teal)]">●</span> direct adjacency</li>
          <li><span className="font-mono text-[var(--accent-yellow)]">◐</span> brokered at the DMZ</li>
          <li><span className="font-mono">○</span> denied</li>
        </ul>
      </section>

      <p className="text-[11px] text-[var(--text-secondary)] border-t border-[var(--border-color)] pt-3">
        {data.meta.note}
      </p>
    </>
  );
}
