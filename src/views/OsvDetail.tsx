'use client';
import { useParams } from 'next/navigation';
import Link from 'next/link';
import { useOsvDetail } from '../hooks/useApi';
import { formatDate } from '../lib/formatDate';
import { PageHeader } from '../components/layout/PageHeader';
import { Badge } from '../components/shared/Badge';
import { DiamondLoader } from '../components/shared/FoldingDiamond';

const SEVERITY_COLORS: Record<string, string> = {
  CRITICAL: 'bg-[var(--pink-faint)] text-[var(--accent-pink)] border-[var(--pink-dim)]',
  HIGH: 'bg-[var(--orange-faint)] text-[var(--accent-orange)] border-[var(--orange-dim)]',
  MEDIUM: 'bg-[var(--yellow-faint)] text-[var(--accent-yellow)] border-[var(--yellow-dim)]',
  LOW: 'bg-[var(--blue-faint)] text-[var(--accent-blue)] border-[var(--blue-dim)]',
};

function SeverityBadge({ severity }: { severity: string | null }) {
  if (!severity) return null;
  const classes =
    SEVERITY_COLORS[severity] ??
    'bg-[var(--hover-overlay)] text-[var(--text-secondary)] border-[var(--border-color)]';
  return (
    <span className={`inline-flex items-center px-2 py-0.5 rounded-full text-xs font-medium border ${classes}`}>
      {severity}
    </span>
  );
}

export function OsvDetail() {
  const { osvId: rawId } = useParams<{ osvId: string }>();
  const osvId = decodeURIComponent(rawId ?? '');
  const { data, isLoading, error } = useOsvDetail(osvId);

  if (isLoading) return <DiamondLoader text={`Loading ${osvId}…`} />;
  if (error || !data) {
    return (
      <div className="space-y-4">
        <PageHeader title="OSV advisory not found" />
        <p className="text-sm text-[var(--text-secondary)]">
          No OSV record matches <span className="font-mono">{osvId}</span>. The ID may have been
          withdrawn or never ingested (we ingest only non-GHSA ecosystems).
        </p>
        <Link
          href="/cti/advisories"
          className="text-sm text-[var(--accent-teal)] hover:underline"
        >
          ← Back to advisories
        </Link>
      </div>
    );
  }

  // Group affected packages by package ecosystem for scanning.
  const byEco = new Map<string, typeof data.affected>();
  for (const a of data.affected) {
    if (!byEco.has(a.packageEcosystem)) byEco.set(a.packageEcosystem, []);
    byEco.get(a.packageEcosystem)!.push(a);
  }

  return (
    <div className="space-y-6">
      <PageHeader
        title={data.osvId}
        subtitle={
          data.summary ??
          `${data.ecosystem} advisory · published ${data.published ? formatDate(data.published) : '—'}`
        }
        breadcrumb={[
          { label: 'Advisories', href: '/cti/advisories' },
          { label: data.osvId },
        ]}
        titleAction={
          <div className="flex items-center gap-2">
            <Badge label={data.ecosystem} variant="yellow" />
            <SeverityBadge severity={data.cvssSeverity} />
            {data.cvssScore != null && (
              <span className="text-xs font-mono text-[var(--text-secondary)]">
                CVSS {data.cvssScore.toFixed(1)}
              </span>
            )}
          </div>
        }
      />

      {/* Aliases (CVEs + trackers) */}
      {data.aliases.length > 0 && (
        <section>
          <h2 className="text-sm font-bold uppercase tracking-wider text-[var(--accent-teal)] mb-2">
            Aliases
          </h2>
          <div className="flex flex-wrap gap-2">
            {data.aliases.map((a) => {
              const isCve = /^CVE-\d{4}-\d+$/.test(a);
              return isCve ? (
                <Link
                  key={a}
                  href={`/cti/cves/${a}`}
                  className="px-2 py-0.5 rounded-md text-xs font-mono border bg-[var(--pink-faint)] text-[var(--accent-pink)] border-[var(--pink-dim)] hover:underline"
                >
                  {a}
                </Link>
              ) : (
                <span
                  key={a}
                  className="px-2 py-0.5 rounded-md text-xs font-mono border bg-[var(--hover-overlay)] text-[var(--text-secondary)] border-[var(--border-color)]"
                >
                  {a}
                </span>
              );
            })}
          </div>
        </section>
      )}

      {/* Details */}
      {data.details && (
        <section>
          <h2 className="text-sm font-bold uppercase tracking-wider text-[var(--accent-teal)] mb-2">
            Description
          </h2>
          <div className="rounded-md border border-[var(--border-color)] bg-[var(--surface-card)] px-4 py-3 text-sm text-[var(--text-primary)] leading-relaxed whitespace-pre-wrap">
            {data.details}
          </div>
        </section>
      )}

      {/* CVSS */}
      {(data.cvssVector || data.severityRaw.length > 0) && (
        <section>
          <h2 className="text-sm font-bold uppercase tracking-wider text-[var(--accent-teal)] mb-2">
            Severity scoring
          </h2>
          {data.cvssVector && (
            <div className="text-xs font-mono text-[var(--text-secondary)] break-all">
              {data.cvssVector}
            </div>
          )}
          {data.severityRaw.length > 0 && (
            <ul className="text-xs text-[var(--text-secondary)] mt-1 space-y-0.5">
              {data.severityRaw.map((s, i) => (
                <li key={i} className="font-mono">
                  <span className="text-[var(--text-primary)]">{s.type ?? 'UNKNOWN'}</span>:{' '}
                  {s.score ?? '—'}
                </li>
              ))}
            </ul>
          )}
        </section>
      )}

      {/* Affected packages, grouped by ecosystem */}
      <section>
        <h2 className="text-sm font-bold uppercase tracking-wider text-[var(--accent-teal)] mb-2">
          Affected packages <span className="font-normal text-[var(--text-secondary)]">({data.packageCount})</span>
        </h2>
        {data.affected.length === 0 ? (
          <p className="text-sm text-[var(--text-secondary)]">
            No affected packages recorded on this advisory.
          </p>
        ) : (
          <div className="space-y-4">
            {[...byEco.entries()].map(([eco, items]) => (
              <div key={eco} className="rounded-md border border-[var(--border-color)] bg-[var(--surface-card)]">
                <div className="px-3 py-1.5 bg-[var(--surface-deep)] border-b border-[var(--border-color)] text-xs uppercase tracking-wider text-[var(--text-secondary)]">
                  {eco} <span className="text-[var(--text-secondary)]">· {items.length} packages</span>
                </div>
                <ul className="divide-y divide-[var(--border-color)]">
                  {items.map((a) => (
                    <li
                      key={`${a.packageEcosystem}:${a.packageName}`}
                      className="px-3 py-2 flex items-start gap-3 text-sm"
                    >
                      <span className="font-mono text-[var(--text-primary)] min-w-0 break-all">
                        {a.packageName}
                      </span>
                      <div className="flex-1" />
                      {a.versions && a.versions.length > 0 && (
                        <span className="text-xs text-[var(--text-secondary)] font-mono">
                          {a.versions.slice(0, 3).join(', ')}
                          {a.versions.length > 3 && ` +${a.versions.length - 3}`}
                        </span>
                      )}
                      {a.ranges && a.ranges.length > 0 && (
                        <span className="text-[10px] uppercase tracking-wider text-[var(--text-secondary)]">
                          {a.ranges.length} range{a.ranges.length === 1 ? '' : 's'}
                        </span>
                      )}
                    </li>
                  ))}
                </ul>
              </div>
            ))}
          </div>
        )}
      </section>

      {/* Footer metadata */}
      <section className="pt-4 border-t border-[var(--border-color)] text-xs text-[var(--text-secondary)] flex flex-wrap gap-6">
        <span>
          Published:{' '}
          <span className="text-[var(--text-primary)]">
            {data.published ? formatDate(data.published) : '—'}
          </span>
        </span>
        <span>
          Modified:{' '}
          <span className="text-[var(--text-primary)]">
            {data.modified ? formatDate(data.modified) : '—'}
          </span>
        </span>
        <span>
          Source:{' '}
          <a
            href={`https://osv.dev/vulnerability/${encodeURIComponent(data.osvId)}`}
            target="_blank"
            rel="noopener noreferrer"
            className="text-[var(--accent-teal)] hover:underline"
          >
            osv.dev ↗
          </a>
        </span>
      </section>
    </div>
  );
}
