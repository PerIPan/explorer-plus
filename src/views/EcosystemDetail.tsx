'use client';
import Link from 'next/link';
import { useParams } from 'next/navigation';
import { useEcosystemDetail } from '../hooks/useApi';
import { PageHeader } from '../components/layout/PageHeader';
import { Badge } from '../components/shared/Badge';
import { DiamondLoader } from '../components/shared/FoldingDiamond';
import { formatDate } from '../lib/formatDate';
import { CATEGORY_LABELS, type EcosystemCategory } from '../lib/ecosystems';
import type { EcosystemDetail as EcosystemDetailType } from '../lib/types';

const CATEGORY_BADGE_VARIANT: Record<EcosystemCategory, 'teal' | 'orange' | 'purple' | 'yellow'> = {
  'package-manager': 'teal',
  'os-distro': 'orange',
  'container-distro': 'purple',
  'kernel-misc': 'yellow',
};

const SEVERITY_COLORS: Record<string, string> = {
  CRITICAL: 'bg-[var(--pink-faint)] text-[var(--accent-pink)] border-[var(--pink-dim)]',
  HIGH: 'bg-[var(--orange-faint)] text-[var(--accent-orange)] border-[var(--orange-dim)]',
  MEDIUM: 'bg-[var(--yellow-faint)] text-[var(--accent-yellow)] border-[var(--yellow-dim)]',
  LOW: 'bg-[var(--blue-faint)] text-[var(--accent-blue)] border-[var(--blue-dim)]',
};

function SeverityBadge({ severity }: { severity: string | null }) {
  if (!severity) return <span className="text-[var(--text-secondary)] text-xs">—</span>;
  const classes =
    SEVERITY_COLORS[severity] ??
    'bg-[var(--hover-overlay)] text-[var(--text-secondary)] border-[var(--border-color)]';
  return (
    <span className={`inline-flex items-center px-2 py-0.5 rounded-full text-[10px] font-medium border ${classes}`}>
      {severity}
    </span>
  );
}

function SeverityBreakdownBar({ breakdown }: { breakdown: EcosystemDetailType['severityBreakdown'] }) {
  const total = breakdown.CRITICAL + breakdown.HIGH + breakdown.MEDIUM + breakdown.LOW + breakdown.UNRATED;
  if (total === 0) return null;
  const unratedPct = Math.round((breakdown.UNRATED / total) * 100);
  return (
    <div
      title={unratedPct > 20
        ? `${unratedPct}% unrated — distros like Chainguard strip CVSS on rebuild advisories`
        : 'Severity distribution'}
    >
      <div className="flex w-full h-3 rounded overflow-hidden">
        {(['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'UNRATED'] as const).map((k) => {
          const pct = (breakdown[k] / total) * 100;
          if (pct === 0) return null;
          const bg =
            k === 'CRITICAL' ? 'bg-[var(--accent-pink)]' :
            k === 'HIGH' ? 'bg-[var(--accent-orange)]' :
            k === 'MEDIUM' ? 'bg-[var(--accent-yellow)]' :
            k === 'LOW' ? 'bg-[var(--accent-blue)]' :
            'bg-[var(--border-color)]';
          return <div key={k} className={bg} style={{ width: `${pct}%` }} title={`${k}: ${breakdown[k].toLocaleString()}`} />;
        })}
      </div>
      <div className="flex flex-wrap gap-3 text-xs mt-2">
        <span><span className="text-[var(--accent-pink)]">●</span> CRITICAL {breakdown.CRITICAL.toLocaleString()}</span>
        <span><span className="text-[var(--accent-orange)]">●</span> HIGH {breakdown.HIGH.toLocaleString()}</span>
        <span><span className="text-[var(--accent-yellow)]">●</span> MEDIUM {breakdown.MEDIUM.toLocaleString()}</span>
        <span><span className="text-[var(--accent-blue)]">●</span> LOW {breakdown.LOW.toLocaleString()}</span>
        <span className="text-[var(--text-secondary)]">● Unrated {breakdown.UNRATED.toLocaleString()} ({unratedPct}%)</span>
      </div>
    </div>
  );
}

function StatTile({ label, value, tone = 'default' }: { label: string; value: number; tone?: 'default' | 'pink' }) {
  const valueClass = tone === 'pink' ? 'text-[var(--accent-pink)]' : 'text-[var(--text-primary)]';
  return (
    <div className="rounded-md border border-[var(--border-color)] bg-[var(--surface-card)] px-4 py-3">
      <div className="text-[10px] uppercase tracking-wider text-[var(--text-secondary)]">{label}</div>
      <div className={`text-xl font-mono mt-1 ${valueClass}`}>{value.toLocaleString()}</div>
    </div>
  );
}

function advisoryHref(a: EcosystemDetailType['recentAdvisories'][number]): string {
  return a.source === 'GHSA'
    ? `/cti/ghsa/${a.advisoryId}`
    : `/cti/osv/${encodeURIComponent(a.advisoryId)}`;
}

export function EcosystemDetail() {
  const { slug: rawSlug } = useParams<{ slug: string }>();
  const slug = rawSlug ?? '';
  const { data, isLoading, error } = useEcosystemDetail(slug);

  if (isLoading) return <DiamondLoader text={`Loading ${slug}…`} />;
  if (error || !data) {
    return (
      <div className="space-y-4">
        <PageHeader
          title="Ecosystem not found"
          breadcrumb={[{ label: 'Ecosystems', href: '/ecosystems' }, { label: slug }]}
        />
        <p className="text-sm text-[var(--text-secondary)]">
          No ecosystem matches <span className="font-mono">{slug}</span>.
        </p>
        <Link href="/ecosystems" className="text-sm text-[var(--accent-teal)] hover:underline">
          ← Back to all ecosystems
        </Link>
      </div>
    );
  }

  const { meta, stats, severityBreakdown, topPackages, recentAdvisories } = data;

  return (
    <div className="space-y-6">
      <PageHeader
        title={meta.displayName}
        subtitle={meta.description}
        breadcrumb={[{ label: 'Ecosystems', href: '/ecosystems' }, { label: meta.displayName }]}
        titleAction={
          <Badge
            label={CATEGORY_LABELS[meta.category]}
            variant={CATEGORY_BADGE_VARIANT[meta.category]}
          />
        }
      />

      {/* Header meta + quick links */}
      <div className="flex flex-wrap items-center gap-3 text-xs">
        {meta.homepage && (
          <a
            href={meta.homepage}
            target="_blank"
            rel="noopener noreferrer"
            className="text-[var(--accent-teal)] hover:underline"
          >
            Upstream ↗
          </a>
        )}
        <Link
          href={`/cti/advisories?ecosystem=${encodeURIComponent(meta.canonical)}&severity=`}
          className="text-[var(--accent-teal)] hover:underline"
        >
          Browse all advisories →
        </Link>
      </div>

      {/* Stats strip */}
      <section className="grid grid-cols-2 md:grid-cols-4 gap-3">
        <StatTile label="Total advisories" value={stats.total} />
        <StatTile label="Last 14 days" value={stats.last14d} />
        <StatTile label="Last 30 days" value={stats.last30d} />
        <StatTile label="CRITICAL (30d)" value={stats.criticalLast30d} tone="pink" />
      </section>

      {/* Severity breakdown */}
      <section>
        <h2 className="text-sm font-bold uppercase tracking-wider text-[var(--accent-teal)] mb-2">
          Severity breakdown
        </h2>
        <div className="rounded-md border border-[var(--border-color)] bg-[var(--surface-card)] px-4 py-3">
          <SeverityBreakdownBar breakdown={severityBreakdown} />
        </div>
      </section>

      {/* Top packages */}
      <section>
        <h2 className="text-sm font-bold uppercase tracking-wider text-[var(--accent-teal)] mb-2">
          Top affected packages <span className="font-normal text-[var(--text-secondary)]">({topPackages.length})</span>
        </h2>
        {topPackages.length === 0 ? (
          <p className="text-sm text-[var(--text-secondary)]">No per-package data for this ecosystem.</p>
        ) : (
          <div className="rounded-md border border-[var(--border-color)] bg-[var(--surface-card)]">
            <ul className="divide-y divide-[var(--border-color)]">
              {topPackages.map((p) => (
                <li key={p.packageName} className="px-3 py-2 flex items-center justify-between">
                  <Link
                    href={`/packages/${encodeURIComponent(meta.canonical)}/${encodeURIComponent(p.packageName)}`}
                    className="font-mono text-sm text-[var(--accent-teal)] hover:underline truncate"
                  >
                    {p.packageName}
                  </Link>
                  <span className="text-xs text-[var(--text-secondary)] font-mono ml-4 shrink-0">
                    {p.advisoryCount.toLocaleString()} advisor{p.advisoryCount === 1 ? 'y' : 'ies'}
                  </span>
                </li>
              ))}
            </ul>
          </div>
        )}
      </section>

      {/* Recent advisories */}
      <section>
        <h2 className="text-sm font-bold uppercase tracking-wider text-[var(--accent-teal)] mb-2">
          Recent advisories <span className="font-normal text-[var(--text-secondary)]">(top {recentAdvisories.length} by severity)</span>
        </h2>
        {recentAdvisories.length === 0 ? (
          <p className="text-sm text-[var(--text-secondary)]">No advisories in the database yet.</p>
        ) : (
          <div className="rounded-md border border-[var(--border-color)]">
            <ul className="divide-y divide-[var(--border-color)]">
              {recentAdvisories.map((a) => (
                <li key={`${a.source}:${a.advisoryId}`} className="px-3 py-2 bg-[var(--surface-card)]">
                  <div className="grid grid-cols-[auto_auto_auto_1fr_auto] items-center gap-3 text-xs">
                    <SeverityBadge severity={a.severity} />
                    <span
                      className={`inline-flex items-center px-1.5 py-0.5 rounded-full text-[10px] font-semibold border ${
                        a.source === 'GHSA'
                          ? 'bg-[var(--teal-faint)] text-[var(--accent-teal)] border-[var(--teal-dim)]'
                          : 'bg-[var(--yellow-faint)] text-[var(--accent-yellow)] border-[var(--yellow-dim)]'
                      }`}
                    >
                      {a.source}
                    </span>
                    <Link
                      href={advisoryHref(a)}
                      className="font-mono text-[var(--accent-teal)] hover:underline truncate"
                    >
                      {a.advisoryId}
                      {a.cveId && <span className="ml-2 text-[var(--accent-pink)]">{a.cveId}</span>}
                    </Link>
                    {a.summary ? (
                      <span
                        className="text-[11px] text-[var(--text-secondary)] truncate"
                        title={a.summary}
                      >
                        {a.summary}
                      </span>
                    ) : (
                      <span />
                    )}
                    <span className="text-[10px] text-[var(--text-secondary)] shrink-0">
                      {a.publishedAt ? formatDate(a.publishedAt) : '—'}
                    </span>
                  </div>
                </li>
              ))}
            </ul>
          </div>
        )}
        {recentAdvisories.length > 0 && (
          <div className="text-right mt-2">
            <Link
              href={`/cti/advisories?ecosystem=${encodeURIComponent(meta.canonical)}&severity=`}
              className="text-xs text-[var(--accent-teal)] hover:underline"
            >
              View all {meta.displayName} advisories →
            </Link>
          </div>
        )}
      </section>
    </div>
  );
}
