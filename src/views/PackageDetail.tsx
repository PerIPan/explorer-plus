'use client';
import { useParams } from 'next/navigation';
import Link from 'next/link';
import { usePackageDetail } from '../hooks/useApi';
import { formatDate } from '../lib/formatDate';
import { PageHeader } from '../components/layout/PageHeader';
import { Badge } from '../components/shared/Badge';
import { EntityLink } from '../components/shared/EntityLink';
import { FrameworkMapCard } from '../components/relationships/shared/FrameworkMapCard';
import { DiamondLoader } from '../components/shared/FoldingDiamond';
import { ECOSYSTEM_BY_CANONICAL } from '../lib/ecosystems';

const SEVERITY_COLORS: Record<string, string> = {
  CRITICAL: 'bg-[var(--pink-faint)] text-[var(--accent-pink)] border-[var(--pink-dim)]',
  HIGH: 'bg-[var(--orange-faint)] text-[var(--accent-orange)] border-[var(--orange-dim)]',
  MEDIUM: 'bg-[var(--yellow-faint)] text-[var(--accent-yellow)] border-[var(--yellow-dim)]',
  LOW: 'bg-[var(--blue-faint)] text-[var(--accent-blue)] border-[var(--blue-dim)]',
};

const SEVERITY_ORDER = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'];

function SeverityBadge({ severity }: { severity: string | null }) {
  if (!severity) return <span className="text-[var(--text-secondary)] text-xs">—</span>;
  const classes = SEVERITY_COLORS[severity] ?? 'bg-[var(--hover-overlay)] text-[var(--text-secondary)] border-[var(--border-color)]';
  return (
    <span className={`inline-flex items-center px-2 py-0.5 rounded-full text-[10px] font-medium border ${classes}`}>
      {severity}
    </span>
  );
}

export function PackageDetail() {
  const { ecosystem: rawEco, nameEncoded: rawName } = useParams<{ ecosystem: string; nameEncoded: string }>();
  const ecosystem = rawEco ?? '';
  const nameEncoded = rawName ?? '';
  const { data, isLoading, error } = usePackageDetail(ecosystem, nameEncoded);

  if (isLoading) return <DiamondLoader text="Loading package..." />;
  if (error || !data) {
    return (
      <div className="text-[var(--accent-orange)] text-sm py-8 text-center">
        Failed to load package details.
      </div>
    );
  }

  const topSeverity = SEVERITY_ORDER.find((s) => data.severityCounts[s]) ?? null;

  return (
    <div className="space-y-4">
      <PageHeader
        title={data.packageName}
        subtitle={`${data.ecosystem} — ${data.advisoryCount} advisories · 360 view`}
        actions={
          <div className="flex items-center gap-3 flex-wrap">
            <Badge label="package" variant="blue" />
            <Badge label={data.ecosystem} variant="blue" />
            {topSeverity && <SeverityBadge severity={topSeverity} />}
            {data.purl && (
              <span className="font-mono text-xs text-[var(--text-secondary)] truncate max-w-md" title={data.purl}>
                {data.purl}
              </span>
            )}
            {(() => {
              // Packages store ecosystem lowercased; lookup by canonical works
              // for the GHSA side (npm, pypi, …). No match → render nothing.
              const meta = ECOSYSTEM_BY_CANONICAL.get(data.ecosystem);
              return meta ? (
                <Link
                  href={`/ecosystems/${meta.slug}`}
                  className="text-xs text-[var(--accent-teal)] hover:underline"
                >
                  Explore all {meta.displayName} →
                </Link>
              ) : null;
            })()}
          </div>
        }
      />

      {/* Severity breakdown */}
      {Object.keys(data.severityCounts).length > 0 && (
        <FrameworkMapCard label="Severity Breakdown" labelColor="#f472b6" count={Object.keys(data.severityCounts).length}>
          <div className="flex flex-wrap gap-2">
            {SEVERITY_ORDER
              .filter((s) => data.severityCounts[s])
              .map((s) => (
                <span
                  key={s}
                  className={`inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-[10px] font-medium border ${SEVERITY_COLORS[s]}`}
                >
                  {s} <span className="font-mono">×{data.severityCounts[s]}</span>
                </span>
              ))}
          </div>
        </FrameworkMapCard>
      )}

      {/* Advisories */}
      <FrameworkMapCard label="GHSA Advisories" labelColor="#f472b6" count={data.advisories.length}>
        {data.advisories.length === 0 ? (
          <p className="text-xs text-[var(--text-secondary)]">No advisories.</p>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-xs">
              <thead className="bg-[var(--surface-deep)] text-[var(--text-secondary)]">
                <tr>
                  <th className="text-left px-3 py-2 w-24">Severity</th>
                  <th className="text-left px-3 py-2">GHSA</th>
                  <th className="text-left px-3 py-2">CVE</th>
                  <th className="text-left px-3 py-2">Summary</th>
                  <th className="text-left px-3 py-2">Vulnerable Range</th>
                  <th className="text-left px-3 py-2">Fixed</th>
                  <th className="text-left px-3 py-2 w-24">Published</th>
                </tr>
              </thead>
              <tbody>
                {data.advisories.map((a) => (
                  <tr
                    key={`${a.ghsaId}|${a.vulnerableRange ?? ''}`}
                    className="border-t border-[var(--border-color)] align-top"
                  >
                    <td className="px-3 py-2">
                      <SeverityBadge severity={a.severity} />
                    </td>
                    <td className="px-3 py-2">
                      <Link href={`/cti/ghsa/${a.ghsaId}`} className="font-mono text-[var(--accent-teal)] hover:underline">
                        {a.ghsaId}
                      </Link>
                    </td>
                    <td className="px-3 py-2">
                      {a.cveId ? (
                        <Link href={`/cti/cves/${a.cveId}`} className="font-mono text-[var(--accent-pink)] hover:underline">
                          {a.cveId}
                        </Link>
                      ) : (
                        <span className="text-[var(--text-secondary)]">—</span>
                      )}
                    </td>
                    <td className="px-3 py-2 text-[var(--text-secondary)] max-w-sm line-clamp-2">
                      {a.summary ?? '—'}
                    </td>
                    <td className="px-3 py-2 font-mono text-[var(--text-secondary)]">
                      {a.vulnerableRange ?? '—'}
                    </td>
                    <td className="px-3 py-2 font-mono text-[var(--accent-green)]">
                      {a.fixedVersion ?? '—'}
                    </td>
                    <td className="px-3 py-2 text-[var(--text-secondary)]">
                      {formatDate(a.publishedAt)}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </FrameworkMapCard>

      {/* Linked techniques */}
      <FrameworkMapCard
        label="Linked ATT&CK Techniques"
        labelColor="#14b8a6"
        count={data.linkedTechniques.length}
        defaultOpen={data.linkedTechniques.length > 0}
      >
        {data.linkedTechniques.length === 0 ? (
          <p className="text-xs text-[var(--text-secondary)]">No techniques reachable via CWE→CAPEC bridge.</p>
        ) : (
          <div className="flex flex-wrap gap-1.5">
            {data.linkedTechniques.map((t) => (
              <EntityLink key={t.attackId} type="technique" attackId={t.attackId} name={t.name} useMap />
            ))}
          </div>
        )}
      </FrameworkMapCard>
    </div>
  );
}
