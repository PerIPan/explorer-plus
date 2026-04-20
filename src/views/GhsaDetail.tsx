'use client';
import { useParams } from 'next/navigation';
import Link from 'next/link';
import { useGhsaDetail } from '../hooks/useApi';
import { formatDate } from '../lib/formatDate';
import { PageHeader } from '../components/layout/PageHeader';
import { Badge } from '../components/shared/Badge';
import { EntityLink } from '../components/shared/EntityLink';
import { DiamondLoader } from '../components/shared/FoldingDiamond';

const SEVERITY_COLORS: Record<string, string> = {
  CRITICAL: 'bg-[var(--pink-faint)] text-[var(--accent-pink)] border-[var(--pink-dim)]',
  HIGH: 'bg-[var(--orange-faint)] text-[var(--accent-orange)] border-[var(--orange-dim)]',
  MEDIUM: 'bg-[var(--yellow-faint)] text-[var(--accent-yellow)] border-[var(--yellow-dim)]',
  LOW: 'bg-[var(--blue-faint)] text-[var(--accent-blue)] border-[var(--blue-dim)]',
};

function SeverityBadge({ severity }: { severity: string | null }) {
  if (!severity) return null;
  const classes = SEVERITY_COLORS[severity] ?? 'bg-[var(--hover-overlay)] text-[var(--text-secondary)] border-[var(--border-color)]';
  return (
    <span className={`inline-flex items-center px-2 py-0.5 rounded-full text-xs font-medium border ${classes}`}>
      {severity}
    </span>
  );
}

export function GhsaDetail() {
  const { ghsaId: rawId } = useParams<{ ghsaId: string }>();
  // Only normalize the GHSA- prefix — the 12-char random segment is stored
  // lowercase in GitHub's canonical form (e.g. GHSA-g4vj-cjjj-v7hg).
  const ghsaId = (rawId ?? '').replace(/^ghsa-/i, 'GHSA-');
  const { data, isLoading, error } = useGhsaDetail(ghsaId);

  if (isLoading) return <DiamondLoader text="Loading GHSA advisory..." />;
  if (error || !data) {
    return (
      <div className="text-[var(--accent-orange)] text-sm py-8 text-center">
        Failed to load GHSA advisory.
      </div>
    );
  }

  const isWithdrawn = Boolean(data.withdrawnAt);

  return (
    <div className="space-y-6">
      <PageHeader
        title={data.ghsaId}
        subtitle={data.summary ?? 'GitHub Security Advisory'}
        actions={
          <div className="flex items-center gap-2">
            <SeverityBadge severity={data.severity} />
            {data.cvssScore != null && (
              <span className="font-mono text-xs text-[var(--text-secondary)]">CVSS {data.cvssScore.toFixed(1)}</span>
            )}
            <a
              href={`https://github.com/advisories/${data.ghsaId}`}
              target="_blank"
              rel="noopener noreferrer"
              className="text-xs text-[var(--accent-teal)] hover:underline"
            >
              View on GitHub ↗
            </a>
          </div>
        }
      />

      {isWithdrawn && (
        <div className="border border-[var(--orange-dim)] bg-[var(--orange-faint)] text-[var(--accent-orange)] text-sm rounded-lg px-4 py-3">
          <strong>Withdrawn.</strong> This advisory was revoked by GitHub on{' '}
          {formatDate(data.withdrawnAt!)}. Historical record preserved.
        </div>
      )}

      {/* Header facts */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
        <div className="bg-[var(--surface-card)] border border-[var(--border-color)] rounded-md p-3">
          <div className="text-[10px] uppercase tracking-wider text-[var(--text-secondary)] mb-1">CVE alias</div>
          {data.cveId ? (
            <Link href={`/cti/cves/${data.cveId}`} className="font-mono text-xs text-[var(--accent-pink)] hover:underline">
              {data.cveId}
            </Link>
          ) : (
            <span className="text-xs text-[var(--text-secondary)]">GHSA-only</span>
          )}
        </div>
        <div className="bg-[var(--surface-card)] border border-[var(--border-color)] rounded-md p-3">
          <div className="text-[10px] uppercase tracking-wider text-[var(--text-secondary)] mb-1">Published</div>
          <div className="text-xs text-[var(--text-primary)]">{formatDate(data.publishedAt)}</div>
        </div>
        <div className="bg-[var(--surface-card)] border border-[var(--border-color)] rounded-md p-3">
          <div className="text-[10px] uppercase tracking-wider text-[var(--text-secondary)] mb-1">Packages</div>
          <div className="text-xs text-[var(--text-primary)]">{data.packageCount}</div>
        </div>
        <div className="bg-[var(--surface-card)] border border-[var(--border-color)] rounded-md p-3">
          <div className="text-[10px] uppercase tracking-wider text-[var(--text-secondary)] mb-1">Techniques</div>
          <div className="text-xs text-[var(--text-primary)]">{data.techniqueCount}</div>
        </div>
      </div>

      {/* Description */}
      {data.description && (
        <section>
          <h2 className="text-sm font-semibold text-[var(--text-primary)] uppercase tracking-wider mb-2">Description</h2>
          <p className="text-sm text-[var(--text-secondary)] whitespace-pre-wrap leading-relaxed">{data.description}</p>
        </section>
      )}

      {/* CVSS vector */}
      {data.cvssVector && (
        <section>
          <h2 className="text-sm font-semibold text-[var(--text-primary)] uppercase tracking-wider mb-2">CVSS v3.1</h2>
          <div className="text-xs font-mono text-[var(--text-secondary)] bg-[var(--surface-card)] border border-[var(--border-color)] rounded p-2">
            {data.cvssVector}
          </div>
          {data.cvssV4Score != null && data.cvssV4Vector && (
            <>
              <h3 className="text-xs text-[var(--text-secondary)] mt-3 mb-1">CVSS v4 — {data.cvssV4Score.toFixed(1)}</h3>
              <div className="text-xs font-mono text-[var(--text-secondary)] bg-[var(--surface-card)] border border-[var(--border-color)] rounded p-2">
                {data.cvssV4Vector}
              </div>
            </>
          )}
        </section>
      )}

      {/* CWEs */}
      {data.cwes.length > 0 && (
        <section>
          <h2 className="text-sm font-semibold text-[var(--text-primary)] uppercase tracking-wider mb-2">
            CWE Weaknesses ({data.cwes.length})
          </h2>
          <div className="flex flex-wrap gap-1.5">
            {data.cwes.map((cwe) => (
              <a
                key={cwe}
                href={`https://cwe.mitre.org/data/definitions/${cwe.replace(/^CWE-/i, '')}.html`}
                target="_blank"
                rel="noopener noreferrer"
                className="text-[10px] px-2 py-0.5 rounded bg-[var(--surface-card)] border border-[var(--border-color)] text-[var(--accent-blue)] hover:border-[var(--blue-dim)] hover:underline transition-colors font-mono"
              >
                {cwe}
              </a>
            ))}
          </div>
        </section>
      )}

      {/* Affected packages */}
      {data.packages.length > 0 && (
        <section>
          <h2 className="text-sm font-semibold text-[var(--text-primary)] uppercase tracking-wider mb-2">
            Affected Packages ({data.packages.length})
          </h2>
          <div className="overflow-x-auto">
            <table className="w-full text-xs">
              <thead className="bg-[var(--surface-deep)] text-[var(--text-secondary)]">
                <tr>
                  <th className="text-left px-3 py-2">Ecosystem</th>
                  <th className="text-left px-3 py-2">Package</th>
                  <th className="text-left px-3 py-2">Vulnerable Range</th>
                  <th className="text-left px-3 py-2">Fixed Version</th>
                </tr>
              </thead>
              <tbody>
                {data.packages.map((pkg, i) => (
                  <tr key={`${pkg.ecosystem}/${pkg.packageName}/${i}`} className="border-t border-[var(--border-color)]">
                    <td className="px-3 py-2">
                      <Badge label={pkg.ecosystem} variant="blue" />
                    </td>
                    <td className="px-3 py-2">
                      <Link
                        href={`/packages/${pkg.ecosystem}/${encodeURIComponent(pkg.packageName)}`}
                        className="font-mono text-[var(--text-primary)] hover:text-[var(--accent-teal)] hover:underline"
                      >
                        {pkg.packageName}
                      </Link>
                    </td>
                    <td className="px-3 py-2 font-mono text-[var(--text-secondary)]">
                      {pkg.vulnerableRange ?? '—'}
                    </td>
                    <td className="px-3 py-2 font-mono text-[var(--accent-green)]">
                      {pkg.fixedVersion ?? '—'}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </section>
      )}

      {/* Linked ATT&CK techniques */}
      {data.techniques.length > 0 && (
        <section>
          <h2 className="text-sm font-semibold text-[var(--text-primary)] uppercase tracking-wider mb-2">
            Linked ATT&CK Techniques ({data.techniques.length})
          </h2>
          <div className="flex flex-wrap gap-1.5">
            {data.techniques.map((t) => (
              <EntityLink key={t.attackId} type="technique" attackId={t.attackId} name={t.name} useMap />
            ))}
          </div>
        </section>
      )}

      {/* Attack patterns (CAPEC) linked via CWE overlap */}
      {data.capecPatterns && data.capecPatterns.length > 0 && (
        <section>
          <h2 className="text-sm font-semibold text-[var(--text-primary)] uppercase tracking-wider mb-2">
            Attack Patterns (CAPEC) — {data.capecPatterns.length}
          </h2>
          <div className="flex flex-wrap gap-1.5">
            {data.capecPatterns.map((p) => (
              <Link
                key={p.capecId}
                href={`/cti/capec/${p.capecId}`}
                title={p.severity ? `${p.name} · Severity: ${p.severity}` : p.name}
                className="inline-flex items-center gap-1 px-2 py-0.5 rounded-md text-[11px] border bg-[var(--yellow-faint)] text-[var(--accent-yellow)] border-[var(--yellow-dim)] hover:underline"
              >
                <span className="font-mono">{p.capecId}</span>
                <span>{p.name}</span>
              </Link>
            ))}
          </div>
        </section>
      )}
    </div>
  );
}
