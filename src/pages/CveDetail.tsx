import { useState, useEffect } from 'react';
import { usePageTitle } from '../hooks/usePageTitle';
import { useParams, Link } from 'react-router-dom';
import { isSafeUrl } from '../lib/urlSafety';
import { useCveDetail } from '../hooks/useApi';
import { PageHeader } from '../components/layout/PageHeader';
import { Badge } from '../components/shared/Badge';
import { EntityLink } from '../components/shared/EntityLink';

type TabId = 'overview' | 'techniques' | 'reports';

const TABS: { id: TabId; label: string }[] = [
  { id: 'overview', label: 'Overview' },
  { id: 'techniques', label: 'Techniques' },
  { id: 'reports', label: 'Related Reports' },
];

const SEVERITY_COLORS: Record<string, string> = {
  CRITICAL: 'bg-[var(--pink-faint)] text-[var(--accent-pink)] border-[var(--pink-dim)]',
  HIGH: 'bg-[var(--orange-faint)] text-[var(--accent-orange)] border-[var(--orange-dim)]',
  MEDIUM: 'bg-[var(--yellow-faint)] text-[var(--accent-yellow)] border-[var(--yellow-dim)]',
  LOW: 'bg-[var(--blue-faint)] text-[var(--accent-blue)] border-[var(--blue-dim)]',
};

const SOURCE_VARIANTS: Record<string, 'teal' | 'orange' | 'purple' | 'blue' | 'green' | 'pink'> = {
  otx: 'teal',
  cisa_kev: 'blue',
  nvd: 'purple',
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

function formatDate(iso: string | null): string {
  if (!iso) return '—';
  return new Date(iso).toLocaleDateString('en-US', {
    year: 'numeric', month: 'short', day: 'numeric',
  });
}

/** Parse CVSS vector string into readable components */
function parseCvssVector(vector: string | null): Array<{ label: string; value: string; _key: string }> {
  if (!vector) return [];
  const parts = vector.split('/').slice(1); // skip "CVSS:3.1"
  const labels: Record<string, string> = {
    AV: 'Attack Vector',
    AC: 'Attack Complexity',
    PR: 'Privileges Required',
    UI: 'User Interaction',
    S: 'Scope',
    C: 'Confidentiality',
    I: 'Integrity',
    A: 'Availability',
  };
  const valueMap: Record<string, Record<string, string>> = {
    AV: { N: 'Network', A: 'Adjacent', L: 'Local', P: 'Physical' },
    AC: { L: 'Low', H: 'High' },
    PR: { N: 'None', L: 'Low', H: 'High' },
    UI: { N: 'None', R: 'Required' },
    S: { U: 'Unchanged', C: 'Changed' },
    C: { N: 'None', L: 'Low', H: 'High' },
    I: { N: 'None', L: 'Low', H: 'High' },
    A: { N: 'None', L: 'Low', H: 'High' },
  };
  return parts.map((p, i) => {
    const [key, val] = p.split(':');
    return {
      label: labels[key] ?? key,
      value: valueMap[key]?.[val] ?? val,
      _key: `${key}-${i}`,
    };
  });
}

export function CveDetail() {
  const { cveId } = useParams<{ cveId: string }>();
  const { data, isLoading, error } = useCveDetail(cveId ?? '');
  usePageTitle(data ? data.cveId : 'CVE');
  const [activeTab, setActiveTab] = useState<TabId>('overview');

  // Reset tab when navigating between CVEs
  useEffect(() => { setActiveTab('overview'); }, [cveId]);

  if (isLoading) {
    return (
      <div className="flex items-center gap-3 text-[var(--text-secondary)] py-12">
        <span className="inline-block w-5 h-5 border-2 border-[var(--teal-dim)] border-t-[var(--accent-teal)] rounded-full animate-spin" />
        Loading CVE details...
      </div>
    );
  }

  if (error || !data) {
    return (
      <div className="space-y-4">
        <PageHeader title={cveId ?? 'CVE'} subtitle="Vulnerability Details" />
        <p className="text-[var(--text-secondary)] text-sm py-6">
          CVE not found or not yet enriched.{' '}
          <Link to="/cti/cves" className="text-[var(--accent-teal)] hover:underline">
            Back to CVEs
          </Link>
        </p>
      </div>
    );
  }

  const cvssComponents = parseCvssVector(data.cvssVector);

  return (
    <div className="space-y-4">
      {/* Header */}
      <div>
        <div className="flex items-center gap-2 mb-2">
          <SeverityBadge severity={data.cvssSeverity} />
          {data.cvssScore != null && (
            <span className="inline-flex items-center px-2 py-0.5 rounded-full text-xs font-medium border bg-[var(--blue-faint)] text-[var(--accent-blue)] border-[var(--blue-dim)]">
              CVSS {data.cvssScore.toFixed(1)}
            </span>
          )}
          {data.cweId && (
            <span className="inline-flex items-center px-2 py-0.5 rounded-full text-xs font-medium border bg-[var(--hover-overlay)] text-[var(--text-secondary)] border-[var(--border-color)]">
              {data.cweId}
            </span>
          )}
        </div>
        <PageHeader title={data.cveId} subtitle={data.publishedAt ? `Published ${formatDate(data.publishedAt)}` : 'Vulnerability Details'} />
      </div>

      {/* Tabs */}
      <div className="flex gap-0 border-b border-[var(--border-color)]">
        {TABS.map((tab) => {
          const count = tab.id === 'techniques' ? data.techniques.length
            : tab.id === 'reports' ? data.reports.length
            : undefined;
          return (
            <button
              key={tab.id}
              onClick={() => setActiveTab(tab.id)}
              className={`px-4 py-2.5 text-sm font-medium transition-colors
                ${activeTab === tab.id
                  ? 'text-[var(--accent-teal)] border-b-2 border-[var(--accent-teal)]'
                  : 'text-[var(--text-secondary)] hover:text-[var(--text-primary)]'
                }`}
            >
              {tab.label}{count != null ? ` (${count})` : ''}
            </button>
          );
        })}
      </div>

      {/* Tab Content */}
      <div className="pt-2">
        {activeTab === 'overview' && (
          <div className="space-y-6">
            {/* Description */}
            {data.description && (
              <section>
                <h3 className="text-sm font-semibold text-[var(--text-secondary)] uppercase tracking-wider mb-2">
                  Description
                </h3>
                <div className="bg-[var(--surface-card)] border border-[var(--border-color)] rounded-lg p-4">
                  <p className="text-sm text-[var(--text-primary)] leading-relaxed">{data.description}</p>
                </div>
              </section>
            )}

            {/* CVSS Breakdown */}
            {cvssComponents.length > 0 && (
              <section>
                <h3 className="text-sm font-semibold text-[var(--text-secondary)] uppercase tracking-wider mb-2">
                  CVSS Breakdown
                </h3>
                <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
                  {cvssComponents.map((c) => (
                    <div
                      key={c._key}
                      className="bg-[var(--surface-card)] border border-[var(--border-color)] rounded-lg p-3"
                    >
                      <div className="text-[10px] text-[var(--text-secondary)] uppercase tracking-wider mb-1">{c.label}</div>
                      <div className="text-sm text-[var(--text-primary)] font-medium">{c.value}</div>
                    </div>
                  ))}
                </div>
              </section>
            )}

            {/* Sources */}
            <section>
              <h3 className="text-sm font-semibold text-[var(--text-secondary)] uppercase tracking-wider mb-2">
                Sources
              </h3>
              <div className="flex flex-wrap gap-2">
                {data.sources.map((s) => (
                  <div key={s.source} className="flex items-center gap-2">
                    <Badge label={s.source} variant={SOURCE_VARIANTS[s.source] ?? 'neutral'} />
                    {s.sourceRef && isSafeUrl(s.sourceRef) && (
                      <a
                        href={s.sourceRef}
                        target="_blank"
                        rel="noopener noreferrer"
                        className="text-xs text-[var(--accent-teal)] hover:underline"
                      >
                        View
                      </a>
                    )}
                  </div>
                ))}
              </div>
            </section>

            {/* External Links */}
            <section>
              <h3 className="text-sm font-semibold text-[var(--text-secondary)] uppercase tracking-wider mb-2">
                External Links
              </h3>
              <div className="flex flex-wrap gap-3">
                <a
                  href={`https://nvd.nist.gov/vuln/detail/${data.cveId}`}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="text-xs text-[var(--accent-teal)] hover:underline"
                >
                  NVD
                </a>
                <a
                  href={`https://otx.alienvault.com/indicator/cve/${data.cveId}`}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="text-xs text-[var(--accent-teal)] hover:underline"
                >
                  AlienVault OTX
                </a>
                <a
                  href={`https://cve.mitre.org/cgi-bin/cvename.cgi?name=${data.cveId}`}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="text-xs text-[var(--accent-teal)] hover:underline"
                >
                  MITRE CVE
                </a>
              </div>
            </section>
          </div>
        )}

        {activeTab === 'techniques' && (
          <div className="space-y-2">
            {data.techniques.length === 0 ? (
              <p className="text-[var(--text-secondary)] text-sm py-6">No linked techniques found.</p>
            ) : (
              data.techniques.map((t) => (
                <div
                  key={t.attackId}
                  className="flex items-center justify-between gap-3 py-2 px-3 rounded-md bg-[var(--surface-card)] border border-[var(--border-color)]"
                >
                  <EntityLink type="technique" attackId={t.attackId} name={t.name} />
                  <div className="flex flex-wrap gap-1 shrink-0">
                    {t.tactics.map((tac) => (
                      <Badge key={tac} label={tac} variant="neutral" />
                    ))}
                  </div>
                </div>
              ))
            )}
          </div>
        )}

        {activeTab === 'reports' && (
          <div className="space-y-2">
            {data.reports.length === 0 ? (
              <p className="text-[var(--text-secondary)] text-sm py-6">No related reports found.</p>
            ) : (
              <>
                <p className="text-[var(--text-secondary)] text-xs mb-3">
                  Reports linked via shared techniques — may not directly reference this CVE.
                </p>
                {data.reports.map((r) => (
                  <div
                    key={r.id}
                    className="flex items-center justify-between gap-3 py-2 px-3 rounded-md bg-[var(--surface-card)] border border-[var(--border-color)]"
                  >
                    {r.url && isSafeUrl(r.url) ? (
                      <a
                        href={r.url}
                        target="_blank"
                        rel="noopener noreferrer"
                        className="text-[var(--text-primary)] text-sm hover:text-[var(--accent-teal)] hover:underline flex-1 truncate"
                      >
                        {r.title}
                      </a>
                    ) : (
                      <span className="text-[var(--text-primary)] text-sm flex-1 truncate">{r.title}</span>
                    )}
                    <div className="flex items-center gap-2 shrink-0">
                      {r.source && <Badge label={r.source} variant="neutral" />}
                      <span className="text-[var(--text-secondary)] text-xs">{formatDate(r.publishedAt)}</span>
                    </div>
                  </div>
                ))}
              </>
            )}
          </div>
        )}
      </div>
    </div>
  );
}
