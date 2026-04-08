import { useState, useEffect } from 'react';
import { useParams, useSearchParams, Link } from 'react-router-dom';
import { isSafeUrl, ctidCloudUrl, ctidVerisUrl } from '../lib/urlSafety';
import { useTechnique, useIntelligence, useFrameworks } from '../hooks/useApi';
import { formatDate } from '../lib/formatDate';
import { PageHeader } from '../components/layout/PageHeader';
import { Badge } from '../components/shared/Badge';
import { DeprecatedBadge } from '../components/shared/DeprecatedBadge';
import { EntityLink } from '../components/shared/EntityLink';
import { sanitize, sanitizeMarkdown } from '../lib/sanitize';
import type { CloudControl } from '../lib/types';
import { DiamondLoader } from '../components/shared/FoldingDiamond';

type TabId =
  | 'overview'
  | 'groups'
  | 'software'
  | 'mitigations'
  | 'datasources'
  | 'campaigns'
  | 'subtechniques'
  | 'procedures'
  | 'intelligence'
  | 'frameworks';

const TABS: { id: TabId; label: string }[] = [
  { id: 'overview', label: 'Overview' },
  { id: 'groups', label: 'Groups' },
  { id: 'software', label: 'Software' },
  { id: 'mitigations', label: 'Mitigations' },
  { id: 'datasources', label: 'Data Sources' },
  { id: 'campaigns', label: 'Campaigns' },
  { id: 'subtechniques', label: 'Sub-Techniques' },
  { id: 'procedures', label: 'Procedures' },
  { id: 'intelligence', label: 'Intelligence' },
  { id: 'frameworks', label: 'Frameworks' },
];

const LEVEL_VARIANTS: Record<string, 'pink' | 'orange' | 'yellow' | 'blue' | 'green' | 'neutral'> = {
  critical: 'pink',
  high: 'orange',
  medium: 'yellow',
  low: 'blue',
  informational: 'green',
};

function LevelBadge({ level }: { level: string | null }) {
  if (!level) return null;
  return <Badge label={level} variant={LEVEL_VARIANTS[level.toLowerCase()] ?? 'neutral'} />;
}


/** Generate OTX indicator URL from IOC type and value */
function otxUrl(type: string, value: string): string | null {
  switch (type) {
    case 'cve': return `https://otx.alienvault.com/indicator/cve/${encodeURIComponent(value)}`;
    case 'ip': return `https://otx.alienvault.com/indicator/IPv4/${encodeURIComponent(value)}`;
    case 'domain': return `https://otx.alienvault.com/indicator/domain/${encodeURIComponent(value)}`;
    case 'url': return `https://otx.alienvault.com/indicator/url/${encodeURIComponent(value)}`;
    case 'hash': return `https://otx.alienvault.com/indicator/file/${encodeURIComponent(value)}`;
    case 'email': return `https://otx.alienvault.com/indicator/email/${encodeURIComponent(value)}`;
    default: return null;
  }
}

interface IntelligenceTabProps {
  attackId: string;
}

function IntelligenceTab({ attackId }: IntelligenceTabProps) {
  const { data, isLoading, error } = useIntelligence(attackId);

  if (isLoading) {
    return (
      <div className="flex items-center gap-2 text-[var(--text-secondary)] text-sm py-6">
        <span className="inline-block w-4 h-4 border-2 border-[var(--teal-dim)] border-t-[var(--accent-teal)] rounded-full animate-spin" />
        Loading intelligence data...
      </div>
    );
  }

  if (error || !data) {
    return (
      <p className="text-[var(--text-secondary)] text-sm py-6">
        Intelligence data unavailable. Feeds may not have been synced yet.
      </p>
    );
  }

  const isEmpty =
    data.reports.length === 0 &&
    data.sigmaRules.length === 0 &&
    data.atomicTests.length === 0 &&
    data.defensiveMappings.length === 0 &&
    data.iocs.length === 0;

  if (isEmpty) {
    return (
      <p className="text-[var(--text-secondary)] text-sm py-6">
        No intelligence data found for this technique. Trigger a feed sync from{' '}
        <Link to="/cti/feed-status" className="text-[var(--accent-teal)] hover:underline">
          Feed Status
        </Link>
        .
      </p>
    );
  }

  return (
    <div className="space-y-8">
      {/* Recent Reports */}
      {data.reports.length > 0 && (
        <section>
          <h3 className="text-sm font-semibold text-[var(--text-secondary)] uppercase tracking-wider mb-3">
            Recent Reports ({data.reports.length})
          </h3>
          <div className="space-y-2">
            {data.reports.map((r) => (
              <div
                key={r.id}
                className="flex items-center justify-between gap-3 py-2 px-3 rounded-md bg-[var(--surface-card)] border border-[var(--border-color)]"
              >
                {r.url ? (
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
                  <Badge label={r.source} variant="neutral" />
                  <span className="text-[var(--text-secondary)] text-xs">{formatDate(r.published_at)}</span>
                </div>
              </div>
            ))}
          </div>
        </section>
      )}

      {/* Sigma Rules */}
      {data.sigmaRules.length > 0 && (
        <section>
          <h3 className="text-sm font-semibold text-[var(--text-secondary)] uppercase tracking-wider mb-3">
            Sigma Detection Rules ({data.sigmaRules.length})
          </h3>
          <div className="space-y-2">
            {data.sigmaRules.map((rule) => (
              <div
                key={rule.id}
                className="flex items-center justify-between gap-3 py-2 px-3 rounded-md bg-[var(--surface-card)] border border-[var(--border-color)]"
              >
                <div className="flex-1 min-w-0">
                  <span className="text-[var(--text-primary)] text-sm">{rule.title}</span>
                  <span className="ml-2 font-mono text-xs text-[var(--text-secondary)]">{rule.sigma_id}</span>
                </div>
                <div className="flex items-center gap-2 shrink-0">
                  <LevelBadge level={rule.level} />
                  {rule.logsource_product && (
                    <span className="text-[var(--text-secondary)] text-xs">{rule.logsource_product}</span>
                  )}
                </div>
              </div>
            ))}
          </div>
        </section>
      )}

      {/* Atomic Tests */}
      {data.atomicTests.length > 0 && (
        <section>
          <h3 className="text-sm font-semibold text-[var(--text-secondary)] uppercase tracking-wider mb-3">
            Atomic Red Team Tests ({data.atomicTests.length})
          </h3>
          <div className="space-y-2">
            {data.atomicTests.map((test) => (
              <div
                key={test.id}
                className="py-2 px-3 rounded-md bg-[var(--surface-card)] border border-[var(--border-color)] space-y-1"
              >
                <div className="flex items-center gap-2">
                  <span className="text-[var(--accent-teal)] text-xs font-mono">#{test.test_number}</span>
                  <span className="text-[var(--text-primary)] text-sm">{test.name}</span>
                  {test.executor_type && (
                    <Badge label={test.executor_type} variant="purple" />
                  )}
                </div>
                {test.platforms && test.platforms.length > 0 && (
                  <div className="flex gap-1 flex-wrap">
                    {test.platforms.map((p) => (
                      <Badge key={p} label={p} variant="blue" />
                    ))}
                  </div>
                )}
              </div>
            ))}
          </div>
        </section>
      )}

      {/* D3FEND Defensive Mappings */}
      {data.defensiveMappings.length > 0 && (
        <section>
          <h3 className="text-sm font-semibold text-[var(--text-secondary)] uppercase tracking-wider mb-3">
            D3FEND Defensive Mappings ({data.defensiveMappings.length})
          </h3>
          <div className="space-y-2">
            {data.defensiveMappings.map((dm) => (
              <div
                key={dm.id}
                className="py-2 px-3 rounded-md bg-[var(--surface-card)] border border-[var(--border-color)]"
              >
                <div className="flex items-center gap-2">
                  <span className="font-mono text-xs text-[var(--accent-teal)]">{dm.d3fend_id}</span>
                  <span className="text-[var(--text-primary)] text-sm">{dm.d3fend_label}</span>
                </div>
              </div>
            ))}
          </div>
        </section>
      )}

      {/* Related IOCs */}
      {data.iocs.length > 0 && (
        <section>
          <h3 className="text-sm font-semibold text-[var(--text-secondary)] uppercase tracking-wider mb-3">
            Related IOCs ({data.iocs.length})
          </h3>
          <div className="overflow-x-auto rounded-lg border border-[var(--border-color)]">
            <table className="w-full text-sm">
              <thead className="bg-[var(--surface-card)] border-b border-[var(--border-color)]">
                <tr>
                  {['Type', 'Value', 'Source', 'Malware', 'First Seen', 'Confidence'].map((h) => (
                    <th
                      key={h}
                      className="px-3 py-2 text-left text-xs font-semibold text-[var(--text-secondary)] uppercase tracking-wider"
                    >
                      {h}
                    </th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {data.iocs.map((ioc, i) => (
                  <tr
                    key={ioc.id}
                    className={`border-b border-[var(--border-color)] last:border-0 ${i % 2 === 0 ? 'bg-[var(--surface-card)]' : 'bg-[var(--surface-base)]'}`}
                  >
                    <td className="px-3 py-2">
                      <Badge label={ioc.type} variant="neutral" />
                    </td>
                    <td className="px-3 py-2 font-mono text-xs max-w-[200px] truncate">
                      {(() => {
                        if (ioc.type === 'cve') {
                          return (
                            <Link to={`/cti/cves/${ioc.value}`} className="text-[var(--accent-teal)] hover:underline">{ioc.value}</Link>
                          );
                        }
                        const link = otxUrl(ioc.type, ioc.value);
                        return link ? (
                          <a href={link} target="_blank" rel="noopener noreferrer" className="text-[var(--accent-teal)] hover:underline">{ioc.value}</a>
                        ) : (
                          <span className="text-[var(--text-primary)]">{ioc.value}</span>
                        );
                      })()}
                    </td>
                    <td className="px-3 py-2 text-xs text-[var(--text-secondary)]">{ioc.source}</td>
                    <td className="px-3 py-2 text-xs text-[var(--accent-orange)]">{ioc.malware_family ?? '—'}</td>
                    <td className="px-3 py-2 text-xs text-[var(--text-secondary)]">{formatDate(ioc.first_seen_at)}</td>
                    <td className="px-3 py-2 text-xs text-[var(--text-secondary)]">{ioc.confidence ?? '—'}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </section>
      )}
    </div>
  );
}

// ── Cloud Controls section ─────────────────────────────────────────────────────

const CLOUD_PROVIDER_LABELS: Record<string, string> = {
  azure: 'Azure',
  gcp: 'GCP',
  aws: 'AWS',
  m365: 'M365',
};

const CLOUD_PROVIDER_COLORS: Record<string, string> = {
  azure: 'bg-[var(--blue-faint)] text-[var(--accent-blue)] border-[var(--blue-dim)]',
  gcp: 'bg-[var(--green-faint)] text-[var(--accent-green)] border-[var(--green-dim)]',
  aws: 'bg-[var(--orange-faint)] text-[var(--accent-orange)] border-[var(--orange-dim)]',
  m365: 'bg-[var(--teal-faint)] text-[var(--accent-teal)] border-[var(--teal-dim)]',
};

function CloudControlsSection({ controls }: { controls: CloudControl[] }) {
  const [activeProvider, setActiveProvider] = useState<string>('all');

  // Group controls by provider
  const providers = Array.from(new Set(controls.map((c) => c.provider))).sort();
  const filtered =
    activeProvider === 'all'
      ? controls
      : controls.filter((c) => c.provider === activeProvider);

  return (
    <section>
      <h3 className="text-sm font-semibold text-[var(--text-secondary)] uppercase tracking-wider mb-3">
        Cloud Security Controls ({controls.length})
      </h3>

      {/* Provider filter tabs */}
      <div className="flex gap-1.5 flex-wrap mb-3">
        <button
          type="button"
          onClick={() => setActiveProvider('all')}
          className={`px-3 py-1 rounded-full text-xs font-medium border transition-colors ${
            activeProvider === 'all'
              ? 'bg-[var(--teal-faint)] text-[var(--accent-teal)] border-[var(--teal-dim)]'
              : 'bg-transparent text-[var(--text-secondary)] border-[var(--border-color)] hover:text-[var(--text-primary)]'
          }`}
        >
          All ({controls.length})
        </button>
        {providers.map((p) => {
          const count = controls.filter((c) => c.provider === p).length;
          const colorCls =
            activeProvider === p
              ? (CLOUD_PROVIDER_COLORS[p] ?? 'bg-[var(--hover-overlay)] text-[var(--text-secondary)] border-[var(--border-color)]')
              : 'bg-transparent text-[var(--text-secondary)] border-[var(--border-color)] hover:text-[var(--text-primary)]';
          return (
            <button
              key={p}
              type="button"
              onClick={() => setActiveProvider(p)}
              className={`px-3 py-1 rounded-full text-xs font-medium border transition-colors ${colorCls}`}
            >
              {CLOUD_PROVIDER_LABELS[p] ?? p.toUpperCase()} ({count})
            </button>
          );
        })}
      </div>

      <div className="space-y-1.5">
        {filtered.map((ctrl) => {
          const colorCls =
            CLOUD_PROVIDER_COLORS[ctrl.provider] ??
            'bg-[var(--hover-overlay)] text-[var(--text-secondary)] border-[var(--border-color)]';
          return (
            <div
              key={`${ctrl.provider}-${ctrl.controlId}`}
              className="flex items-start gap-3 py-2 px-3 rounded-md bg-[var(--surface-card)] border border-[var(--border-color)]"
            >
              <span className={`inline-flex items-center px-2 py-0.5 rounded-full text-[10px] font-bold border shrink-0 ${colorCls}`}>
                {CLOUD_PROVIDER_LABELS[ctrl.provider] ?? ctrl.provider.toUpperCase()}
              </span>
              <div className="flex-1 min-w-0">
                <div className="flex items-center gap-2 flex-wrap">
                  <a
                    href={ctidCloudUrl(ctrl.provider, ctrl.controlId)}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="font-mono text-xs text-[var(--accent-teal)] shrink-0 hover:underline"
                    title={`View on CTID Mappings Explorer`}
                  >{ctrl.controlId} ↗</a>
                  <span className="text-sm text-[var(--text-primary)]">{ctrl.controlName}</span>
                  {ctrl.mappingType && (
                    <span className="text-xs text-[var(--text-secondary)]">{ctrl.mappingType}</span>
                  )}
                </div>
                {ctrl.controlDescription && (
                  <p className="text-xs text-[var(--text-secondary)] mt-0.5 line-clamp-2">
                    {ctrl.controlDescription}
                  </p>
                )}
              </div>
            </div>
          );
        })}
      </div>
    </section>
  );
}

const NIST_FAMILY_COLORS: Record<string, string> = {
  'Access Control': 'blue',
  'Audit and Accountability': 'purple',
  'Incident Response': 'orange',
  'System and Information Integrity': 'pink',
  'Configuration Management': 'teal',
};

function FrameworksTab({ attackId }: { attackId: string }) {
  const { data, isLoading, error } = useFrameworks(attackId);

  if (isLoading) {
    return (
      <div className="flex items-center gap-2 text-[var(--text-secondary)] text-sm py-6">
        <span className="inline-block w-4 h-4 border-2 border-[var(--teal-dim)] border-t-[var(--accent-teal)] rounded-full animate-spin" />
        Loading framework mappings...
      </div>
    );
  }

  if (error || !data) {
    return (
      <p className="text-[var(--text-secondary)] text-sm py-6">
        Framework data unavailable.
      </p>
    );
  }

  const isEmpty =
    data.nist.length === 0 &&
    data.engage.length === 0 &&
    (data.verisCategories?.length ?? 0) === 0 &&
    (data.cloudControls?.length ?? 0) === 0 &&
    (data.owasp?.length ?? 0) === 0;

  if (isEmpty) {
    return (
      <p className="text-[var(--text-secondary)] text-sm py-6">
        No framework mappings found for this technique. Run{' '}
        <code className="text-[var(--accent-teal)] text-xs font-mono">
          node scripts/sync-frameworks.mjs
        </code>{' '}
        to populate data.
      </p>
    );
  }

  return (
    <div className="space-y-8">
      {/* NIST 800-53 */}
      {data.nist.length > 0 && (
        <section>
          <h3 className="text-sm font-semibold text-[var(--text-secondary)] uppercase tracking-wider mb-3">
            NIST 800-53 Controls ({data.nist.length})
          </h3>
          <div className="space-y-2">
            {data.nist.map((ctrl) => (
              <a
                key={ctrl.controlId}
                href={`https://csf.tools/reference/nist-sp-800-53/r5/${ctrl.controlId.split('-')[0].toLowerCase()}/${ctrl.controlId.replace(/-0+/g, '-').toLowerCase()}/`}
                target="_blank"
                rel="noopener noreferrer"
                className="flex items-start gap-3 py-2 px-3 rounded-md bg-[var(--surface-card)] border border-[var(--border-color)] hover:border-[var(--teal-dim)] transition-colors group"
              >
                <span className="font-mono text-xs text-[var(--accent-teal)] mt-0.5 shrink-0 w-14 group-hover:underline">
                  {ctrl.controlId}
                </span>
                <div className="flex-1 min-w-0">
                  <span className="text-[var(--text-primary)] text-sm">
                    {ctrl.controlName ?? ctrl.controlId}
                  </span>
                </div>
                <div className="flex items-center gap-2 shrink-0">
                  {ctrl.controlFamily && (
                    <Badge
                      label={ctrl.controlFamily}
                      variant={
                        (NIST_FAMILY_COLORS[ctrl.controlFamily] ?? 'neutral') as any
                      }
                    />
                  )}
                  {ctrl.mappingType && (
                    <span className="text-[var(--text-secondary)] text-xs">{ctrl.mappingType}</span>
                  )}
                </div>
              </a>
            ))}
          </div>
          <div className="pt-2">
            <Link
              to="/frameworks/nist"
              className="text-xs text-[var(--accent-teal)] hover:underline"
            >
              Browse all NIST 800-53 controls
            </Link>
          </div>
        </section>
      )}

      {/* MITRE Engage */}
      {data.engage.length > 0 && (
        <section>
          <h3 className="text-sm font-semibold text-[var(--text-secondary)] uppercase tracking-wider mb-3">
            MITRE Engage Activities ({data.engage.length})
          </h3>
          <div className="space-y-2">
            {data.engage.map((act) => (
              <div
                key={act.engageId}
                className="py-2 px-3 rounded-md bg-[var(--surface-card)] border border-[var(--border-color)]"
              >
                <div className="flex items-center gap-2 flex-wrap">
                  <span className="font-mono text-xs text-[var(--accent-teal)] shrink-0">
                    {act.engageId}
                  </span>
                  <span className="text-[var(--text-primary)] text-sm">{act.engageName}</span>
                  {act.goal && (
                    <Badge label={act.goal} variant="orange" />
                  )}
                  {act.approach && (
                    <Badge label={act.approach} variant="purple" />
                  )}
                </div>
                {act.engageDescription && (
                  <p className="text-[var(--text-secondary)] text-xs mt-1 line-clamp-2">
                    {act.engageDescription}
                  </p>
                )}
              </div>
            ))}
          </div>
          <div className="pt-2">
            <Link
              to="/frameworks/engage"
              className="text-xs text-[var(--accent-teal)] hover:underline"
            >
              Browse all Engage activities
            </Link>
          </div>
        </section>
      )}

      {/* RE&CT — general link (actions are not per-technique) */}
      <section>
        <h3 className="text-sm font-semibold text-[var(--text-secondary)] uppercase tracking-wider mb-3">
          RE&CT Incident Response
        </h3>
        <p className="text-[var(--text-secondary)] text-sm">
          RE&CT response actions are not mapped per-technique — they cover the full IR lifecycle.
          View the full action catalogue to find relevant response steps for this technique type.
        </p>
        <div className="pt-2">
          <Link
            to="/frameworks/react"
            className="text-xs text-[var(--accent-teal)] hover:underline"
          >
            Browse RE&CT response actions
          </Link>
        </div>
      </section>

      {/* VERIS */}
      {(data.verisCategories?.length ?? 0) > 0 && (
        <section>
          <h3 className="text-sm font-semibold text-[var(--text-secondary)] uppercase tracking-wider mb-3">
            VERIS Categories ({data.verisCategories!.length})
          </h3>
          <div className="flex flex-wrap gap-2">
            {data.verisCategories!.map((v) => (
              <a
                key={v.verisId}
                href={ctidVerisUrl(v.verisId)}
                target="_blank"
                rel="noopener noreferrer"
                title={`View ${v.verisId} on CTID Mappings Explorer`}
                className="inline-flex items-center px-2.5 py-1 rounded-md text-xs font-medium bg-[var(--purple-faint)] text-[var(--accent-purple)] border border-[var(--purple-dim)] hover:bg-[var(--purple-dim)] transition-colors"
              >
                {v.verisId} ↗
              </a>
            ))}
          </div>
        </section>
      )}

      {/* Cloud Controls */}
      {(data.cloudControls?.length ?? 0) > 0 && (
        <CloudControlsSection controls={data.cloudControls!} />
      )}

      {/* OWASP Categories */}
      {data.owasp && data.owasp.length > 0 && (
        <section>
          <h3 className="text-sm font-semibold text-[var(--text-secondary)] uppercase tracking-wider mb-3">
            OWASP Categories ({data.owasp.length})
          </h3>
          <div className="flex flex-wrap gap-1.5">
            {data.owasp.map((cat) => (
              <EntityLink
                key={`${cat.categoryId}-${cat.framework}`}
                type="owasp"
                attackId={cat.categoryId}
                name={cat.name}
              />
            ))}
          </div>
          <div className="pt-2">
            <Link to="/frameworks/owasp" className="text-xs text-[var(--accent-teal)] hover:underline">
              Browse all OWASP categories
            </Link>
          </div>
        </section>
      )}
    </div>
  );
}

export function TechniqueDetail() {
  const { attackId } = useParams<{ attackId: string }>();
  const [searchParams] = useSearchParams();
  const { data, isLoading, error } = useTechnique(attackId ?? '');
  const tabParam = searchParams.get('tab') as TabId | null;
  const validTabs = new Set<string>(TABS.map((t) => t.id));
  const [activeTab, setActiveTab] = useState<TabId>(tabParam && validTabs.has(tabParam) ? tabParam : 'overview');

  // Sync active tab when URL ?tab= changes (e.g. back button, external link)
  useEffect(() => {
    if (tabParam && validTabs.has(tabParam) && tabParam !== activeTab) {
      setActiveTab(tabParam);
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [tabParam]);

  if (isLoading) {
    return <DiamondLoader text="Loading..." />;
  }

  if (error || !data) {
    return (
      <div className="flex items-center justify-center h-64 text-[var(--accent-orange)]">
        Technique not found.
      </div>
    );
  }

  const description = data.description
    ? sanitize(sanitizeMarkdown(data.description))
    : null;

  const detection = data.detection
    ? sanitize(sanitizeMarkdown(data.detection))
    : null;

  return (
    <div className="space-y-6">
      <PageHeader
        title={data.name}
        breadcrumb={[
          { label: 'Techniques', href: '/techniques' },
          { label: data.attackId },
        ]}
        titleAction={
          <Link to={`/?entity=${data.attackId}&tab=technique-map`} className="inline-flex items-center gap-0.5 px-1.5 py-0.5 rounded text-[9px] font-medium text-[var(--text-secondary)] hover:text-[var(--accent-teal)] transition-colors" title="View in 360 Views">360 →</Link>
        }
        actions={
          <div className="flex items-center gap-2">
            {(data.isRevoked || data.isDeprecated) && (<DeprecatedBadge isRevoked={data.isRevoked} />)}
            <span className="font-mono text-xs text-[var(--accent-teal)] bg-[var(--teal-faint)] border border-[var(--teal-dim)] px-2 py-1 rounded">{data.attackId}</span>
          </div>
        }
      />

      {/* Metadata strip */}
      <div className="flex flex-wrap gap-4 text-sm bg-[var(--surface-card)] border border-[var(--border-color)] rounded-lg px-4 py-3">
        {data.domain && (
          <div className="flex items-center gap-2">
            <span className="text-[var(--text-secondary)]">Domain:</span>
            <Badge label={data.domain.replace('-attack', '')} variant="neutral" />
          </div>
        )}
        {data.tactics && data.tactics.length > 0 && (
          <div className="flex items-center gap-2">
            <span className="text-[var(--text-secondary)]">Tactic:</span>
            {data.tactics.map((t) => (
              <Badge key={t} label={t} variant="yellow" />
            ))}
          </div>
        )}
        {data.platforms?.length ? (
          <div className="flex items-center gap-2 flex-wrap">
            <span className="text-[var(--text-secondary)]">Platforms:</span>
            {data.platforms.map((p) => (
              <Badge key={p} label={p} variant="blue" />
            ))}
          </div>
        ) : null}
        {data.maturity && (
          <div className="flex items-center gap-2">
            <span className="text-[var(--text-secondary)]">Maturity:</span>
            <Badge
              label={data.maturity}
              variant={data.maturity === 'realized' ? 'green' : data.maturity === 'demonstrated' ? 'yellow' : 'orange'}
              className="cursor-help"
            />
          </div>
        )}
        {data.atlasXrefs && data.atlasXrefs.length > 0 && (
          <div className="flex items-center gap-2">
            <span className="text-[var(--text-secondary)]">
              {data.domain === 'atlas-attack' ? 'ATT&CK Equivalent:' : 'ATLAS AI Context:'}
            </span>
            {data.atlasXrefs.map((xref) => (
              <a
                key={xref.attackId}
                href={`/techniques/${encodeURIComponent(xref.attackId)}?domain=${encodeURIComponent(xref.domain ?? '')}`}
                className="text-xs text-[var(--accent-teal)] hover:underline font-mono"
              >
                {xref.attackId} {xref.name}
              </a>
            ))}
          </div>
        )}
        {data.url && isSafeUrl(data.url) && (
          <a
            href={data.url}
            target="_blank"
            rel="noopener noreferrer"
            className="text-xs text-[var(--accent-teal)] hover:underline"
          >
            MITRE Reference
          </a>
        )}
      </div>

      {/* Tabs */}
      <div className="border-b border-[var(--border-color)]">
        <div className="relative">
          <div
            className="flex gap-1 overflow-x-auto
              [&::-webkit-scrollbar]:hidden [-ms-overflow-style:none] [scrollbar-width:none]"
          >
            {TABS.map((tab) => (
              <button
                key={tab.id}
                type="button"
                onClick={() => setActiveTab(tab.id)}
                className={`
                  px-4 py-2 text-sm font-medium whitespace-nowrap transition-colors duration-150
                  border-b-2 -mb-px
                  ${activeTab === tab.id
                    ? 'text-[var(--accent-teal)] border-[var(--accent-teal)]'
                    : 'text-[var(--text-secondary)] border-transparent hover:text-[var(--text-primary)]'
                  }
                `}
              >
                {tab.label}
              </button>
            ))}
          </div>
          <div
            className="pointer-events-none absolute right-0 top-0 h-full w-10 bg-gradient-to-l from-[var(--surface-deep)] to-transparent z-10"
            aria-hidden="true"
          />
        </div>
      </div>

      {/* Tab content */}
      <div>
        {activeTab === 'overview' && (
          <div className="space-y-6">
            {description && (
              <div>
                <h3 className="text-sm font-semibold text-[var(--text-secondary)] uppercase tracking-wider mb-2">
                  Description
                </h3>
                <p className="text-[var(--text-primary)] text-sm leading-relaxed whitespace-pre-wrap">
                  {description}
                </p>
              </div>
            )}
            {detection && (
              <div>
                <h3 className="text-sm font-semibold text-[var(--text-secondary)] uppercase tracking-wider mb-2">
                  Detection
                </h3>
                <p className="text-[var(--text-primary)] text-sm leading-relaxed whitespace-pre-wrap">
                  {detection}
                </p>
              </div>
            )}
          </div>
        )}

        {activeTab === 'subtechniques' && (
          <div className="space-y-2">
            {data.sub_techniques?.length ? (
              data.sub_techniques.map((sub) => (
                <div
                  key={sub.attackId}
                  className="flex items-center gap-3 py-2 border-b border-[var(--border-color)] last:border-0"
                >
                  <EntityLink
                    type="technique"
                    attackId={sub.attackId}
                    name={sub.name}
                  />
                  {sub.tactics && sub.tactics.length > 0 && (
                    <Badge label={sub.tactics[0]} variant="yellow" />
                  )}
                </div>
              ))
            ) : (
              <p className="text-[var(--text-secondary)] text-sm">No sub-techniques.</p>
            )}
          </div>
        )}

        {activeTab === 'procedures' && (
          <div className="space-y-2">
            {(() => {
              const procs = (data.groups ?? []).filter((g) => g.procedure);
              if (procs.length === 0) return (
                <p className="text-[var(--text-secondary)] text-sm py-4">No procedures documented for this technique.</p>
              );
              return procs.map((g) => (
                <details key={g.attackId} className="group rounded-lg border border-[var(--border-color)] bg-[var(--surface-card)] overflow-hidden">
                  <summary className="flex items-center gap-3 px-4 py-3 cursor-pointer hover:bg-[var(--teal-ghost)] transition-colors">
                    <svg className="w-3 h-3 text-[var(--text-secondary)] transition-transform group-open:rotate-90 shrink-0" fill="none" stroke="currentColor" strokeWidth={2} viewBox="0 0 24 24" aria-hidden="true">
                      <path strokeLinecap="round" strokeLinejoin="round" d="M9 5l7 7-7 7" />
                    </svg>
                    <EntityLink type="group" attackId={g.attackId} name={g.name} />
                  </summary>
                  <div className="px-4 pb-3 pt-1 border-t border-[var(--border-color)]">
                    <p
                      className="text-xs text-[var(--text-secondary)] leading-relaxed whitespace-pre-wrap"
                      dangerouslySetInnerHTML={{ __html: sanitize(sanitizeMarkdown(g.procedure ?? '')) }}
                    />
                  </div>
                </details>
              ));
            })()}
          </div>
        )}

        {activeTab === 'groups' && (
          <div className="space-y-3">
            {(data.groups ?? []).length === 0 ? (
              <p className="text-[var(--text-secondary)] text-sm py-4">No groups linked to this technique.</p>
            ) : (
              (data.groups ?? []).map((g) => (
                <div key={g.attackId} className="py-2 border-b border-[var(--border-color)] last:border-0 space-y-1">
                  <EntityLink type="group" attackId={g.attackId} name={g.name} />
                  {g.procedure && (
                    <p className="text-[var(--text-secondary)] text-xs leading-relaxed pl-1">{g.procedure}</p>
                  )}
                </div>
              ))
            )}
            <div className="pt-2">
              <Link
                to={`/relationships?entity=${data.attackId}&tab=technique-map`}
                className="text-xs text-[var(--accent-teal)] hover:underline"
              >
                View technique map
              </Link>
            </div>
          </div>
        )}

        {activeTab === 'software' && (
          <div className="space-y-3">
            {(data.software ?? []).length === 0 ? (
              <p className="text-[var(--text-secondary)] text-sm py-4">No software linked to this technique.</p>
            ) : (
              (data.software ?? []).map((s) => (
                <div key={s.attackId} className="py-2 border-b border-[var(--border-color)] last:border-0 space-y-1">
                  <div className="flex items-center gap-2">
                    <EntityLink type="software" attackId={s.attackId} name={s.name} />
                    <Badge label={s.type} variant={s.type === 'malware' ? 'pink' : 'purple'} />
                  </div>
                  {s.description && (
                    <p className="text-[var(--text-secondary)] text-xs leading-relaxed pl-1">{s.description}</p>
                  )}
                </div>
              ))
            )}
            <div className="pt-2">
              <Link
                to={`/relationships?entity=${data.attackId}&tab=technique-map`}
                className="text-xs text-[var(--accent-teal)] hover:underline"
              >
                View technique map
              </Link>
            </div>
          </div>
        )}

        {activeTab === 'mitigations' && (
          <div className="space-y-3">
            {(data.mitigations ?? []).length === 0 ? (
              <p className="text-[var(--text-secondary)] text-sm py-4">No mitigations linked to this technique.</p>
            ) : (
              (data.mitigations ?? []).map((m) => (
                <div key={m.attackId} className="py-2 border-b border-[var(--border-color)] last:border-0 space-y-1">
                  <EntityLink type="mitigation" attackId={m.attackId} name={m.name} />
                  {m.description && (
                    <p className="text-[var(--text-secondary)] text-xs leading-relaxed pl-1">{m.description}</p>
                  )}
                </div>
              ))
            )}
            <div className="pt-2">
              <Link
                to={`/relationships?entity=${data.attackId}&tab=technique-map`}
                className="text-xs text-[var(--accent-teal)] hover:underline"
              >
                View technique map
              </Link>
            </div>
          </div>
        )}

        {activeTab === 'datasources' && (
          <div className="space-y-3">
            {(data.dataComponents ?? []).length === 0 ? (
              <p className="text-[var(--text-secondary)] text-sm py-4">No data sources linked to this technique.</p>
            ) : (
              (data.dataComponents ?? []).map((dc, i) => (
                <div key={i} className="py-2 border-b border-[var(--border-color)] last:border-0 space-y-1">
                  <div className="flex items-center gap-2 flex-wrap">
                    <EntityLink
                      type="data_source"
                      attackId={dc.dataSourceAttackId}
                      name={dc.dataSourceName}
                    />
                    <Badge label={dc.componentName} variant="neutral" />
                  </div>
                  {dc.description && (
                    <p className="text-[var(--text-secondary)] text-xs leading-relaxed pl-1">{dc.description}</p>
                  )}
                </div>
              ))
            )}
            <div className="pt-2">
              <Link
                to={`/relationships?entity=${data.attackId}&tab=technique-map`}
                className="text-xs text-[var(--accent-teal)] hover:underline"
              >
                View technique map
              </Link>
            </div>
          </div>
        )}

        {activeTab === 'campaigns' && (
          <div className="space-y-3">
            {(data.campaigns ?? []).length === 0 ? (
              <p className="text-[var(--text-secondary)] text-sm py-4">No campaigns linked to this technique.</p>
            ) : (
              (data.campaigns ?? []).map((c) => (
                <div key={c.attackId} className="py-2 border-b border-[var(--border-color)] last:border-0 space-y-1">
                  <EntityLink type="campaign" attackId={c.attackId} name={c.name} />
                  {c.description && (
                    <p className="text-[var(--text-secondary)] text-xs leading-relaxed pl-1">{c.description}</p>
                  )}
                </div>
              ))
            )}
            <div className="pt-2">
              <Link
                to={`/relationships?entity=${data.attackId}&tab=technique-map`}
                className="text-xs text-[var(--accent-teal)] hover:underline"
              >
                View technique map
              </Link>
            </div>
          </div>
        )}

        {activeTab === 'intelligence' && (
          <IntelligenceTab attackId={data.attackId} />
        )}

        {activeTab === 'frameworks' && (
          <FrameworksTab attackId={data.attackId} />
        )}
      </div>
    </div>
  );
}
