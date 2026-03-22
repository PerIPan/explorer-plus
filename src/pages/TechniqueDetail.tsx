import { useState } from 'react';
import { useParams, Link } from 'react-router-dom';
import { useTechnique, useIntelligence } from '../hooks/useApi';
import { PageHeader } from '../components/layout/PageHeader';
import { Badge } from '../components/shared/Badge';
import { DeprecatedBadge } from '../components/shared/DeprecatedBadge';
import { EntityLink } from '../components/shared/EntityLink';
import { sanitize, sanitizeMarkdown } from '../lib/sanitize';

type TabId =
  | 'overview'
  | 'groups'
  | 'software'
  | 'mitigations'
  | 'datasources'
  | 'campaigns'
  | 'subtechniques'
  | 'intelligence';

const TABS: { id: TabId; label: string }[] = [
  { id: 'overview', label: 'Overview' },
  { id: 'groups', label: 'Groups' },
  { id: 'software', label: 'Software' },
  { id: 'mitigations', label: 'Mitigations' },
  { id: 'datasources', label: 'Data Sources' },
  { id: 'campaigns', label: 'Campaigns' },
  { id: 'subtechniques', label: 'Sub-Techniques' },
  { id: 'intelligence', label: 'Intelligence' },
];

const LEVEL_COLORS: Record<string, string> = {
  critical: 'bg-[#f472b618] text-[#f472b6] border-[#f472b633]',
  high: 'bg-[#f9731618] text-[#f97316] border-[#f9731633]',
  medium: 'bg-[#fbbf2418] text-[#fbbf24] border-[#fbbf2433]',
  low: 'bg-[#60a5fa18] text-[#60a5fa] border-[#60a5fa33]',
  informational: 'bg-[#34d39918] text-[#34d399] border-[#34d39933]',
};

function LevelBadge({ level }: { level: string | null }) {
  if (!level) return null;
  const classes = LEVEL_COLORS[level.toLowerCase()] ?? 'bg-[#ffffff08] text-[#8892b0] border-[#2a2a4a]';
  return (
    <span className={`inline-flex items-center px-2 py-0.5 rounded-full text-xs font-medium border ${classes}`}>
      {level}
    </span>
  );
}

function formatDate(iso: string | null): string {
  if (!iso) return '—';
  return new Date(iso).toLocaleDateString('en-US', {
    year: 'numeric', month: 'short', day: 'numeric',
  });
}

interface IntelligenceTabProps {
  attackId: string;
}

function IntelligenceTab({ attackId }: IntelligenceTabProps) {
  const { data, isLoading, error } = useIntelligence(attackId);

  if (isLoading) {
    return (
      <div className="flex items-center gap-2 text-[#8892b0] text-sm py-6">
        <span className="inline-block w-4 h-4 border-2 border-[#64ffda33] border-t-[#64ffda] rounded-full animate-spin" />
        Loading intelligence data...
      </div>
    );
  }

  if (error || !data) {
    return (
      <p className="text-[#8892b0] text-sm py-6">
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
      <p className="text-[#8892b0] text-sm py-6">
        No intelligence data found for this technique. Trigger a feed sync from{' '}
        <Link to="/cti/feed-status" className="text-[#64ffda] hover:underline">
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
          <h3 className="text-sm font-semibold text-[#8892b0] uppercase tracking-wider mb-3">
            Recent Reports ({data.reports.length})
          </h3>
          <div className="space-y-2">
            {data.reports.map((r) => (
              <div
                key={r.id}
                className="flex items-center justify-between gap-3 py-2 px-3 rounded-md bg-[#16213e] border border-[#2a2a4a]"
              >
                <a
                  href={r.url}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="text-[#ccd6f6] text-sm hover:text-[#64ffda] hover:underline flex-1 truncate"
                >
                  {r.title}
                </a>
                <div className="flex items-center gap-2 shrink-0">
                  <Badge label={r.source} variant="neutral" />
                  <span className="text-[#8892b0] text-xs">{formatDate(r.published_at)}</span>
                </div>
              </div>
            ))}
          </div>
        </section>
      )}

      {/* Sigma Rules */}
      {data.sigmaRules.length > 0 && (
        <section>
          <h3 className="text-sm font-semibold text-[#8892b0] uppercase tracking-wider mb-3">
            Sigma Detection Rules ({data.sigmaRules.length})
          </h3>
          <div className="space-y-2">
            {data.sigmaRules.map((rule) => (
              <div
                key={rule.id}
                className="flex items-center justify-between gap-3 py-2 px-3 rounded-md bg-[#16213e] border border-[#2a2a4a]"
              >
                <div className="flex-1 min-w-0">
                  <span className="text-[#ccd6f6] text-sm">{rule.title}</span>
                  <span className="ml-2 font-mono text-xs text-[#8892b0]">{rule.sigma_id}</span>
                </div>
                <div className="flex items-center gap-2 shrink-0">
                  <LevelBadge level={rule.level} />
                  {rule.logsource_product && (
                    <span className="text-[#8892b0] text-xs">{rule.logsource_product}</span>
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
          <h3 className="text-sm font-semibold text-[#8892b0] uppercase tracking-wider mb-3">
            Atomic Red Team Tests ({data.atomicTests.length})
          </h3>
          <div className="space-y-2">
            {data.atomicTests.map((test) => (
              <div
                key={test.id}
                className="py-2 px-3 rounded-md bg-[#16213e] border border-[#2a2a4a] space-y-1"
              >
                <div className="flex items-center gap-2">
                  <span className="text-[#64ffda] text-xs font-mono">#{test.test_number}</span>
                  <span className="text-[#ccd6f6] text-sm">{test.name}</span>
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
          <h3 className="text-sm font-semibold text-[#8892b0] uppercase tracking-wider mb-3">
            D3FEND Defensive Mappings ({data.defensiveMappings.length})
          </h3>
          <div className="space-y-2">
            {data.defensiveMappings.map((dm) => (
              <div
                key={dm.id}
                className="py-2 px-3 rounded-md bg-[#16213e] border border-[#2a2a4a]"
              >
                <div className="flex items-center gap-2">
                  <span className="font-mono text-xs text-[#64ffda]">{dm.d3fend_id}</span>
                  <span className="text-[#ccd6f6] text-sm">{dm.d3fend_label}</span>
                </div>
                {dm.d3fend_description && (
                  <p className="text-[#8892b0] text-xs mt-1 line-clamp-2">{dm.d3fend_description}</p>
                )}
              </div>
            ))}
          </div>
        </section>
      )}

      {/* Related IOCs */}
      {data.iocs.length > 0 && (
        <section>
          <h3 className="text-sm font-semibold text-[#8892b0] uppercase tracking-wider mb-3">
            Related IOCs ({data.iocs.length})
          </h3>
          <div className="overflow-x-auto rounded-lg border border-[#2a2a4a]">
            <table className="w-full text-sm">
              <thead className="bg-[#16213e] border-b border-[#2a2a4a]">
                <tr>
                  {['Type', 'Value', 'Source', 'Malware', 'First Seen', 'Confidence'].map((h) => (
                    <th
                      key={h}
                      className="px-3 py-2 text-left text-xs font-semibold text-[#8892b0] uppercase tracking-wider"
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
                    className={`border-b border-[#2a2a4a] last:border-0 ${i % 2 === 0 ? 'bg-[#16213e]' : 'bg-[#1a1a2e]'}`}
                  >
                    <td className="px-3 py-2">
                      <Badge label={ioc.type} variant="neutral" />
                    </td>
                    <td className="px-3 py-2 font-mono text-xs text-[#ccd6f6] max-w-[200px] truncate">
                      {ioc.value}
                    </td>
                    <td className="px-3 py-2 text-xs text-[#8892b0]">{ioc.source}</td>
                    <td className="px-3 py-2 text-xs text-[#f97316]">{ioc.malware_family ?? '—'}</td>
                    <td className="px-3 py-2 text-xs text-[#8892b0]">{formatDate(ioc.first_seen_at)}</td>
                    <td className="px-3 py-2 text-xs text-[#8892b0]">{ioc.confidence ?? '—'}</td>
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

export function TechniqueDetail() {
  const { attackId } = useParams<{ attackId: string }>();
  const { data, isLoading, error } = useTechnique(attackId ?? '');
  const [activeTab, setActiveTab] = useState<TabId>('overview');

  if (isLoading) {
    return (
      <div className="flex items-center justify-center h-64 text-[#8892b0]">
        <span className="inline-block w-5 h-5 border-2 border-[#64ffda33] border-t-[#64ffda] rounded-full animate-spin mr-2" />
        Loading...
      </div>
    );
  }

  if (error || !data) {
    return (
      <div className="flex items-center justify-center h-64 text-[#f97316]">
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
        actions={
          <div className="flex items-center gap-2">
            {(data.isRevoked || data.isDeprecated) && (
              <DeprecatedBadge isRevoked={data.isRevoked} />
            )}
            <span className="font-mono text-xs text-[#64ffda] bg-[#64ffda18] border border-[#64ffda33] px-2 py-1 rounded">
              {data.attackId}
            </span>
          </div>
        }
      />

      {/* Metadata strip */}
      <div className="flex flex-wrap gap-4 text-sm">
        {data.tacticPhase && (
          <div className="flex items-center gap-2">
            <span className="text-[#8892b0]">Tactic:</span>
            <Badge label={data.tacticPhase} variant="yellow" />
          </div>
        )}
        {data.platforms?.length ? (
          <div className="flex items-center gap-2 flex-wrap">
            <span className="text-[#8892b0]">Platforms:</span>
            {data.platforms.map((p) => (
              <Badge key={p} label={p} variant="blue" />
            ))}
          </div>
        ) : null}
        {data.url && (
          <a
            href={data.url}
            target="_blank"
            rel="noopener noreferrer"
            className="text-xs text-[#64ffda] hover:underline"
          >
            MITRE Reference
          </a>
        )}
      </div>

      {/* Tabs */}
      <div className="border-b border-[#2a2a4a]">
        <div className="flex gap-1 overflow-x-auto">
          {TABS.map((tab) => (
            <button
              key={tab.id}
              type="button"
              onClick={() => setActiveTab(tab.id)}
              className={`
                px-4 py-2 text-sm font-medium whitespace-nowrap transition-colors duration-150
                border-b-2 -mb-px
                ${activeTab === tab.id
                  ? 'text-[#64ffda] border-[#64ffda]'
                  : 'text-[#8892b0] border-transparent hover:text-[#ccd6f6]'
                }
              `}
            >
              {tab.label}
            </button>
          ))}
        </div>
      </div>

      {/* Tab content */}
      <div>
        {activeTab === 'overview' && (
          <div className="space-y-6">
            {description && (
              <div>
                <h3 className="text-sm font-semibold text-[#8892b0] uppercase tracking-wider mb-2">
                  Description
                </h3>
                <p className="text-[#ccd6f6] text-sm leading-relaxed whitespace-pre-wrap">
                  {description}
                </p>
              </div>
            )}
            {detection && (
              <div>
                <h3 className="text-sm font-semibold text-[#8892b0] uppercase tracking-wider mb-2">
                  Detection
                </h3>
                <p className="text-[#ccd6f6] text-sm leading-relaxed whitespace-pre-wrap">
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
                  className="flex items-center gap-3 py-2 border-b border-[#2a2a4a] last:border-0"
                >
                  <EntityLink
                    type="technique"
                    attackId={sub.attackId}
                    name={sub.name}
                  />
                  {sub.tacticPhase && (
                    <Badge label={sub.tacticPhase} variant="yellow" />
                  )}
                </div>
              ))
            ) : (
              <p className="text-[#8892b0] text-sm">No sub-techniques.</p>
            )}
          </div>
        )}

        {(activeTab === 'groups' ||
          activeTab === 'software' ||
          activeTab === 'mitigations' ||
          activeTab === 'datasources' ||
          activeTab === 'campaigns') && (
          <div className="text-[#8892b0] text-sm py-4">
            Relationship data for this section is available via the{' '}
            <Link to="/relationships" className="text-[#64ffda] hover:underline">
              Relationships Explorer
            </Link>
            . Search for{' '}
            <span className="font-mono text-[#64ffda]">{data.attackId}</span> to
            explore connections.
          </div>
        )}

        {activeTab === 'intelligence' && (
          <IntelligenceTab attackId={data.attackId} />
        )}
      </div>
    </div>
  );
}
