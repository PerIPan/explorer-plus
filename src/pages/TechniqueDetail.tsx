import { useState } from 'react';
import { useParams, Link } from 'react-router-dom';
import { useTechnique } from '../hooks/useApi';
import { PageHeader } from '../components/layout/PageHeader';
import { Badge } from '../components/shared/Badge';
import { DeprecatedBadge } from '../components/shared/DeprecatedBadge';
import { EntityLink } from '../components/shared/EntityLink';
import { sanitize, sanitizeMarkdown } from '../lib/sanitize';

type TabId = 'overview' | 'groups' | 'software' | 'mitigations' | 'datasources' | 'campaigns' | 'subtechniques';

const TABS: { id: TabId; label: string }[] = [
  { id: 'overview', label: 'Overview' },
  { id: 'groups', label: 'Groups' },
  { id: 'software', label: 'Software' },
  { id: 'mitigations', label: 'Mitigations' },
  { id: 'datasources', label: 'Data Sources' },
  { id: 'campaigns', label: 'Campaigns' },
  { id: 'subtechniques', label: 'Sub-Techniques' },
];

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
      </div>
    </div>
  );
}
