import { useParams, Link } from 'react-router-dom';
import { useCampaign } from '../hooks/useApi';
import { PageHeader } from '../components/layout/PageHeader';
import { Badge } from '../components/shared/Badge';
import { DeprecatedBadge } from '../components/shared/DeprecatedBadge';
import { CampaignTimeline } from '../components/charts/CampaignTimeline';
import { sanitize, sanitizeMarkdown } from '../lib/sanitize';

function fmtDate(d: string | null) {
  if (!d) return 'Unknown';
  return new Date(d).toLocaleDateString('en-US', {
    year: 'numeric',
    month: 'long',
  });
}

export function CampaignDetail() {
  const { attackId } = useParams<{ attackId: string }>();
  const { data, isLoading, error } = useCampaign(attackId ?? '');

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
        Campaign not found.
      </div>
    );
  }

  const description = data.description
    ? sanitize(sanitizeMarkdown(data.description))
    : null;

  return (
    <div className="space-y-6">
      <PageHeader
        title={data.name}
        breadcrumb={[
          { label: 'Campaigns', href: '/campaigns' },
          { label: data.attackId },
        ]}
        actions={
          <div className="flex items-center gap-2">
            {(data.isRevoked || data.isDeprecated) && (
              <DeprecatedBadge isRevoked={data.isRevoked} />
            )}
            <span className="font-mono text-xs text-[#60a5fa] bg-[#60a5fa18] border border-[#60a5fa33] px-2 py-1 rounded">
              {data.attackId}
            </span>
          </div>
        }
      />

      {/* Timeline card — only render when at least one date exists (FIX 25) */}
      {(data.first_seen || data.last_seen) && (
        <div className="bg-[#16213e] border border-[#2a2a4a] rounded-lg p-5">
          <h3 className="text-sm font-semibold text-[#8892b0] uppercase tracking-wider mb-3">
            Timeline
          </h3>
          <div className="flex gap-8 text-sm mb-3">
            {data.first_seen && (
              <div>
                <span className="text-[#8892b0]">First Seen: </span>
                <span className="text-[#ccd6f6]">{fmtDate(data.first_seen)}</span>
              </div>
            )}
            {data.last_seen && (
              <div>
                <span className="text-[#8892b0]">Last Seen: </span>
                <span className="text-[#ccd6f6]">{fmtDate(data.last_seen)}</span>
              </div>
            )}
          </div>
          <CampaignTimeline
            firstSeen={data.first_seen}
            lastSeen={data.last_seen}
            name={data.name}
          />
        </div>
      )}

      {/* Aliases */}
      {data.aliases?.length ? (
        <div className="bg-[#16213e] border border-[#2a2a4a] rounded-lg p-5">
          <h3 className="text-sm font-semibold text-[#a8b2d8] uppercase tracking-wider mb-3">
            Aliases
          </h3>
          <div className="flex flex-wrap gap-1.5">
            {data.aliases.map((a) => (
              <Badge key={a} label={a} variant="blue" />
            ))}
          </div>
        </div>
      ) : null}

      {/* Description */}
      {description && (
        <div className="bg-[#16213e] border border-[#2a2a4a] rounded-lg p-5">
          <h3 className="text-sm font-semibold text-[#a8b2d8] uppercase tracking-wider mb-3">
            Description
          </h3>
          <p className="text-[#ccd6f6] text-sm leading-relaxed whitespace-pre-wrap">
            {description}
          </p>
        </div>
      )}

      {/* Relationships — FIX 23 */}
      <div className="bg-[#16213e] border border-[#2a2a4a] rounded-lg p-5">
        <div className="flex items-center justify-between mb-3">
          <h3 className="text-sm font-semibold text-[#8892b0] uppercase tracking-wider">
            Relationships
          </h3>
          <Link
            to={`/relationships?entity=${data.attackId}`}
            className="text-xs text-[#64ffda] hover:underline"
          >
            View full graph &rarr;
          </Link>
        </div>
        <p className="text-sm text-[#8892b0]">
          Explore techniques, groups, and software for{' '}
          <span className="text-[#ccd6f6] font-medium">{data.name}</span>{' '}
          in the Relationships Explorer.
        </p>
      </div>
    </div>
  );
}
