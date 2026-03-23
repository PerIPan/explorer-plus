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
      <div className="flex items-center justify-center h-64 text-[var(--text-secondary)]">
        <span className="inline-block w-5 h-5 border-2 border-[var(--teal-dim)] border-t-[var(--accent-teal)] rounded-full animate-spin mr-2" />
        Loading...
      </div>
    );
  }

  if (error || !data) {
    return (
      <div className="flex items-center justify-center h-64 text-[var(--accent-orange)]">
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
            <span className="font-mono text-xs text-[var(--accent-blue)] bg-[var(--blue-faint)] border border-[var(--blue-dim)] px-2 py-1 rounded">
              {data.attackId}
            </span>
          </div>
        }
      />

      {/* Timeline card — only render when at least one date exists (FIX 25) */}
      {(data.firstSeen || data.lastSeen) && (
        <div className="bg-[var(--surface-card)] border border-[var(--border-color)] rounded-lg p-5">
          <h3 className="text-sm font-semibold text-[var(--text-secondary)] uppercase tracking-wider mb-3">
            Timeline
          </h3>
          <div className="flex gap-8 text-sm mb-3">
            {data.firstSeen && (
              <div>
                <span className="text-[var(--text-secondary)]">First Seen: </span>
                <span className="text-[var(--text-primary)]">{fmtDate(data.firstSeen)}</span>
              </div>
            )}
            {data.lastSeen && (
              <div>
                <span className="text-[var(--text-secondary)]">Last Seen: </span>
                <span className="text-[var(--text-primary)]">{fmtDate(data.lastSeen)}</span>
              </div>
            )}
          </div>
          <CampaignTimeline
            firstSeen={data.firstSeen}
            lastSeen={data.lastSeen}
            name={data.name}
          />
        </div>
      )}

      {/* Aliases */}
      {data.aliases?.length ? (
        <div className="bg-[var(--surface-card)] border border-[var(--border-color)] rounded-lg p-5">
          <h3 className="text-sm font-semibold text-[var(--text-secondary)] uppercase tracking-wider mb-3">
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
        <div className="bg-[var(--surface-card)] border border-[var(--border-color)] rounded-lg p-5">
          <h3 className="text-sm font-semibold text-[var(--text-secondary)] uppercase tracking-wider mb-3">
            Description
          </h3>
          <p className="text-[var(--text-primary)] text-sm leading-relaxed whitespace-pre-wrap">
            {description}
          </p>
        </div>
      )}

      {/* Relationships — FIX 23 */}
      <div className="bg-[var(--surface-card)] border border-[var(--border-color)] rounded-lg p-5">
        <div className="flex items-center justify-between mb-3">
          <h3 className="text-sm font-semibold text-[var(--text-secondary)] uppercase tracking-wider">
            Relationships
          </h3>
          <Link
            to={`/relationships?entity=${data.attackId}`}
            className="text-xs text-[var(--accent-teal)] hover:underline"
          >
            View full graph &rarr;
          </Link>
        </div>
        <p className="text-sm text-[var(--text-secondary)]">
          Explore techniques, groups, and software for{' '}
          <span className="text-[var(--text-primary)] font-medium">{data.name}</span>{' '}
          in the Relationships Explorer.
        </p>
      </div>
    </div>
  );
}
