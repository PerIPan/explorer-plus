import { useParams, Link } from 'react-router-dom';
import { useGroup } from '../hooks/useApi';
import { PageHeader } from '../components/layout/PageHeader';
import { Badge } from '../components/shared/Badge';
import { DeprecatedBadge } from '../components/shared/DeprecatedBadge';
import { sanitize, sanitizeMarkdown } from '../lib/sanitize';

export function GroupDetail() {
  const { attackId } = useParams<{ attackId: string }>();
  const { data, isLoading, error } = useGroup(attackId ?? '');

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
        Group not found.
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
          { label: 'Groups', href: '/groups' },
          { label: data.attackId },
        ]}
        actions={
          <div className="flex items-center gap-2">
            {(data.isRevoked || data.isDeprecated) && (
              <DeprecatedBadge isRevoked={data.isRevoked} />
            )}
            <span className="font-mono text-xs text-[#f97316] bg-[#f9731618] border border-[#f9731633] px-2 py-1 rounded">
              {data.attackId}
            </span>
          </div>
        }
      />

      {/* Single metadata card with labeled rows (FIX 24) */}
      <div className="bg-[#16213e] border border-[#2a2a4a] rounded-lg p-5 space-y-3">
        {data.country && (
          <div className="flex items-start gap-4">
            <span className="text-xs font-semibold text-[#8892b0] uppercase tracking-wider w-36 shrink-0 pt-0.5">
              Country / Attribution
            </span>
            <Badge label={data.country} variant="orange" />
          </div>
        )}
        {data.aliases?.length ? (
          <div className="flex items-start gap-4">
            <span className="text-xs font-semibold text-[#8892b0] uppercase tracking-wider w-36 shrink-0 pt-0.5">
              Aliases
            </span>
            <div className="flex flex-wrap gap-1.5">
              {data.aliases.map((a) => (
                <Badge key={a} label={a} variant="orange" />
              ))}
            </div>
          </div>
        ) : null}
        {data.url && (
          <div className="flex items-start gap-4">
            <span className="text-xs font-semibold text-[#8892b0] uppercase tracking-wider w-36 shrink-0 pt-0.5">
              Reference
            </span>
            <a
              href={data.url}
              target="_blank"
              rel="noopener noreferrer"
              className="text-xs text-[#64ffda] hover:underline"
            >
              View on MITRE ATT&amp;CK
            </a>
          </div>
        )}
      </div>

      {/* Description */}
      {description && (
        <div className="bg-[#16213e] border border-[#2a2a4a] rounded-lg p-5">
          <h3 className="text-sm font-semibold text-[#8892b0] uppercase tracking-wider mb-3">
            Description
          </h3>
          <p className="text-[#ccd6f6] text-sm leading-relaxed whitespace-pre-wrap">
            {description}
          </p>
        </div>
      )}

      {/* Relationships — inline preview + full graph link (FIX 23) */}
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
          Use the Relationships Explorer to visualize techniques, software, and campaigns used by{' '}
          <span className="text-[#ccd6f6] font-medium">{data.name}</span>.
        </p>
      </div>
    </div>
  );
}
