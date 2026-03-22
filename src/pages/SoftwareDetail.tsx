import { useParams, Link } from 'react-router-dom';
import { useSoftwareDetail } from '../hooks/useApi';
import { PageHeader } from '../components/layout/PageHeader';
import { Badge } from '../components/shared/Badge';
import { DeprecatedBadge } from '../components/shared/DeprecatedBadge';
import { sanitize, sanitizeMarkdown } from '../lib/sanitize';

export function SoftwareDetail() {
  const { attackId } = useParams<{ attackId: string }>();
  const { data, isLoading, error } = useSoftwareDetail(attackId ?? '');

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
        Software not found.
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
          { label: 'Software', href: '/software' },
          { label: data.attackId },
        ]}
        actions={
          <div className="flex items-center gap-2">
            {(data.isRevoked || data.isDeprecated) && (
              <DeprecatedBadge isRevoked={data.isRevoked} />
            )}
            <Badge
              label={data.type === 'malware' ? 'Malware' : 'Tool'}
              variant={data.type === 'malware' ? 'orange' : 'teal'}
            />
            <span className="font-mono text-xs text-[#a78bfa] bg-[#a78bfa18] border border-[#a78bfa33] px-2 py-1 rounded">
              {data.attackId}
            </span>
          </div>
        }
      />

      {/* Metadata */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        {data.platforms?.length ? (
          <div className="bg-[#16213e] border border-[#2a2a4a] rounded-lg p-4">
            <h3 className="text-xs font-semibold text-[#a8b2d8] uppercase tracking-wider mb-2">
              Platforms
            </h3>
            <div className="flex flex-wrap gap-1.5">
              {data.platforms.map((p) => (
                <Badge key={p} label={p} variant="blue" />
              ))}
            </div>
          </div>
        ) : null}

        {data.aliases?.length ? (
          <div className="bg-[#16213e] border border-[#2a2a4a] rounded-lg p-4">
            <h3 className="text-xs font-semibold text-[#a8b2d8] uppercase tracking-wider mb-2">
              Aliases
            </h3>
            <div className="flex flex-wrap gap-1.5">
              {data.aliases.map((a) => (
                <Badge key={a} label={a} variant="purple" />
              ))}
            </div>
          </div>
        ) : null}
      </div>

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

      {data.url && (
        <a
          href={data.url}
          target="_blank"
          rel="noopener noreferrer"
          className="inline-flex items-center gap-1 text-xs text-[#64ffda] hover:underline"
        >
          View on MITRE ATT&CK
        </a>
      )}

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
          Explore groups that use{' '}
          <span className="text-[#ccd6f6] font-medium">{data.name}</span>{' '}
          and the techniques it employs in the Relationships Explorer.
        </p>
      </div>
    </div>
  );
}
