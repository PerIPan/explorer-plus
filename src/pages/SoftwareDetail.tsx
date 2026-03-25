import { useParams, Link } from 'react-router-dom';
import { usePageTitle } from '../hooks/usePageTitle';
import { useSoftwareDetail } from '../hooks/useApi';
import { PageHeader } from '../components/layout/PageHeader';
import { Badge } from '../components/shared/Badge';
import { DeprecatedBadge } from '../components/shared/DeprecatedBadge';
import { sanitize, sanitizeMarkdown } from '../lib/sanitize';

export function SoftwareDetail() {
  const { attackId } = useParams<{ attackId: string }>();
  const { data, isLoading, error } = useSoftwareDetail(attackId ?? '');
  usePageTitle(data ? `${data.name} ${data.attackId}` : 'Software');

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
        titleAction={
          <Link
            to={`/?entity=${data.attackId}&tab=software-map`}
            className="inline-flex items-center gap-0.5 px-1.5 py-0.5 rounded text-[9px] font-medium text-[var(--text-secondary)] hover:text-[var(--accent-teal)] transition-colors"
            title="View in 360 Views"
          >
            360 →
          </Link>
        }
        actions={
          <div className="flex items-center gap-2">
            {(data.isRevoked || data.isDeprecated) && (
              <DeprecatedBadge isRevoked={data.isRevoked} />
            )}
            <Badge
              label={data.type === 'malware' ? 'Malware' : 'Tool'}
              variant={data.type === 'malware' ? 'orange' : 'teal'}
            />
            <span className="font-mono text-xs text-[var(--accent-purple)] bg-[var(--purple-faint)] border border-[var(--purple-dim)] px-2 py-1 rounded">
              {data.attackId}
            </span>
          </div>
        }
      />

      {/* Metadata */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        {data.platforms?.length ? (
          <div className="bg-[var(--surface-card)] border border-[var(--border-color)] rounded-lg p-4">
            <h3 className="text-xs font-semibold text-[var(--text-secondary)] uppercase tracking-wider mb-2">
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
          <div className="bg-[var(--surface-card)] border border-[var(--border-color)] rounded-lg p-4">
            <h3 className="text-xs font-semibold text-[var(--text-secondary)] uppercase tracking-wider mb-2">
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
        <div className="bg-[var(--surface-card)] border border-[var(--border-color)] rounded-lg p-5">
          <h3 className="text-sm font-semibold text-[var(--text-secondary)] uppercase tracking-wider mb-3">
            Description
          </h3>
          <p
            className="text-[var(--text-primary)] text-sm leading-relaxed whitespace-pre-wrap"
            dangerouslySetInnerHTML={{ __html: description }}
          />
        </div>
      )}

      {data.url && (
        <a
          href={data.url}
          target="_blank"
          rel="noopener noreferrer"
          className="inline-flex items-center gap-1 text-xs text-[var(--accent-teal)] hover:underline"
        >
          View on MITRE ATT&CK
        </a>
      )}

      <div className="bg-[var(--surface-card)] border border-[var(--border-color)] rounded-lg p-5">
        <div className="flex items-center gap-4 mb-3">
          <h3 className="text-sm font-semibold text-[var(--text-secondary)] uppercase tracking-wider">
            Relationships
          </h3>
          <Link
            to={`/?entity=${data.attackId}&tab=software-map`}
            className="inline-flex items-center gap-0.5 px-1.5 py-0.5 rounded text-[9px] font-medium text-[var(--text-secondary)] hover:text-[var(--accent-teal)] transition-colors"
          >
            view map →
          </Link>
        </div>
        <p className="text-sm text-[var(--text-secondary)]">
          Explore groups that use{' '}
          <span className="text-[var(--text-primary)] font-medium">{data.name}</span>{' '}
          and the techniques it employs in the Relationships Explorer.
        </p>
      </div>
    </div>
  );
}
