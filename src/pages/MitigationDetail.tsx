import { useParams, Link } from 'react-router-dom';
import { useMitigation } from '../hooks/useApi';
import { PageHeader } from '../components/layout/PageHeader';
import { DeprecatedBadge } from '../components/shared/DeprecatedBadge';
import { sanitize, sanitizeMarkdown } from '../lib/sanitize';

export function MitigationDetail() {
  const { attackId } = useParams<{ attackId: string }>();
  const { data, isLoading, error } = useMitigation(attackId ?? '');

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
        Mitigation not found.
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
          { label: 'Mitigations', href: '/mitigations' },
          { label: data.attackId },
        ]}
        actions={
          <div className="flex items-center gap-2">
            {(data.isRevoked || data.isDeprecated) && (
              <DeprecatedBadge isRevoked={data.isRevoked} />
            )}
            <span className="font-mono text-xs text-[var(--accent-green)] bg-[var(--green-faint)] border border-[var(--green-dim)] px-2 py-1 rounded">
              {data.attackId}
            </span>
          </div>
        }
      />

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
        <div className="flex items-center justify-between mb-3">
          <h3 className="text-sm font-semibold text-[var(--text-secondary)] uppercase tracking-wider">
            Mitigated Techniques
          </h3>
          <Link
            to={`/relationships?entity=${data.attackId}`}
            className="text-xs text-[var(--accent-teal)] hover:underline"
          >
            View full graph &rarr;
          </Link>
        </div>
        <p className="text-sm text-[var(--text-secondary)]">
          Explore techniques this mitigation addresses in the Relationships Explorer.
        </p>
      </div>
    </div>
  );
}
