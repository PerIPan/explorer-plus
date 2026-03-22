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
      <div className="flex items-center justify-center h-64 text-[#8892b0]">
        <span className="inline-block w-5 h-5 border-2 border-[#64ffda33] border-t-[#64ffda] rounded-full animate-spin mr-2" />
        Loading...
      </div>
    );
  }

  if (error || !data) {
    return (
      <div className="flex items-center justify-center h-64 text-[#f97316]">
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
            <span className="font-mono text-xs text-[#34d399] bg-[#34d39918] border border-[#34d39933] px-2 py-1 rounded">
              {data.attackId}
            </span>
          </div>
        }
      />

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
        <h3 className="text-sm font-semibold text-[#8892b0] uppercase tracking-wider mb-2">
          Mitigated Techniques
        </h3>
        <p className="text-sm text-[#8892b0]">
          Explore techniques this mitigation addresses in the{' '}
          <Link
            to={`/relationships?entity=${data.attackId}`}
            className="text-[#64ffda] hover:underline"
          >
            Relationships Explorer
          </Link>
          .
        </p>
      </div>
    </div>
  );
}
