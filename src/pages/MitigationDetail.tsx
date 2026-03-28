import { useParams, Link } from 'react-router-dom';
import { usePageTitle } from '../hooks/usePageTitle';
import { useMitigation } from '../hooks/useApi';
import { PageHeader } from '../components/layout/PageHeader';
import { DeprecatedBadge } from '../components/shared/DeprecatedBadge';
import { sanitize, sanitizeMarkdown } from '../lib/sanitize';
import { DiamondLoader } from '../components/shared/FoldingDiamond';

export function MitigationDetail() {
  const { attackId } = useParams<{ attackId: string }>();
  const { data, isLoading, error } = useMitigation(attackId ?? '');
  usePageTitle(data ? `${data.name} ${data.attackId}` : 'Mitigation');

  if (isLoading) {
    return <DiamondLoader text="Loading..." />;
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
        titleAction={
          <Link to={`/?entity=${data.attackId}&tab=mitigation-map`} className="inline-flex items-center gap-0.5 px-1.5 py-0.5 rounded text-[9px] font-medium text-[var(--text-secondary)] hover:text-[var(--accent-teal)] transition-colors" title="View in 360 Views">360 →</Link>
        }
        actions={
          <div className="flex items-center gap-2">
            {(data.isRevoked || data.isDeprecated) && (<DeprecatedBadge isRevoked={data.isRevoked} />)}
            <span className="font-mono text-xs text-[var(--accent-green)] bg-[var(--green-faint)] border border-[var(--green-dim)] px-2 py-1 rounded">{data.attackId}</span>
          </div>
        }
      />

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
            Mitigated Techniques
          </h3>
          <Link
            to={`/?entity=${data.attackId}&tab=mitigation-map`}
            className="inline-flex items-center gap-0.5 px-1.5 py-0.5 rounded text-[9px] font-medium text-[var(--text-secondary)] hover:text-[var(--accent-teal)] transition-colors"
          >
            view map →
          </Link>
        </div>
        <p className="text-sm text-[var(--text-secondary)]">
          Explore techniques this mitigation addresses in the Relationships Explorer.
        </p>
      </div>
    </div>
  );
}
