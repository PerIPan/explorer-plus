'use client';
import { useParams } from 'next/navigation';
import Link from 'next/link';
import { useGroup } from '../hooks/useApi';
import { PageHeader } from '../components/layout/PageHeader';
import { Badge } from '../components/shared/Badge';
import { DeprecatedBadge } from '../components/shared/DeprecatedBadge';
import { sanitize, sanitizeMarkdown } from '../lib/sanitize';
import { DiamondLoader } from '../components/shared/FoldingDiamond';

export function GroupDetail() {
  const { attackId } = useParams<{ attackId: string }>();
  const { data, isLoading, error } = useGroup(attackId ?? '');

  if (isLoading) {
    return <DiamondLoader text="Loading..." />;
  }

  if (error || !data) {
    return (
      <div className="flex items-center justify-center h-64 text-[var(--accent-orange)]">
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
        titleAction={
          <Link
            href={`/?entity=${data.attackId}&tab=actor`}
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
            <span className="font-mono text-xs text-[var(--accent-orange)] bg-[var(--orange-faint)] border border-[var(--orange-dim)] px-2 py-1 rounded">
              {data.attackId}
            </span>
          </div>
        }
      />

      {/* Single metadata card with labeled rows (FIX 24) */}
      <div className="bg-[var(--surface-card)] border border-[var(--border-color)] rounded-lg p-5 space-y-3">
        {data.aliases?.length ? (
          <div className="flex items-start gap-4">
            <span className="text-xs font-semibold text-[var(--text-secondary)] uppercase tracking-wider w-36 shrink-0 pt-0.5">
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
            <span className="text-xs font-semibold text-[var(--text-secondary)] uppercase tracking-wider w-36 shrink-0 pt-0.5">
              Reference
            </span>
            <a
              href={data.url}
              target="_blank"
              rel="noopener noreferrer"
              className="text-xs text-[var(--accent-teal)] hover:underline"
            >
              View on MITRE ATT&amp;CK
            </a>
          </div>
        )}
      </div>

      {/* Description */}
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

      {/* Relationships — inline preview + full graph link (FIX 23) */}
      <div className="bg-[var(--surface-card)] border border-[var(--border-color)] rounded-lg p-5">
        <div className="flex items-center gap-4 mb-3">
          <h3 className="text-sm font-semibold text-[var(--text-secondary)] uppercase tracking-wider">
            Relationships
          </h3>
          <Link
            href={`/?entity=${data.attackId}&tab=actor`}
            className="inline-flex items-center gap-0.5 px-1.5 py-0.5 rounded text-[9px] font-medium text-[var(--text-secondary)] hover:text-[var(--accent-teal)] transition-colors"
          >
            view profile →
          </Link>
        </div>
        <p className="text-sm text-[var(--text-secondary)]">
          Use the Relationships Explorer to visualize techniques, software, and campaigns used by{' '}
          <span className="text-[var(--text-primary)] font-medium">{data.name}</span>.
        </p>
      </div>
    </div>
  );
}
