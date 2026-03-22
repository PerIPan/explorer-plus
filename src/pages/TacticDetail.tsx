import { useParams } from 'react-router-dom';
import { useTactic, useTechniques } from '../hooks/useApi';
import { PageHeader } from '../components/layout/PageHeader';
import { EntityLink } from '../components/shared/EntityLink';
import { sanitize, sanitizeMarkdown } from '../lib/sanitize';

export function TacticDetail() {
  const { attackId } = useParams<{ attackId: string }>();
  const { data, isLoading, error } = useTactic(attackId ?? '');

  /** Fetch techniques for this tactic using shortName */
  const { data: techData, isLoading: techLoading } = useTechniques(
    data?.shortName ? { tactic: data.shortName, limit: '500' } : {}
  );

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
        Tactic not found.
      </div>
    );
  }

  const description = data.description
    ? sanitize(sanitizeMarkdown(data.description))
    : null;

  const techniques = techData?.data ?? [];

  return (
    <div className="space-y-6">
      <PageHeader
        title={data.name}
        breadcrumb={[
          { label: 'Tactics', href: '/tactics' },
          { label: data.attackId },
        ]}
        actions={
          <span className="font-mono text-xs text-[#fbbf24] bg-[#fbbf2418] border border-[#fbbf2433] px-2 py-1 rounded">
            {data.attackId}
          </span>
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

      {/* Techniques list */}
      <div className="bg-[#16213e] border border-[#2a2a4a] rounded-lg p-5">
        <h3 className="text-sm font-semibold text-[#8892b0] uppercase tracking-wider mb-4">
          Techniques
          {!techLoading && (
            <span className="ml-2 text-[#64ffda] font-semibold normal-case text-sm">
              ({techniques.length})
            </span>
          )}
        </h3>

        {techLoading ? (
          <div className="flex items-center text-[#8892b0] text-sm">
            <span className="inline-block w-4 h-4 border-2 border-[#64ffda33] border-t-[#64ffda] rounded-full animate-spin mr-2" />
            Loading techniques...
          </div>
        ) : techniques.length > 0 ? (
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-2">
            {techniques.map((t) => (
              <EntityLink
                key={t.attackId}
                type="technique"
                attackId={t.attackId}
                name={t.name}
              />
            ))}
          </div>
        ) : (
          <p className="text-[#8892b0] text-sm">No techniques found for this tactic.</p>
        )}
      </div>
    </div>
  );
}
