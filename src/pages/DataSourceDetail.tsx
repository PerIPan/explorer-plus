import { useParams } from 'react-router-dom';
import { useDataSource } from '../hooks/useApi';
import { PageHeader } from '../components/layout/PageHeader';
import { sanitize, sanitizeMarkdown } from '../lib/sanitize';

export function DataSourceDetail() {
  const { attackId } = useParams<{ attackId: string }>();
  const { data, isLoading, error } = useDataSource(attackId ?? '');

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
        Data source not found.
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
          { label: 'Data Sources', href: '/data-sources' },
          { label: data.attackId },
        ]}
        actions={
          <span className="font-mono text-xs text-[#f472b6] bg-[#f472b618] border border-[#f472b633] px-2 py-1 rounded">
            {data.attackId}
          </span>
        }
      />

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

      {/* Data components */}
      {data.components?.length ? (
        <div className="bg-[#16213e] border border-[#2a2a4a] rounded-lg p-5">
          <h3 className="text-sm font-semibold text-[#a8b2d8] uppercase tracking-wider mb-4">
            Data Components ({data.components.length})
          </h3>
          <div className="space-y-3">
            {data.components.map((comp) => {
              const compDesc = comp.description
                ? sanitize(sanitizeMarkdown(comp.description))
                : null;
              return (
                <div
                  key={comp.id}
                  className="border border-[#2a2a4a] rounded-lg p-3 bg-[#1a1a2e]"
                >
                  <div className="flex items-center gap-2 mb-1">
                    <span className="text-sm font-medium text-[#f472b6]">
                      {comp.name}
                    </span>
                  </div>
                  {compDesc && (
                    <p className="text-xs text-[#8892b0] leading-relaxed">
                      {compDesc}
                    </p>
                  )}
                </div>
              );
            })}
          </div>
        </div>
      ) : null}
    </div>
  );
}
