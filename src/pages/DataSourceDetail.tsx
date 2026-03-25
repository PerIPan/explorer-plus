import { useParams, Link } from 'react-router-dom';
import { usePageTitle } from '../hooks/usePageTitle';
import { useDataSource } from '../hooks/useApi';
import { PageHeader } from '../components/layout/PageHeader';
import { sanitize, sanitizeMarkdown } from '../lib/sanitize';

export function DataSourceDetail() {
  const { attackId } = useParams<{ attackId: string }>();
  const { data, isLoading, error } = useDataSource(attackId ?? '');
  usePageTitle(data ? `${data.name} ${data.attackId}` : 'Data Source');

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
        titleAction={
          <Link to={`/?entity=${data.attackId}&tab=data-source-map`} className="inline-flex items-center gap-0.5 px-1.5 py-0.5 rounded text-[9px] font-medium text-[var(--text-secondary)] hover:text-[var(--accent-teal)] transition-colors" title="View in 360 Views">360 →</Link>
        }
        actions={
          <span className="font-mono text-xs text-[var(--accent-pink)] bg-[var(--pink-faint)] border border-[var(--pink-dim)] px-2 py-1 rounded">{data.attackId}</span>
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

      {/* Data components */}
      {data.components?.length ? (
        <div className="bg-[var(--surface-card)] border border-[var(--border-color)] rounded-lg p-5">
          <h3 className="text-sm font-semibold text-[var(--text-secondary)] uppercase tracking-wider mb-4">
            Data Components ({data.components.length})
          </h3>
          <div className="space-y-3">
            {data.components.map((comp: { componentId?: string; componentName?: string; componentDescription?: string; id?: string; name?: string; description?: string | null }) => {
              const name = comp.componentName ?? comp.name ?? '';
              const desc = comp.componentDescription ?? comp.description ?? '';
              const compDesc = desc ? sanitize(sanitizeMarkdown(desc)) : null;
              const key = comp.componentId ?? comp.id ?? name;
              return (
                <div
                  key={key}
                  className="border border-[var(--border-color)] rounded-lg p-3 bg-[var(--surface-base)]"
                >
                  <div className="flex items-center gap-2 mb-1">
                    <span className="text-sm font-medium text-[var(--accent-pink)]">
                      {name}
                    </span>
                  </div>
                  {compDesc && (
                    <p className="text-xs text-[var(--text-secondary)] leading-relaxed">
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
