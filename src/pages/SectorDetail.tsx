import { useParams } from 'react-router-dom';
import { usePageTitle } from '../hooks/usePageTitle';
import { useGroups } from '../hooks/useApi';
import { PageHeader } from '../components/layout/PageHeader';
import { EntityLink } from '../components/shared/EntityLink';

export function SectorDetail() {
  const { sectorName } = useParams<{ sectorName: string }>();
  const decodedName = sectorName ? decodeURIComponent(sectorName) : '';

  const { data, isLoading, error } = useGroups(
    decodedName ? { sector: decodedName, limit: '500' } : {}
  );
  usePageTitle(decodedName ? `${decodedName} Sector` : 'Sector');

  if (isLoading) {
    return (
      <div className="flex items-center justify-center h-64 text-[var(--text-secondary)]">
        <span className="inline-block w-5 h-5 border-2 border-[var(--teal-dim)] border-t-[var(--accent-teal)] rounded-full animate-spin mr-2" />
        Loading...
      </div>
    );
  }

  if (error) {
    return (
      <div className="flex items-center justify-center h-64 text-[var(--accent-orange)]">
        Failed to load sector data.
      </div>
    );
  }

  const groups = data?.data ?? [];

  return (
    <div className="space-y-6">
      <PageHeader
        title={decodedName}
        breadcrumb={[
          { label: 'Sectors', href: '/sectors' },
          { label: decodedName },
        ]}
      />

      <div className="bg-[var(--surface-card)] border border-[var(--border-color)] rounded-lg p-5">
        <h3 className="text-sm font-semibold text-[var(--text-secondary)] uppercase tracking-wider mb-4">
          Groups targeting this sector
          <span className="ml-2 text-[var(--accent-orange)] font-semibold normal-case text-sm">
            ({groups.length})
          </span>
        </h3>

        {groups.length > 0 ? (
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-3">
            {groups.map((g) => (
              <div
                key={g.attackId}
                className="bg-[var(--surface-base)] border border-[var(--border-color)] rounded-lg p-3 hover:border-[var(--orange-dim)] transition-colors"
              >
                <EntityLink
                  type="group"
                  attackId={g.attackId}
                  name={g.name}
                />
              </div>
            ))}
          </div>
        ) : (
          <p className="text-[var(--text-secondary)] text-sm">No groups found for this sector.</p>
        )}
      </div>
    </div>
  );
}
