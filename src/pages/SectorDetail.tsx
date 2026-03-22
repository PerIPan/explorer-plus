import { useParams } from 'react-router-dom';
import { useGroups } from '../hooks/useApi';
import { PageHeader } from '../components/layout/PageHeader';
import { EntityLink } from '../components/shared/EntityLink';

export function SectorDetail() {
  const { sectorName } = useParams<{ sectorName: string }>();
  const decodedName = sectorName ? decodeURIComponent(sectorName) : '';

  const { data, isLoading, error } = useGroups(
    decodedName ? { sector: decodedName, limit: '500' } : {}
  );

  if (isLoading) {
    return (
      <div className="flex items-center justify-center h-64 text-[#8892b0]">
        <span className="inline-block w-5 h-5 border-2 border-[#64ffda33] border-t-[#64ffda] rounded-full animate-spin mr-2" />
        Loading...
      </div>
    );
  }

  if (error) {
    return (
      <div className="flex items-center justify-center h-64 text-[#f97316]">
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

      <div className="bg-[#16213e] border border-[#2a2a4a] rounded-lg p-5">
        <h3 className="text-sm font-semibold text-[#a8b2d8] uppercase tracking-wider mb-4">
          Groups targeting this sector
          <span className="ml-2 text-[#f97316] font-semibold normal-case text-sm">
            ({groups.length})
          </span>
        </h3>

        {groups.length > 0 ? (
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-3">
            {groups.map((g) => (
              <div
                key={g.attackId}
                className="bg-[#1a1a2e] border border-[#2a2a4a] rounded-lg p-3 hover:border-[#f9731644] transition-colors"
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
          <p className="text-[#8892b0] text-sm">No groups found for this sector.</p>
        )}
      </div>
    </div>
  );
}
