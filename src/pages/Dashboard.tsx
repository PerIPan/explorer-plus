import { useDashboard } from '../hooks/useApi';
import { PageHeader } from '../components/layout/PageHeader';
import { StatCard } from '../components/shared/StatCard';
import { EntityLink } from '../components/shared/EntityLink';
import { TacticBarChart } from '../components/charts/TacticBarChart';
import { SectorPieChart } from '../components/charts/SectorPieChart';
import { GroupTechniqueChart } from '../components/charts/GroupTechniqueChart';

export function Dashboard() {
  const { data, isLoading, error } = useDashboard();

  if (isLoading) {
    return (
      <div className="flex items-center justify-center h-64 text-[#8892b0]">
        <span className="inline-block w-5 h-5 border-2 border-[#64ffda33] border-t-[#64ffda] rounded-full animate-spin mr-2" />
        Loading dashboard...
      </div>
    );
  }

  if (error || !data) {
    return (
      <div className="flex items-center justify-center h-64 text-[#f97316]">
        Failed to load dashboard data.
      </div>
    );
  }

  const { stats, topGroups, tacticDistribution, sectorBreakdown } = data;

  return (
    <div className="space-y-6">
      <PageHeader
        title="Dashboard"
        subtitle="MITRE ATT&CK knowledge base overview"
      />

      {/* Stat cards */}
      <div className="grid grid-cols-2 lg:grid-cols-3 xl:grid-cols-6 gap-4">
        <StatCard
          label="Techniques"
          value={stats.techniqueCount}
          accent="text-[#64ffda]"
        />
        <StatCard
          label="Groups"
          value={stats.groupCount}
          accent="text-[#f97316]"
        />
        <StatCard
          label="Software"
          value={stats.softwareCount}
          accent="text-[#a78bfa]"
        />
        <StatCard
          label="Campaigns"
          value={stats.campaignCount}
          accent="text-[#60a5fa]"
        />
        <StatCard
          label="Mitigations"
          value={stats.mitigationCount}
          accent="text-[#34d399]"
        />
        <StatCard
          label="Data Sources"
          value={stats.dataSourceCount}
          accent="text-[#f472b6]"
        />
      </div>

      {/* Charts row */}
      <div className="grid grid-cols-1 xl:grid-cols-2 gap-6">
        {/* Tactic distribution */}
        <div className="bg-[#16213e] border border-[#2a2a4a] rounded-lg p-5">
          <h2 className="text-sm font-semibold text-[#ccd6f6] mb-4">
            Techniques per Tactic
          </h2>
          {tacticDistribution.length > 0 ? (
            <TacticBarChart data={tacticDistribution} />
          ) : (
            <p className="text-[#8892b0] text-sm">No data available.</p>
          )}
        </div>

        {/* Sector breakdown */}
        <div className="bg-[#16213e] border border-[#2a2a4a] rounded-lg p-5">
          <h2 className="text-sm font-semibold text-[#ccd6f6] mb-4">
            Groups by Sector
          </h2>
          {sectorBreakdown.length > 0 ? (
            <SectorPieChart data={sectorBreakdown} />
          ) : (
            <p className="text-[#8892b0] text-sm">No sector data available.</p>
          )}
        </div>
      </div>

      {/* Top groups */}
      <div className="grid grid-cols-1 xl:grid-cols-2 gap-6">
        <div className="bg-[#16213e] border border-[#2a2a4a] rounded-lg p-5">
          <h2 className="text-sm font-semibold text-[#ccd6f6] mb-4">
            Top Groups by Technique Coverage
          </h2>
          {topGroups.length > 0 ? (
            <GroupTechniqueChart data={topGroups.slice(0, 10)} />
          ) : (
            <p className="text-[#8892b0] text-sm">No group data available.</p>
          )}
        </div>

        {/* Top groups table */}
        <div className="bg-[#16213e] border border-[#2a2a4a] rounded-lg p-5">
          <h2 className="text-sm font-semibold text-[#ccd6f6] mb-4">
            Top 10 Groups
          </h2>
          <div className="space-y-2">
            {topGroups.slice(0, 10).map((g, i) => (
              <div
                key={g.attackId}
                className="flex items-center justify-between py-1.5 border-b border-[#2a2a4a] last:border-0"
              >
                <div className="flex items-center gap-3">
                  <span className="text-xs text-[#2a2a4a] font-mono w-5 text-right">
                    {i + 1}
                  </span>
                  <EntityLink
                    type="group"
                    attackId={g.attackId}
                    name={g.name}
                  />
                </div>
                <span className="text-sm font-semibold text-[#f97316] tabular-nums">
                  {g.techniqueCount}
                </span>
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
}
