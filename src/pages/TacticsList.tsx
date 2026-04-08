import { useMemo } from 'react';
import { useNavigate } from 'react-router-dom';
import { useTactics } from '../hooks/useApi';
import { useSector } from '../contexts/SectorContext';
import { useDomain } from '../contexts/DomainContext';
import { PageHeader } from '../components/layout/PageHeader';
import { DataTable, type ColumnDef } from '../components/shared/DataTable';
import { EntityLink } from '../components/shared/EntityLink';
import type { Tactic } from '../lib/types';

export function TacticsList() {

  const navigate = useNavigate();
  const { sectorParam } = useSector();
  const { domainParam } = useDomain();
  const { data, isLoading } = useTactics({ limit: '100', ...sectorParam, ...domainParam });

  /** Sort by kill chain order (sortOrder) */
  const sorted = useMemo(
    () =>
      [...(data?.data ?? [])].sort((a, b) => (a.sortOrder ?? 0) - (b.sortOrder ?? 0)),
    [data]
  );

  const columns: ColumnDef<Tactic>[] = [
    {
      key: 'sortOrder',
      header: '#',
      width: '50px',
      align: 'center',
      render: (row) => (
        <span className="text-xs text-[var(--border-color)] font-mono">{row.sortOrder}</span>
      ),
    },
    {
      key: 'attackId',
      header: 'ATT&CK ID',
      width: '120px',
      render: (row) => (
        <span className="font-mono text-xs text-[var(--accent-yellow)]">{row.attackId}</span>
      ),
    },
    {
      key: 'name',
      header: 'Tactic',
      render: (row) => (
        <EntityLink type="tactic" attackId={row.attackId} name={row.name} />
      ),
    },
    {
      key: 'domain',
      header: 'Domain',
      width: '70px',
      align: 'center',
      render: (row) =>
        row.domain ? (
          <span className="text-[10px] text-[var(--text-secondary)] uppercase block text-center">{row.domain.replace('-attack', '')}</span>
        ) : null,
    },
  ];

  return (
    <div className="space-y-4">
      <PageHeader
        title="Tactics"
        subtitle={isLoading ? 'Loading tactics...' : `${sorted.length} MITRE ATT&CK tactics in kill chain order`}
      />

      <DataTable
        columns={columns}
        data={sorted}
        loading={isLoading}
        onRowClick={(row) => navigate(`/tactics/${row.attackId}`)}
        rowKey={(row) => row.attackId}
        emptyMessage="No tactics found."
      />
    </div>
  );
}
