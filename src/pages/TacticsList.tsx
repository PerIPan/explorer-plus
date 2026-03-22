import { useMemo } from 'react';
import { useNavigate } from 'react-router-dom';
import { useTactics } from '../hooks/useApi';
import { PageHeader } from '../components/layout/PageHeader';
import { DataTable, type ColumnDef } from '../components/shared/DataTable';
import { EntityLink } from '../components/shared/EntityLink';
import type { Tactic } from '../lib/types';

export function TacticsList() {
  const navigate = useNavigate();
  const { data, isLoading } = useTactics({ limit: '100' });

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
        <span className="text-xs text-[#2a2a4a] font-mono">{row.sortOrder}</span>
      ),
    },
    {
      key: 'attackId',
      header: 'ATT&CK ID',
      width: '120px',
      render: (row) => (
        <span className="font-mono text-xs text-[#fbbf24]">{row.attackId}</span>
      ),
    },
    {
      key: 'name',
      header: 'Tactic',
      render: (row) => (
        <EntityLink type="tactic" attackId={row.attackId} name={row.name} />
      ),
    },
  ];

  return (
    <div className="space-y-4">
      <PageHeader
        title="Tactics"
        subtitle="The 14 MITRE ATT&CK tactics in kill chain order"
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
