import { useNavigate } from 'react-router-dom';
import { useSectors } from '../hooks/useApi';
import { PageHeader } from '../components/layout/PageHeader';
import { DataTable, type ColumnDef } from '../components/shared/DataTable';
import type { Sector } from '../lib/types';

export function SectorsList() {
  const navigate = useNavigate();

  const { data, isLoading } = useSectors();

  const columns: ColumnDef<Sector>[] = [
    {
      key: 'name',
      header: 'Sector',
      render: (row) => (
        <span className="text-[#ccd6f6] font-medium">{row.name}</span>
      ),
    },
    {
      key: 'groupCount',
      header: 'Groups',
      width: '100px',
      align: 'center',
      render: (row) => (
        <span className="text-xs text-[#8892b0] font-mono">{row.groupCount}</span>
      ),
    },
  ];

  return (
    <div className="space-y-4">
      <PageHeader title="Sectors" subtitle="Industry sectors targeted by tracked threat groups" />

      <DataTable
        columns={columns}
        data={data?.data ?? []}
        loading={isLoading}
        onRowClick={(row) => navigate(`/sectors/${row.slug ?? encodeURIComponent(row.name)}`)}
        rowKey={(row) => row.name}
        emptyMessage="No sectors found."
      />
    </div>
  );
}
