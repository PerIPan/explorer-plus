import { useNavigate, useSearchParams } from 'react-router-dom';
import { useSectors } from '../hooks/useApi';
import { PageHeader } from '../components/layout/PageHeader';
import { DataTable, type ColumnDef } from '../components/shared/DataTable';
import type { Sector } from '../lib/types';

export function SectorsList() {
  const navigate = useNavigate();
  const [searchParams, setSearchParams] = useSearchParams();
  const page = parseInt(searchParams.get('page') ?? '1', 10);

  const { data, isLoading } = useSectors({ page: String(page), limit: '50' });

  const columns: ColumnDef<Sector>[] = [
    {
      key: 'name',
      header: 'Sector',
      render: (row) => (
        <span className="text-[#ccd6f6] font-medium">{row.name}</span>
      ),
    },
    {
      key: 'description',
      header: 'Description',
      render: (row) => (
        <span className="text-xs text-[#8892b0] line-clamp-1">
          {row.description ?? '—'}
        </span>
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
        pagination={data?.pagination}
        onPageChange={(p) => {
          setSearchParams((prev) => {
            const next = new URLSearchParams(prev);
            next.set('page', String(p));
            return next;
          });
        }}
        onRowClick={(row) => navigate(`/sectors/${encodeURIComponent(row.name)}`)}
        rowKey={(row) => row.id}
        emptyMessage="No sectors found."
      />
    </div>
  );
}
