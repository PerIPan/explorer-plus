import type { ReactNode } from 'react';
import type { Pagination as PaginationType } from '../../lib/types';
import { Pagination } from './Pagination';

export interface ColumnDef<T> {
  key: string;
  header: string;
  /** Render function; receives the row, returns a ReactNode */
  render?: (row: T) => ReactNode;
  /** If provided, column is sortable and this key is used in the sort callback */
  sortKey?: string;
  width?: string;
  align?: 'left' | 'center' | 'right';
}

interface DataTableProps<T> {
  columns: ColumnDef<T>[];
  data: T[];
  loading?: boolean;
  pagination?: PaginationType;
  onPageChange?: (page: number) => void;
  /** Current sort column key */
  sortBy?: string;
  /** Current sort direction */
  sortDir?: 'asc' | 'desc';
  onSort?: (sortKey: string) => void;
  onRowClick?: (row: T) => void;
  /** Key accessor for row identity (used as React key) */
  rowKey?: (row: T) => string | number;
  emptyMessage?: string;
}

function SortIcon({ active, dir }: { active: boolean; dir: 'asc' | 'desc' }) {
  return (
    <span aria-hidden="true" className={`ml-1 inline-block text-xs ${active ? 'text-[#64ffda]' : 'text-[#2a2a4a]'}`}>
      {active && dir === 'asc' ? '\u25B4' : '\u25BE'}
    </span>
  );
}

/**
 * Generic reusable data table with sticky header, sorting, pagination, and row click.
 */
export function DataTable<T extends Record<string, unknown>>({
  columns,
  data,
  loading = false,
  pagination,
  onPageChange,
  sortBy,
  sortDir = 'asc',
  onSort,
  onRowClick,
  rowKey,
  emptyMessage = 'No data found.',
}: DataTableProps<T>) {
  const alignClass = {
    left: 'text-left',
    center: 'text-center',
    right: 'text-right',
  };

  return (
    <div className="flex flex-col">
      <div className="overflow-x-auto rounded-lg border border-[#2a2a4a]">
        <table className="w-full text-sm border-collapse">
          {/* Sticky header */}
          <thead className="sticky top-0 z-10 bg-[#16213e] border-b border-[#2a2a4a]">
            <tr>
              {columns.map((col) => (
                <th
                  key={col.key}
                  scope="col"
                  style={col.width ? { width: col.width } : undefined}
                  className={`
                    px-4 py-3 font-semibold text-xs text-[#8892b0] uppercase tracking-wider
                    ${alignClass[col.align ?? 'left']}
                    ${col.sortKey ? 'cursor-pointer select-none hover:text-[#ccd6f6] transition-colors duration-150' : ''}
                  `}
                  onClick={col.sortKey && onSort ? () => onSort(col.sortKey!) : undefined}
                  aria-sort={
                    col.sortKey && sortBy === col.sortKey
                      ? sortDir === 'asc'
                        ? 'ascending'
                        : 'descending'
                      : col.sortKey
                        ? 'none'
                        : undefined
                  }
                >
                  {col.header}
                  {col.sortKey && (
                    <SortIcon
                      active={sortBy === col.sortKey}
                      dir={sortBy === col.sortKey ? sortDir : 'asc'}
                    />
                  )}
                </th>
              ))}
            </tr>
          </thead>

          <tbody>
            {loading && (
              <tr>
                <td colSpan={columns.length} className="px-4 py-10 text-center text-[#8892b0]">
                  <span className="inline-block w-5 h-5 border-2 border-[#64ffda33] border-t-[#64ffda] rounded-full animate-spin mr-2 align-middle" />
                  Loading...
                </td>
              </tr>
            )}

            {!loading && data.length === 0 && (
              <tr>
                <td colSpan={columns.length} className="px-4 py-10 text-center text-[#8892b0]">
                  {emptyMessage}
                </td>
              </tr>
            )}

            {!loading &&
              data.map((row, rowIndex) => {
                const key = rowKey ? rowKey(row) : rowIndex;
                const isEven = rowIndex % 2 === 0;
                return (
                  <tr
                    key={key}
                    onClick={onRowClick ? () => onRowClick(row) : undefined}
                    className={`
                      border-b border-[#2a2a4a] last:border-0
                      ${isEven ? 'bg-[#16213e]' : 'bg-[#1a1a2e]'}
                      ${onRowClick ? 'cursor-pointer hover:bg-[#64ffda0a]' : ''}
                      transition-colors duration-100
                    `}
                  >
                    {columns.map((col) => (
                      <td
                        key={col.key}
                        className={`
                          px-4 py-3 text-[#ccd6f6]
                          ${alignClass[col.align ?? 'left']}
                        `}
                      >
                        {col.render ? col.render(row) : (row[col.key] as ReactNode)}
                      </td>
                    ))}
                  </tr>
                );
              })}
          </tbody>
        </table>
      </div>

      {/* Pagination */}
      {pagination && onPageChange && (
        <Pagination
          page={pagination.page}
          totalPages={pagination.totalPages}
          total={pagination.total}
          limit={pagination.limit}
          onPageChange={onPageChange}
        />
      )}
    </div>
  );
}
