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
    <span aria-hidden="true" className={`ml-1 inline-block text-xs ${active ? 'text-[var(--accent-teal)]' : 'text-[var(--text-secondary)]'}`}>
      {active && dir === 'asc' ? '\u25B4' : '\u25BE'}
    </span>
  );
}

/**
 * Generic reusable data table with sticky header, sorting, pagination, and row click.
 */
export function DataTable<T extends Record<string, any>>({
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
      <div className="overflow-x-auto rounded-lg border border-[var(--border-color)]">
        <table className="w-full text-sm border-collapse">
          {/* Sticky header */}
          <thead className="sticky top-0 z-10 bg-[var(--surface-card)] border-b border-[var(--border-color)]">
            <tr>
              {columns.map((col) => (
                <th
                  key={col.key}
                  scope="col"
                  style={col.width ? { width: col.width } : undefined}
                  className={`
                    px-4 py-3 font-semibold text-xs text-[var(--text-secondary)] uppercase tracking-wider
                    ${alignClass[col.align ?? 'left']}
                    ${col.sortKey ? 'cursor-pointer select-none hover:text-[var(--text-primary)] transition-colors duration-150' : ''}
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
            {loading &&
              Array.from({ length: 8 }).map((_, rowIndex) => (
                <tr
                  key={rowIndex}
                  className={`border-b border-[var(--border-color)] last:border-0 ${rowIndex % 2 === 0 ? 'bg-[var(--surface-card)]' : 'bg-[var(--surface-base)]'}`}
                >
                  {columns.map((col, colIndex) => {
                    const widths = ['w-3/4', 'w-1/2', 'w-1/3'];
                    const w = widths[(colIndex + rowIndex) % widths.length];
                    return (
                      <td key={col.key} className="px-4 py-3">
                        <div className={`h-4 rounded bg-[var(--border-color)] animate-pulse ${w}`} />
                      </td>
                    );
                  })}
                </tr>
              ))
            }

            {!loading && data.length === 0 && (
              <tr>
                <td colSpan={columns.length} className="px-4 py-16 text-center text-[var(--text-secondary)]">
                  <div className="flex flex-col items-center gap-3">
                    <svg
                      className="w-10 h-10 text-[var(--border-color)]"
                      fill="none"
                      stroke="currentColor"
                      strokeWidth={1.5}
                      viewBox="0 0 24 24"
                      aria-hidden="true"
                    >
                      <path strokeLinecap="round" strokeLinejoin="round" d="M20.25 6.375c0 2.278-3.694 4.125-8.25 4.125S3.75 8.653 3.75 6.375m16.5 0c0-2.278-3.694-4.125-8.25-4.125S3.75 4.097 3.75 6.375m16.5 0v11.25c0 2.278-3.694 4.125-8.25 4.125s-8.25-1.847-8.25-4.125V6.375m16.5 5.625c0 2.278-3.694 4.125-8.25 4.125s-8.25-1.847-8.25-4.125" />
                    </svg>
                    <span className="text-sm">{emptyMessage}</span>
                  </div>
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
                    tabIndex={onRowClick ? 0 : undefined}
                    onKeyDown={onRowClick ? (e) => { if (e.key === 'Enter') onRowClick(row); } : undefined}
                    className={`
                      border-b border-[var(--border-color)] last:border-0
                      ${isEven ? 'bg-[var(--surface-card)]' : 'bg-[var(--surface-base)]'}
                      ${onRowClick ? 'cursor-pointer hover:bg-[var(--teal-faint)] focus:outline-none focus:bg-[var(--teal-faint)]' : ''}
                      transition-colors duration-100
                    `}
                  >
                    {columns.map((col) => (
                      <td
                        key={col.key}
                        className={`
                          px-4 py-3 text-[var(--text-primary)]
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
