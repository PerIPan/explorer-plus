import React from "react";
import { useState, useCallback } from 'react';
import { useSearchParams } from 'react-router-dom';
import { useExternalActors } from '../hooks/useApi';
import { useFuseFilter } from '../hooks/useFuseFilter';
import { PageHeader } from '../components/layout/PageHeader';
import { DataTable, type ColumnDef } from '../components/shared/DataTable';
import { EntityLink } from '../components/shared/EntityLink';
import type { ExternalActor } from '../lib/types';

const FUSE_KEYS = ['name', 'description', 'country', 'category'];

/** Expandable row showing description and reference links. */
function ExpandedRow({ actor }: { actor: ExternalActor }) {
  return (
    <tr className="bg-[var(--surface-alt)] border-b border-[var(--border-color)]">
      <td colSpan={6} className="px-6 py-4">
        <div className="space-y-3">
          {actor.description && (
            <p className="text-sm text-[var(--text-secondary)] leading-relaxed max-w-4xl">
              {actor.description}
            </p>
          )}
          {actor.refs && actor.refs.length > 0 && (
            <div>
              <span className="text-[10px] font-semibold text-[var(--text-secondary)] uppercase tracking-wider mr-2">
                References
              </span>
              <div className="mt-1 flex flex-wrap gap-2">
                {actor.refs.map((ref, i) => (
                  <a
                    key={i}
                    href={ref}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="text-xs text-[var(--accent-teal)] hover:underline break-all"
                  >
                    {ref}
                  </a>
                ))}
              </div>
            </div>
          )}
          {!actor.description && (!actor.refs || actor.refs.length === 0) && (
            <span className="text-xs text-[var(--text-secondary)]">No additional details available.</span>
          )}
        </div>
      </td>
    </tr>
  );
}

export function ExternalActors() {
  const [searchParams, setSearchParams] = useSearchParams();
  const [expandedId, setExpandedId] = useState<string | null>(null);
  const [search, setSearch] = useState('');

  const country = searchParams.get('country') ?? '';
  const category = searchParams.get('category') ?? '';
  const sortBy = searchParams.get('sort') ?? 'name';
  const sortDir = (searchParams.get('order') ?? 'asc') as 'asc' | 'desc';

  const params: Record<string, string> = { limit: '5000' };
  if (country) params.country = country;
  if (category) params.category = category;
  if (sortBy) params.sort = sortBy;
  if (sortDir) params.order = sortDir;

  const { data, isLoading } = useExternalActors(params);

  const filteredData = useFuseFilter(data?.data ?? [], FUSE_KEYS, search);

  const setParam = useCallback(
    (key: string, value: string) => {
      setSearchParams((prev) => {
        const next = new URLSearchParams(prev);
        if (value) next.set(key, value); else next.delete(key);
        return next;
      });
    },
    [setSearchParams],
  );

  function handleSort(key: string) {
    setSearchParams((prev) => {
      const next = new URLSearchParams(prev);
      const curKey = prev.get('sort') ?? 'name';
      const curDir = prev.get('order') ?? 'asc';
      next.set('sort', key);
      next.set('order', curKey === key && curDir === 'asc' ? 'desc' : 'asc');
      return next;
    });
  }

  function toggleExpand(id: string) {
    setExpandedId((prev) => (prev === id ? null : id));
  }

  // Unique country options from all loaded data for the dropdown
  const countryOptions = Array.from(
    new Set((data?.data ?? []).map((a) => a.country).filter(Boolean) as string[]),
  ).sort();

  const categoryOptions = [
    'APT',
    'criminal',
    'hacktivist',
    'nation-state',
    'insider',
    'unknown',
  ];

  const columns: ColumnDef<ExternalActor>[] = [
    {
      key: 'expand',
      header: '',
      width: '40px',
      render: (row) => (
        <button
          type="button"
          onClick={(e) => { e.stopPropagation(); toggleExpand(row.id); }}
          aria-label={expandedId === row.id ? 'Collapse row' : 'Expand row'}
          className="text-[var(--text-secondary)] hover:text-[var(--accent-teal)] transition-colors"
        >
          <svg
            className={`w-3.5 h-3.5 transition-transform duration-150 ${expandedId === row.id ? 'rotate-90' : ''}`}
            fill="none"
            stroke="currentColor"
            strokeWidth={2}
            viewBox="0 0 24 24"
            aria-hidden="true"
          >
            <path strokeLinecap="round" strokeLinejoin="round" d="M9 5l7 7-7 7" />
          </svg>
        </button>
      ),
    },
    {
      key: 'name',
      header: 'Name',
      sortKey: 'name',
      render: (row) => (
        <span className="font-medium text-[var(--text-primary)] text-sm">{row.name}</span>
      ),
    },
    {
      key: 'country',
      header: 'Country',
      sortKey: 'country',
      width: '100px',
      render: (row) =>
        row.country ? (
          <span className="font-mono text-xs text-[var(--text-secondary)] uppercase">{row.country}</span>
        ) : (
          <span className="text-[var(--text-secondary)] text-xs">—</span>
        ),
    },
    {
      key: 'category',
      header: 'Category',
      sortKey: 'category',
      width: '130px',
      render: (row) =>
        row.category ? (
          <span className="inline-flex items-center px-2 py-0.5 rounded text-[11px] font-medium bg-[var(--neutral-faint)] text-[var(--accent-neutral)] border border-[var(--neutral-dim)]">
            {row.category}
          </span>
        ) : (
          <span className="text-[var(--text-secondary)] text-xs">—</span>
        ),
    },
    {
      key: 'synonyms',
      header: 'Synonyms',
      render: (row) =>
        row.synonyms && row.synonyms.length > 0 ? (
          <span className="text-xs text-[var(--text-secondary)]">
            {row.synonyms.slice(0, 4).join(', ')}
            {row.synonyms.length > 4 ? ` +${row.synonyms.length - 4}` : ''}
          </span>
        ) : (
          <span className="text-[var(--text-secondary)] text-xs">—</span>
        ),
    },
    {
      key: 'mitreGroupId',
      header: 'ATT&CK Group',
      width: '160px',
      render: (row) =>
        row.mitreGroupId ? (
          <EntityLink type="group" attackId={row.mitreGroupId} name={row.mitreGroupName ?? row.mitreGroupId} />
        ) : (
          <span className="text-[var(--text-secondary)] text-xs">—</span>
        ),
    },
    {
      key: 'source',
      header: 'Source',
      sortKey: 'source',
      width: '100px',
      render: (row) => (
        <span className="inline-flex items-center px-2 py-0.5 rounded text-[11px] font-medium bg-[var(--blue-faint)] text-[var(--accent-blue)] border border-[var(--blue-dim)]">
          {row.source}
        </span>
      ),
    },
  ];

  return (
    <div className="space-y-4">
      <PageHeader
        title="Threat Actors (ETDA)"
        subtitle="514+ threat actors from ThaiCERT / ETDA encyclopedia — extended beyond core ATT&CK groups"
      />

      <div className="flex flex-wrap gap-3">
        <input
          type="search"
          placeholder="Search actors..."
          value={search}
          onChange={(e) => setSearch(e.target.value)}
          className="min-w-[200px] px-3 py-1.5 rounded-md text-sm bg-[var(--surface-card)] border border-[var(--border-color)] text-[var(--text-primary)] placeholder-[var(--text-secondary)] focus:outline-none focus:border-[var(--accent-teal)]"
        />
        <select
          value={country}
          onChange={(e) => setParam('country', e.target.value)}
          className="min-w-[140px] px-3 py-1.5 rounded-md text-sm bg-[var(--surface-card)] border border-[var(--border-color)] text-[var(--text-primary)] focus:outline-none focus:border-[var(--accent-teal)]"
        >
          <option value="">All Countries</option>
          {countryOptions.map((c) => (
            <option key={c} value={c}>{c}</option>
          ))}
        </select>
        <select
          value={category}
          onChange={(e) => setParam('category', e.target.value)}
          className="min-w-[140px] px-3 py-1.5 rounded-md text-sm bg-[var(--surface-card)] border border-[var(--border-color)] text-[var(--text-primary)] focus:outline-none focus:border-[var(--accent-teal)]"
        >
          <option value="">All Categories</option>
          {categoryOptions.map((c) => (
            <option key={c} value={c}>{c}</option>
          ))}
        </select>
      </div>

      {/* Custom table render to support expandable rows */}
      <div className="flex flex-col">
        <div className="overflow-x-auto rounded-lg border border-[var(--border-color)]">
          <table className="w-full text-sm border-collapse">
            <thead className="sticky top-0 z-10 bg-[var(--surface-card)] border-b border-[var(--border-color)]">
              <tr>
                {columns.map((col) => (
                  <th
                    key={col.key}
                    scope="col"
                    style={col.width ? { width: col.width } : undefined}
                    className={`px-4 py-3 font-semibold text-xs text-[var(--text-secondary)] uppercase tracking-wider text-left ${col.sortKey ? 'cursor-pointer select-none hover:text-[var(--text-primary)] transition-colors duration-150' : ''}`}
                    onClick={col.sortKey ? () => handleSort(col.sortKey!) : undefined}
                  >
                    {col.header}
                    {col.sortKey && sortBy === col.sortKey && (
                      <span className="ml-1 text-[var(--accent-teal)]">
                        {sortDir === 'asc' ? '\u25B4' : '\u25BE'}
                      </span>
                    )}
                  </th>
                ))}
              </tr>
            </thead>
            <tbody>
              {isLoading &&
                Array.from({ length: 8 }).map((_, i) => (
                  <tr key={i} className={`border-b border-[var(--border-color)] ${i % 2 === 0 ? 'bg-[var(--surface-card)]' : 'bg-[var(--surface-base)]'}`}>
                    {columns.map((col) => (
                      <td key={col.key} className="px-4 py-3">
                        <div className="h-4 rounded bg-[var(--border-color)] animate-pulse w-3/4" />
                      </td>
                    ))}
                  </tr>
                ))}

              {!isLoading && filteredData.length === 0 && (
                <tr>
                  <td colSpan={columns.length} className="px-4 py-16 text-center text-[var(--text-secondary)] text-sm">
                    No actors found.
                  </td>
                </tr>
              )}

              {!isLoading &&
                filteredData.map((row, rowIndex) => (
                  <React.Fragment key={row.id}>
                    <tr
                      key={row.id}
                      className={`border-b border-[var(--border-color)] ${rowIndex % 2 === 0 ? 'bg-[var(--surface-card)]' : 'bg-[var(--surface-base)]'} hover:bg-[var(--teal-ghost)] transition-colors duration-100`}
                    >
                      {columns.map((col) => (
                        <td key={col.key} className="px-4 py-3 text-[var(--text-primary)]">
                          {col.render ? col.render(row) : String((row as unknown as Record<string, unknown>)[col.key] ?? '')}
                        </td>
                      ))}
                    </tr>
                    {expandedId === row.id && <ExpandedRow key={`${row.id}-exp`} actor={row} />}
                  </React.Fragment>
                ))}
            </tbody>
          </table>
        </div>

        {!search && data?.pagination && (
          <div className="mt-4 flex items-center justify-end text-xs text-[var(--text-secondary)]">
            <span>{data.pagination.total} actors total</span>
          </div>
        )}
        {search && (
          <div className="mt-4 flex items-center justify-end text-xs text-[var(--text-secondary)]">
            <span>{filteredData.length} actors matching &quot;{search}&quot;</span>
          </div>
        )}
      </div>
    </div>
  );
}
