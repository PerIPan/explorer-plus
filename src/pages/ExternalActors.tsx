import React from "react";
import { useState, useCallback, useEffect } from 'react';
import { useSearchParams } from 'react-router-dom';
import { useExternalActors } from '../hooks/useApi';
import { useFuseFilter } from '../hooks/useFuseFilter';
import { PageHeader } from '../components/layout/PageHeader';
import { type ColumnDef } from '../components/shared/DataTable';
import { EntityLink } from '../components/shared/EntityLink';
import { Badge } from '../components/shared/Badge';
import { RefsChevron } from '../components/shared/RefsChevron';
import type { ExternalActor } from '../lib/types';

const FUSE_KEYS = ['name', 'description', 'country', 'category'];

/** Detail row for a metadata field. */
function DetailField({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div className="flex items-start gap-3 py-1.5 border-b border-[var(--border-color)] last:border-b-0">
      <span className="text-xs text-[var(--text-secondary)] w-32 shrink-0 pt-0.5">{label}</span>
      <div className="text-xs text-[var(--text-primary)] flex-1">{children}</div>
    </div>
  );
}

/** Full actor detail modal. */
function ActorDetailModal({ actor, onClose }: { actor: ExternalActor; onClose: () => void }) {
  const dialogRef = React.useRef<HTMLDivElement>(null);
  const previousFocusRef = React.useRef<HTMLElement | null>(null);

  useEffect(() => {
    previousFocusRef.current = document.activeElement as HTMLElement | null;
    dialogRef.current?.focus();

    const handler = (e: KeyboardEvent) => { if (e.key === 'Escape') onClose(); };
    window.addEventListener('keydown', handler);
    return () => {
      window.removeEventListener('keydown', handler);
      previousFocusRef.current?.focus();
    };
  }, [onClose]);

  return (
    <div className="fixed inset-0 z-[100] flex items-center justify-center bg-black/60 backdrop-blur-sm" role="presentation" onClick={onClose}>
      <div
        ref={dialogRef}
        role="dialog"
        aria-modal="true"
        aria-labelledby="actor-modal-title"
        tabIndex={-1}
        className="bg-[var(--surface-card)] border border-[var(--border-color)] rounded-xl shadow-2xl w-full max-w-2xl max-h-[80vh] overflow-y-auto mx-4 outline-none"
        onClick={(e) => e.stopPropagation()}
      >
        {/* Header */}
        <div className="flex items-start justify-between px-6 py-4 border-b border-[var(--border-color)] sticky top-0 bg-[var(--surface-card)] z-10">
          <div>
            <h2 id="actor-modal-title" className="text-lg font-semibold text-[var(--text-primary)]">{actor.name}</h2>
            <div className="flex items-center gap-2 mt-1 flex-wrap">
              <Badge label="ThaiCERT / ETDA" variant="neutral" />
              {actor.country && <Badge label={actor.country} variant="blue" />}
              {actor.category && <Badge label={actor.category} variant="purple" />}
              {actor.mitreGroupId && (
                <EntityLink type="group" attackId={actor.mitreGroupId} name={actor.mitreGroupName ?? actor.mitreGroupId} />
              )}
            </div>
          </div>
          <button
            type="button"
            onClick={onClose}
            className="text-[var(--text-secondary)] hover:text-[var(--text-primary)] transition-colors p-1"
            aria-label="Close"
          >
            <svg className="w-5 h-5" fill="none" stroke="currentColor" strokeWidth={2} viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" d="M6 18L18 6M6 6l12 12" />
            </svg>
          </button>
        </div>

        {/* Body */}
        <div className="px-6 py-4 space-y-4">
          {/* Description */}
          {actor.description && (
            <p className="text-sm text-[var(--text-secondary)] leading-relaxed">{actor.description}</p>
          )}

          {/* Metadata fields */}
          <div className="bg-[var(--surface-alt)] rounded-lg p-4">
            {actor.synonyms && actor.synonyms.length > 0 && (
              <DetailField label="Synonyms">
                <div className="flex flex-wrap gap-1">
                  {actor.synonyms.map((s) => (
                    <Badge key={s} label={s} variant="neutral" />
                  ))}
                </div>
              </DetailField>
            )}
            {actor.motivation && (
              <DetailField label="Motivation">
                {actor.motivation}
              </DetailField>
            )}
            {actor.suspectedStateSponsor && (
              <DetailField label="State Sponsor">
                <Badge label={actor.suspectedStateSponsor} variant="orange" />
              </DetailField>
            )}
            {actor.attributionConfidence && (
              <DetailField label="Confidence">
                {actor.attributionConfidence}
              </DetailField>
            )}
            {actor.firstSeen && (
              <DetailField label="First Seen">
                {actor.firstSeen}
              </DetailField>
            )}
            {actor.suspectedVictims && actor.suspectedVictims.length > 0 && (
              <DetailField label="Suspected Victims">
                <div className="flex flex-wrap gap-1">
                  {actor.suspectedVictims.map((v) => (
                    <Badge key={v} label={v} variant="purple" />
                  ))}
                </div>
              </DetailField>
            )}
            {actor.targetCategories && actor.targetCategories.length > 0 && (
              <DetailField label="Target Categories">
                <div className="flex flex-wrap gap-1">
                  {actor.targetCategories.map((c) => (
                    <Badge key={c} label={c} variant="green" />
                  ))}
                </div>
              </DetailField>
            )}
            <DetailField label="Source">
              <Badge label={actor.source} variant="blue" />
            </DetailField>
          </div>

          {/* References chevron */}
          {actor.refs && actor.refs.length > 0 && (
            <RefsChevron refs={actor.refs} />
          )}
        </div>
      </div>
    </div>
  );
}


export function ExternalActors() {
  const [searchParams, setSearchParams] = useSearchParams();
  const [modalActor, setModalActor] = useState<ExternalActor | null>(null);
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

  /** Column header tooltip descriptions. */
  const COLUMN_TOOLTIPS: Record<string, string> = {
    name: 'Primary name used by ThaiCERT / ETDA encyclopedia',
    country: 'ISO country code of suspected origin or attribution',
    category: 'Actor type (APT, criminal, hacktivist, nation-state). Inferred from motivation / state-sponsor metadata when ETDA does not provide one explicitly',
    synonyms: 'Alternative names and designations across threat intel providers (e.g. Mandiant, CrowdStrike, Microsoft)',
    mitreGroupId: 'Linked MITRE ATT&CK group — auto-matched via synonym overlap with ATT&CK aliases',
    source: 'Intelligence source providing the actor record',
  };

  const columns: ColumnDef<ExternalActor>[] = [
    {
      key: 'name',
      header: 'Name',
      sortKey: 'name',
      tooltip: COLUMN_TOOLTIPS.name,
      render: (row) => (
        <button
          type="button"
          onClick={(e) => { e.stopPropagation(); setModalActor(row); }}
          className="font-medium text-[var(--text-primary)] text-sm hover:text-[var(--accent-teal)] transition-colors text-left"
        >
          {row.name}
        </button>
      ),
    },
    {
      key: 'country',
      header: 'Country',
      sortKey: 'country',
      width: '100px',
      tooltip: COLUMN_TOOLTIPS.country,
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
      tooltip: COLUMN_TOOLTIPS.category,
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
      tooltip: COLUMN_TOOLTIPS.synonyms,
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
      tooltip: COLUMN_TOOLTIPS.mitreGroupId,
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
      tooltip: COLUMN_TOOLTIPS.source,
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
                    title={col.tooltip}
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
                  <tr
                    key={row.id}
                    onClick={() => setModalActor(row)}
                    className={`border-b border-[var(--border-color)] cursor-pointer ${rowIndex % 2 === 0 ? 'bg-[var(--surface-card)]' : 'bg-[var(--surface-base)]'} hover:bg-[var(--teal-ghost)] transition-colors duration-100`}
                  >
                    {columns.map((col) => (
                      <td key={col.key} className="px-4 py-3 text-[var(--text-primary)]">
                        {col.render ? col.render(row) : String((row as unknown as Record<string, unknown>)[col.key] ?? '')}
                      </td>
                    ))}
                  </tr>
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

      {/* Actor detail modal */}
      {modalActor && (
        <ActorDetailModal actor={modalActor} onClose={() => setModalActor(null)} />
      )}
    </div>
  );
}
