'use client';

import { useMemo, useState } from 'react';
import Link from 'next/link';
import { useMatrix } from '../../hooks/useApi';
import { getParentId } from '../../lib/getParentId';
import { MatrixGrid } from '../matrix/MatrixGrid';
import { DiamondLoader } from '../shared/FoldingDiamond';

/**
 * The briefing, placed on the ATT&CK matrix.
 *
 * The bands answer "what should I care about"; they do not answer "where in an
 * intrusion does this happen", and a ranked list cannot — a reader has to hold
 * twelve technique ids in their head and know the kill chain by heart. The
 * matrix answers it at a glance: the same twelve, lit in their tactic columns,
 * everything else dimmed.
 *
 * Scoped by the SAME sector and domain the briefing was built from, so the
 * background this lights against is the visitor's, not ATT&CK's whole corpus.
 */
export function ProfileMatrix({
  sector,
  sectorName,
  domain,
  techniqueIds,
}: {
  sector: string | null;
  sectorName?: string | null;
  domain: string | null;
  techniqueIds: string[];
}) {
  const [open, setOpen] = useState(true);

  /**
   * Sector AND domain — the same scoping the briefing was built from.
   *
   * This was domain-only until the matrix's sector filter was fixed. That
   * filter matched group usage against the parent technique alone, so a group
   * that only ever used T1003.001 did not count towards T1003 and the parent
   * was dropped: on energy it hid 47 parents its own groups demonstrably use,
   * and with them 8 of the 12 techniques this panel exists to place. With
   * sub-technique usage counted, all 12 survive on every sector tried
   * (energy, financial, healthcare, government, defense, technology,
   * manufacturing), so the tighter and more relevant lens is safe to use.
   */
  const params = useMemo(() => {
    const p: Record<string, string> = {};
    if (sector) p.sector = sector;
    // 'all' is the absence of a domain filter for this endpoint, not a value.
    if (domain && domain !== 'all') p.domain = domain;
    return p;
  }, [sector, domain]);

  const { data: matrixResponse, isLoading, error } = useMatrix(params);
  const data = matrixResponse?.data;

  /**
   * Both the id and its parent.
   *
   * MatrixGrid already lights a sub-technique cell when its PARENT is
   * highlighted, but not the reverse — and the bands are overwhelmingly
   * sub-techniques (11 of 12 on a typical briefing), while the grid's cells are
   * parent techniques. Passing ids alone would leave almost the whole matrix
   * dark and read as "your techniques are not in ATT&CK".
   */
  const highlightIds = useMemo(() => {
    const set = new Set<string>();
    for (const id of techniqueIds) {
      set.add(id);
      set.add(getParentId(id));
    }
    return set;
  }, [techniqueIds]);

  if (techniqueIds.length === 0) return null;

  return (
    <section className="mt-6" aria-labelledby="profile-matrix-heading">
      <div className="mb-2 flex flex-wrap items-baseline gap-x-3 gap-y-1">
        <h2
          id="profile-matrix-heading"
          className="text-[11px] font-bold uppercase tracking-wider text-[var(--accent-teal)]"
        >
          Where this sits on the matrix
        </h2>
        <button
          type="button"
          onClick={() => setOpen((v) => !v)}
          aria-expanded={open}
          aria-controls="profile-matrix-body"
          className="text-[11px] font-medium text-[var(--text-secondary)] transition-colors hover:text-[var(--accent-teal)]"
        >
          {open ? 'hide' : 'show'}
        </button>
        <Link
          href={`/matrix${params.sector || params.domain ? `?${new URLSearchParams(params).toString()}` : ''}`}
          className="ml-auto text-[11px] font-semibold text-[var(--accent-teal)] hover:underline"
        >
          Open the full matrix →
        </Link>
      </div>

      <p className="mb-3 text-xs leading-relaxed text-[var(--text-secondary)]">
        The {techniqueIds.length} techniques ranked above, lit in the tactic columns where they are
        used{sectorName ? <> — against the {sectorName} matrix, not the whole corpus</> : null}.
        Everything else is dimmed. A column with nothing lit is a phase this briefing says nothing
        about, which is worth knowing as much as the ones that glow.
      </p>

      {open && (
        <div id="profile-matrix-body">
          {isLoading && <DiamondLoader text="Loading matrix…" />}
          {!isLoading && error && (
            <p className="rounded-md border border-[var(--orange-dim)] bg-[var(--orange-faint)] px-3 py-2 text-xs text-[var(--accent-orange)]">
              The matrix did not load. The briefing above is unaffected.
            </p>
          )}
          {!isLoading && !error && data && (
            <div className="overflow-x-auto">
              <MatrixGrid data={data} highlightIds={highlightIds} />
            </div>
          )}
        </div>
      )}
    </section>
  );
}
