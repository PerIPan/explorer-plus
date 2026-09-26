'use client';

import { useMemo, useState } from 'react';
import { useQuery } from '@tanstack/react-query';

import { Badge } from '../shared/Badge';
import {
  groupLevelsByZone,
  describeSelection,
  levelDisplay,
  nextOtSelection,
  type PurdueLevel,
  type PlacedAsset,
  type OtSelection,
  type OtSelectionAction,
} from '../../lib/profile-ot.mjs';

/* ────────────────────────────────────────────────────────────────────────────
 * Data
 *
 * `GET /api/v1/frameworks/purdue` already returns the seven levels, all
 * eighteen placed assets with `spansLevels`/`isBoundary`, and the 42-pair flow
 * matrix — so this picker READS that endpoint rather than growing a second
 * source of Purdue truth. The flow rules are ignored here (the picker asks what
 * you have, not what may talk to what); the payload is a few KB and splitting
 * the endpoint to save that would cost a round trip and another Neon wake-up.
 *
 * Fetched only when this component renders, which is only in OT mode. The panel
 * is mounted app-wide, so fetching from the provider would pull the Purdue model
 * into every page for the large majority of visitors who never leave IT.
 * ──────────────────────────────────────────────────────────────────────────── */

const PURDUE_ENDPOINT = '/api/v1/frameworks/purdue';

interface PurdueModel {
  levels: PurdueLevel[];
  assets: PlacedAsset[];
}

async function fetchPurdue(): Promise<PurdueModel> {
  const res = await fetch(PURDUE_ENDPOINT);
  if (!res.ok) throw new Error(`HTTP ${res.status}`);
  const body = (await res.json()) as { data?: PurdueModel };
  if (!body?.data?.levels || !body?.data?.assets) throw new Error('Malformed Purdue response');
  return { levels: body.data.levels, assets: body.data.assets };
}

/** Shared by the panel and the OT briefing, so both show the same tree from one
 *  cache entry rather than two fetches of the same few KB. */
export function usePurdueModel() {
  return useQuery({
    queryKey: ['purdue-model'],
    queryFn: fetchPurdue,
    staleTime: 60 * 60 * 1000,
  });
}

/* ────────────────────────────────────────────────────────────────────────────
 * Presentation
 * ──────────────────────────────────────────────────────────────────────────── */

/** Same zone language as src/views/PurdueModel.tsx: OT is where a breach moves
 *  physical things, the DMZ is the checkpoint, IT is the corporate network. */
const ZONE_CHIP: Record<string, 'orange' | 'yellow' | 'blue'> = {
  ot: 'orange',
  dmz: 'yellow',
  it: 'blue',
};

/**
 * The sentence an empty level gets. Stated rather than implied, and stated as
 * an ATT&CK scoping fact rather than as missing data — the visitor looking for
 * their enterprise network is being told where it went, not that we lost it.
 */
const EMPTY_LEVEL_REASON =
  'No ATT&CK ICS assets are placed at Level 5 — that is the Enterprise domain. Switch to IT estate above for it.';

export interface PurdueAssetPickerProps {
  id: string;
  levels: PurdueLevel[];
  assets: PlacedAsset[];
  /** Explicitly ticked asset ids (A0001-A0018). */
  selectedAssets: string[];
  /** Ticked Purdue level keys. */
  selectedLevels: string[];
  /**
   * ONE callback for the WHOLE selection, not one per half.
   *
   * "Clear" is a single gesture that empties both halves, and two callbacks
   * meant two updates in one tick. On the briefing page, where each half was
   * wired to its own `router.replace` built from a render-time closure, the
   * second navigation carried the pre-clear value of the half the first had
   * just emptied and won — so Clear dropped the ticked assets and put the
   * levels back. Reporting the whole selection is what makes "one action, one
   * navigation" structural: there is no half left for a stale closure to fill
   * in. `nextOtSelection` (src/lib/profile-ot.mjs, fixture-tested) computes it.
   */
  onSelectionChange: (next: OtSelection) => void;
  /** Any interaction at all — the panel uses this to cancel its peek timer. */
  onInteract?: () => void;
  /**
   * The panel's cramped presentation. The tree scrolls inside 11rem there — the
   * same height the MultiSelect listboxes use, so an open picker never swallows
   * the questions underneath it — and gets more room on the briefing page.
   */
  compact?: boolean;
}

/**
 * The OT question: which parts of the plant you defend, as zones first and
 * assets second.
 *
 * An OT defender thinks in zones, so Purdue is the primary axis and individual
 * assets are the refinement. Three things here are requirements rather than
 * styling:
 *
 *   • A level that holds no asset is rendered DISABLED with the reason. `l5`
 *     is measured at zero, and offering it live would be a question whose only
 *     possible answer is the engine's `empty-selection` state — the same defect
 *     class as offering Android to a visitor whose domain is enterprise.
 *
 *   • Assets SPAN levels, so the same asset appears under every level it
 *     spans (A0014 under four of them) and the selection de-duplicates. The
 *     count shown is always the distinct count, and the overlap it dropped is
 *     stated rather than left as an unexplained arithmetic gap.
 *
 *   • Level expansion is SHOWN. Ticking "Site Operations" quietly resolves to
 *     seven assets, four of which that label does not name. The resolved list
 *     is rendered under the picker, per level, and the level's own row expands
 *     to the individual assets on request. Silent expansion is as dishonest as
 *     a silent default.
 */
export function PurdueAssetPicker({
  id,
  levels,
  assets,
  selectedAssets,
  selectedLevels,
  onSelectionChange,
  onInteract,
  compact = false,
}: PurdueAssetPickerProps) {
  // Which level rows have their individual assets shown. Purely presentational
  // — expanding a row selects nothing.
  const [openLevels, setOpenLevels] = useState<string[]>([]);

  const zones = useMemo(() => groupLevelsByZone(levels, assets), [levels, assets]);
  const summary = useMemo(
    () => describeSelection(assets, selectedAssets, selectedLevels, levels),
    [assets, selectedAssets, selectedLevels, levels],
  );

  const levelSet = useMemo(() => new Set(selectedLevels), [selectedLevels]);
  const assetSet = useMemo(() => new Set(selectedAssets), [selectedAssets]);
  // Reachable through a ticked LEVEL rather than ticked by hand. Those rows
  // render as checked-and-locked: unticking one would be a lie, since the level
  // above it would put the asset straight back.
  const viaLevelSet = useMemo(
    () => new Set(summary.viaLevels.flatMap((v) => v.assetIds)),
    [summary],
  );

  /** Every gesture, through one place: the next WHOLE selection, reported once.
   *  See `onSelectionChange` above for why this is not two callbacks. */
  function emit(action: OtSelectionAction) {
    onInteract?.();
    onSelectionChange(
      nextOtSelection({ assets: selectedAssets, levels: selectedLevels }, action),
    );
  }

  function toggleLevel(levelKey: string) {
    emit({ type: 'toggle-level', id: levelKey });
  }

  function toggleAsset(attackId: string) {
    emit({ type: 'toggle-asset', id: attackId });
  }

  function toggleOpen(levelKey: string) {
    onInteract?.();
    setOpenLevels((prev) =>
      prev.includes(levelKey) ? prev.filter((l) => l !== levelKey) : [...prev, levelKey],
    );
  }

  const nSelected = summary.effectiveIds.length;
  const statusId = `${id}-status`;

  return (
    <div>
      <div className="flex items-baseline justify-between gap-2 mb-1">
        <span className="block text-xs font-medium text-[var(--text-secondary)]">
          What you defend <span className="text-[var(--text-secondary)]">(required)</span>
        </span>
        {(selectedLevels.length > 0 || selectedAssets.length > 0) && (
          <button
            type="button"
            onClick={() => emit({ type: 'clear' })}
            className="shrink-0 text-[11px] text-[var(--text-secondary)] hover:text-[var(--text-primary)] underline underline-offset-2 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[var(--accent-teal)] rounded"
          >
            Clear
          </button>
        )}
      </div>

      <div
        className={`rounded-md border border-[var(--border-color)] bg-[var(--surface-card)] overflow-y-auto ${
          compact ? 'max-h-[11rem]' : 'max-h-[22rem]'
        }`}
      >
        {zones.map((zone) => (
          <div key={zone.zone}>
            <p
              className="sticky top-0 z-10 flex items-center gap-2 bg-[var(--surface-alt)] px-2 py-1 text-[10px] font-semibold uppercase tracking-wider text-[var(--text-secondary)] border-b border-[var(--border-faint)]"
              title={zone.blurb}
            >
              <Badge label={zone.zone.toUpperCase()} variant={ZONE_CHIP[zone.zone] ?? 'neutral'} />
              {zone.label}
            </p>

            {zone.levels.map((level) => {
              const empty = level.assets.length === 0;
              const isOpen = openLevels.includes(level.levelKey);
              const checked = levelSet.has(level.levelKey);
              const boundaryHere = level.assets.filter((a) => a.isBoundary).length;
              return (
                <div key={level.levelKey} className="border-b border-[var(--border-faint)] last:border-b-0">
                  <div className="flex items-center gap-1 px-2">
                    {/* The level itself. `disabled` rather than merely styled:
                        an empty level must not be reachable by keyboard either,
                        because there is no answer it could contribute. */}
                    <label
                      className={`flex flex-1 min-w-0 items-center gap-2 min-h-[44px] py-1 text-sm ${
                        empty
                          ? 'text-[var(--text-secondary)] opacity-70 cursor-not-allowed'
                          : 'text-[var(--text-primary)] cursor-pointer'
                      }`}
                      title={empty ? EMPTY_LEVEL_REASON : level.description}
                    >
                      <input
                        type="checkbox"
                        disabled={empty}
                        checked={checked}
                        onChange={() => toggleLevel(level.levelKey)}
                        aria-describedby={empty ? `${id}-${level.levelKey}-empty` : undefined}
                        className="shrink-0 h-4 w-4 accent-[var(--accent-teal)] disabled:cursor-not-allowed"
                      />
                      <span className="min-w-0 truncate">
                        <span className="font-semibold tabular-nums">{levelDisplay(level.levelKey)}</span>{' '}
                        {level.label}
                      </span>
                      <span className="shrink-0 ml-auto text-[11px] tabular-nums text-[var(--text-secondary)]">
                        {empty ? 'none' : `${level.assets.length}`}
                        {boundaryHere > 0 && (
                          <span
                            className="ml-1 text-[var(--accent-yellow)]"
                            title={`${boundaryHere} of these are boundary assets — where IT and OT cross.`}
                          >
                            ⇄{boundaryHere}
                          </span>
                        )}
                      </span>
                    </label>

                    {/* Expansion, as a control rather than an assumption: the
                        visitor decides when to see the assets a level resolves
                        to, and the row says how many there are before they do. */}
                    {!empty && (
                      <button
                        type="button"
                        onClick={() => toggleOpen(level.levelKey)}
                        aria-expanded={isOpen}
                        aria-controls={`${id}-${level.levelKey}-assets`}
                        aria-label={
                          isOpen
                            ? `Hide the ${level.assets.length} assets at ${level.label}`
                            : `Show the ${level.assets.length} assets at ${level.label}`
                        }
                        className="shrink-0 flex items-center justify-center min-h-[44px] min-w-[44px] rounded-md text-[var(--text-secondary)] hover:text-[var(--text-primary)] focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[var(--accent-teal)] transition-colors"
                      >
                        <svg
                          aria-hidden="true"
                          viewBox="0 0 24 24"
                          fill="none"
                          stroke="currentColor"
                          strokeWidth={2}
                          className={`w-3.5 h-3.5 transition-transform duration-150 motion-reduce:transition-none ${
                            isOpen ? 'rotate-180' : ''
                          }`}
                        >
                          <path strokeLinecap="round" strokeLinejoin="round" d="M19 9l-7 7-7-7" />
                        </svg>
                      </button>
                    )}
                  </div>

                  {empty && (
                    <p
                      id={`${id}-${level.levelKey}-empty`}
                      className="px-2 pb-2 -mt-1 text-[11px] leading-snug text-[var(--text-secondary)]"
                    >
                      {EMPTY_LEVEL_REASON}
                    </p>
                  )}

                  {isOpen && !empty && (
                    <ul id={`${id}-${level.levelKey}-assets`} className="pb-1">
                      {level.assets.map((asset) => {
                        const viaLevel = viaLevelSet.has(asset.attackId);
                        const ticked = assetSet.has(asset.attackId) || viaLevel;
                        const spansMore = asset.spansLevels.length > 1;
                        return (
                          <li key={asset.attackId}>
                            <label
                              className={`flex items-center gap-2 min-h-[44px] pl-7 pr-2 text-sm ${
                                viaLevel ? 'cursor-not-allowed' : 'cursor-pointer'
                              }`}
                              title={
                                viaLevel
                                  ? `Included because you selected a level it sits at. Untick that level to drop it.`
                                  : spansMore
                                    ? `Also present at ${asset.spansLevels.map(levelDisplay).join(', ')}`
                                    : undefined
                              }
                            >
                              <input
                                type="checkbox"
                                checked={ticked}
                                // Ticked BY A LEVEL. Leaving it clickable would
                                // let the visitor untick something the level
                                // above puts straight back — a control that
                                // does not do what it appears to.
                                disabled={viaLevel}
                                onChange={() => toggleAsset(asset.attackId)}
                                className="shrink-0 h-4 w-4 accent-[var(--accent-teal)] disabled:cursor-not-allowed"
                              />
                              <span className="min-w-0 flex-1 truncate text-[var(--text-primary)]">
                                <span className="font-mono text-[11px] text-[var(--text-secondary)]">
                                  {asset.attackId}
                                </span>{' '}
                                {asset.name}
                              </span>
                              {asset.isBoundary && (
                                <Badge
                                  label="boundary"
                                  variant="yellow"
                                  className="shrink-0"
                                />
                              )}
                              {spansMore && (
                                <span
                                  className="shrink-0 text-[10px] tabular-nums text-[var(--text-secondary)]"
                                  aria-label={`Spans ${asset.spansLevels.length} levels`}
                                >
                                  ×{asset.spansLevels.length}
                                </span>
                              )}
                            </label>
                          </li>
                        );
                      })}
                    </ul>
                  )}
                </div>
              );
            })}
          </div>
        ))}
      </div>

      {/* ── What the selection actually resolved to ─────────────────────────
          Not a nicety. Ticking one level is one click that selects up to eight
          assets, half of which its label does not name; showing the count and
          then the assets themselves is the difference between a choice and a
          surprise. `aria-live` so a screen-reader visitor hears the expansion
          at the moment it happens rather than discovering it on the briefing. */}
      <div id={statusId} aria-live="polite" className="mt-2 text-[11px] leading-relaxed">
        {nSelected === 0 ? (
          <p className="text-[var(--accent-yellow)]">
            {selectedLevels.length > 0
              ? 'The levels you picked hold no ATT&CK ICS asset, so there is nothing to rank yet.'
              : 'Pick at least one level or asset — nothing is selected for you.'}
          </p>
        ) : (
          <>
            <p className="text-[var(--text-primary)]">
              <span className="font-semibold tabular-nums">{nSelected}</span>{' '}
              {nSelected === 1 ? 'asset' : 'assets'} will be ranked
              {summary.boundaryCount > 0 && (
                <>
                  , <span className="tabular-nums">{summary.boundaryCount}</span> of them{' '}
                  <span className="text-[var(--accent-yellow)]">boundary</span>{' '}
                  {summary.boundaryCount === 1 ? 'asset' : 'assets'}
                </>
              )}
              .
              {summary.overlapDropped > 0 && (
                <>
                  {' '}
                  Your levels list{' '}
                  <span className="tabular-nums">{summary.memberships}</span> between them;{' '}
                  <span className="tabular-nums">{summary.overlapDropped}</span> are the same asset
                  at more than one level, so {nSelected} distinct assets are ranked.
                </>
              )}
            </p>

            {summary.viaLevels
              .filter((v) => v.assetIds.length > 0)
              .map((v) => (
                <p key={v.levelKey} className="mt-1 text-[var(--text-secondary)]">
                  <span className="font-semibold text-[var(--text-primary)]">
                    {levelDisplay(v.levelKey)} {v.label}
                  </span>{' '}
                  resolves to <span className="tabular-nums">{v.assetIds.length}</span>:{' '}
                  <span className="font-mono text-[10px]">{v.assetIds.join(' ')}</span>
                </p>
              ))}

            <div className="mt-1.5 flex flex-wrap gap-1">
              {summary.effective.map((a) => (
                <Badge
                  key={a.attackId}
                  label={`${a.attackId} ${a.name}`}
                  variant={a.isBoundary ? 'yellow' : 'teal'}
                  className="max-w-full truncate"
                />
              ))}
            </div>
          </>
        )}
      </div>
    </div>
  );
}

/**
 * The picker plus its own loading and failure states.
 *
 * The failure state matters more than it looks: with no Purdue model there is
 * no way to choose, and the only honest thing to do is say so and leave Apply
 * disabled. Substituting a hardcoded asset list would be a silent default over
 * data we could not read.
 */
export function PurdueAssetPickerLoader(
  props: Omit<PurdueAssetPickerProps, 'levels' | 'assets'>,
) {
  const { data, isPending, error, refetch } = usePurdueModel();

  if (isPending) {
    return (
      <p className="text-xs text-[var(--text-secondary)]" aria-live="polite">
        Loading the Purdue model…
      </p>
    );
  }

  if (error || !data) {
    return (
      <div className="rounded-md border border-[var(--orange-dim)] bg-[var(--orange-faint)] px-3 py-2">
        <p className="text-xs text-[var(--text-primary)]">
          The Purdue model could not be loaded, so there is nothing to choose from. Nothing has been
          selected on your behalf.
        </p>
        <button
          type="button"
          onClick={() => void refetch()}
          className="mt-1 min-h-[44px] text-xs font-semibold text-[var(--accent-teal)] underline underline-offset-2 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[var(--accent-teal)] rounded"
        >
          Try again
        </button>
      </div>
    );
  }

  return <PurdueAssetPicker {...props} levels={data.levels} assets={data.assets} />;
}
