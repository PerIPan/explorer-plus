'use client';

import { useCallback, useEffect, useMemo, useRef, useState, type ReactNode } from 'react';
import Link from 'next/link';
import { useRouter, useSearchParams } from 'next/navigation';
import { useQuery } from '@tanstack/react-query';

import { PageHeader } from '../components/layout/PageHeader';
import { Card, Notice, Metric, num } from '../components/profile/BriefingPrimitives';
import { EntityLink } from '../components/shared/EntityLink';
import { DiamondLoader } from '../components/shared/FoldingDiamond';
import { ErrorState } from '../components/shared/ErrorState';
import { MultiSelect, type MultiSelectOption } from '../components/profile/MultiSelect';
// Value imports come from the zod-free shared module, NOT from ProfilePanel:
// that module also builds a picker from `SCF_FRAMEWORK_REGISTRY` (32 entries,
// not the 254 this comment used to claim) and importing it here for two arrays
// pulled the whole registry into this page's bundle. `ProfileVariant` is a
// type-only import below, which is erased at compile time and costs nothing.
import { SECTOR_OPTIONS, PLATFORMS, platformsForDomain } from '../lib/profile-options';
import { buildProfileUrl } from '../lib/profile-url.mjs';
import {
  resolveProfileDomain,
  parsePlatforms,
  buildProfileApiQuery,
  ALL_DOMAINS,
} from '../lib/profile-query.mjs';
import { useSector, ALL_SECTORS_PARAM } from '../contexts/SectorContext';
import { DEFAULT_DOMAIN, useDomain } from '../contexts/DomainContext';
import { ProfileMatrix } from '../components/profile/ProfileMatrix';

/* ────────────────────────────────────────────────────────────────────────────
 * Wire types
 *
 * Mirrors what app/api/v1/profile/route.ts actually returns. Band items are
 * `PoolItem` there: `platforms` is stripped by `toPoolItem` before the pool
 * becomes response items, so there is deliberately no `platforms` field here.
 * ──────────────────────────────────────────────────────────────────────────── */

interface BandItem {
  attackId: string;
  name: string;
  lift: number;
  groupCount: number;
  iocs: number;
  reports: number;
  cveCount: number;
  kevCount: number;
  maxEpss: number | null;
}

interface ProfileGroup {
  attackId: string;
  name: string;
  aliases: string[] | null;
}

/**
 * One row of the recent-evidence section: a technique distinctive to this
 * sector that also carries a vulnerability published inside the window.
 * `kevCount` can be 0, and that is information rather than a gap.
 */
interface EvidenceRow {
  attackId: string;
  name: string;
  lift: number;
  cveCount: number;
  kevCount: number;
}

interface ProfileResponse {
  profile: {
    sector: string | null;
    sectorName?: string | null;
    platforms: string[] | null;
    domain: string | null;
    sort: SortKey;
  };
  groups: ProfileGroup[];
  bandA: BandItem[];
  bandB: BandItem[];
  /** The bottom section's rows. Optional on the wire so an older deployment of
   *  the assembler degrades to the section simply not rendering. */
  evidence?: EvidenceRow[];
  meta: {
    poolSize: number;
    groupCount: number;
    degenerate: boolean;
    bandBShort: boolean;
    platformDropped: boolean;
    /** Present ONLY on the valid, non-error "no sector chosen" response. */
    reason?: string;
    /**
     * The chosen sort key's evidence column is entirely ZERO across the pool,
     * so Band A is not a ranking — it is a stable-sort slice of an all-zero
     * column. True for every non-enterprise domain on every evidence sort
     * (measured: no live ICS, mobile or ATLAS technique carries KEV, CVE, EPSS,
     * report or IOC evidence), which is exactly the case that used to render
     * "Most KEV evidence" over six zeroes. Optional on the wire so an older
     * deployment of the route degrades to the previous rendering rather than
     * crashing on a missing field.
     */
    evidenceUnavailable?: boolean;
    /** An explicit `domain=all` request: the ranked pool spans domains. The
     *  server's confirmation of what this page already infers from the URL. */
    mixedDomain?: boolean;
    /** The platform selection matched NO technique, so the empty pool below is
     *  the platform answer's doing and not a statement about the sector. */
    platformPoolEmpty?: boolean;
    /**
     * How many techniques Band A was chosen from. Equals `poolSize` on every
     * evidence sort; on `sort=lift` the three-group floor applies to Band A too
     * (lift is a ratio over a sample — a single attributing group reaches its
     * ceiling), so this is the smaller, honest denominator for that band.
     * Optional on the wire: an older deployment of the route omits it and the
     * notice below simply does not render.
     */
    bandAEligible?: number;
    /** Candidates cut off while tying with Band A's last entry. 0 — or absent —
     *  means the band's bottom edge is a real one. */
    bandATied?: number;
    /** Size of the sector pool per platform, counted BEFORE the platform
     *  answer is applied, so the picker can state what each choice narrows to. */
    platformCounts?: Record<string, number>;
    /** The denominator for `platformCounts`: the unfiltered sector pool. NOT
     *  `poolSize`, which moves with the platform selection. */
    poolTotal?: number;
    /** How many days back the evidence section looks. Shipped so the page
     *  labels the window from the response instead of repeating the number. */
    evidenceWindowDays?: number;
    evidenceSince?: string;
  };
}

/* ────────────────────────────────────────────────────────────────────────────
 * Fetch
 *
 * Deliberately NOT `apiFetch` from src/lib/api.ts. That helper collapses every
 * failure into `new Error(body.error)`, discarding the status — and this page
 * has to tell two failures apart that must never look alike:
 *
 *   • 400  the sector/platform/sort the visitor asked for is not one we accept.
 *          An error state that says so.
 *   • 5xx / network  we could not answer. A retryable error state.
 *
 * Rendering a 400 as an empty page would read as "no threats target you",
 * which is the single most misleading thing this feature could say.
 * ──────────────────────────────────────────────────────────────────────────── */

const ENDPOINT = '/api/v1/profile';

class ProfileRequestError extends Error {
  readonly status: number;
  readonly code: string | null;

  constructor(status: number, code: string | null, message: string) {
    super(message);
    this.name = 'ProfileRequestError';
    this.status = status;
    this.code = code;
  }
}

async function fetchProfile(search: string): Promise<ProfileResponse> {
  const res = await fetch(search ? `${ENDPOINT}?${search}` : ENDPOINT);
  if (!res.ok) {
    const body = (await res.json().catch(() => null)) as { error?: string; code?: string } | null;
    throw new ProfileRequestError(res.status, body?.code ?? null, body?.error ?? `HTTP ${res.status}`);
  }
  return (await res.json()) as ProfileResponse;
}

/* ────────────────────────────────────────────────────────────────────────────
 * Sort keys and their live differentiation score
 *
 * `score` is how many of the twelve sectors come out with a DISTINCT top-six
 * list under that sort — measured against production, and the premise of the
 * whole feature. scripts/lib/profile-golden.test.mjs is the standing gate on
 * the two extremes: all twelve sectors differ under lift, and ordering by IOC
 * sightings collapses them.
 *
 * A visitor sorting by sightings is looking at a list that is very nearly the
 * same list every other sector sees. Saying so beside the control is the
 * difference between a briefing and a horoscope.
 * ──────────────────────────────────────────────────────────────────────────── */

type SortKey = 'io' | 'rp' | 'kev' | 'cv' | 'lift';

interface SortOption {
  value: SortKey;
  /** Control label. */
  label: string;
  /** The band-A column this sorts on. */
  column: string;
  score: number;
  blurb: string;
  /**
   * What the column actually measures, and what it is biased by — shown from
   * the (i) inside each pill.
   *
   * Every one of these names its own weakness, because every one has a real
   * one and the differentiation badge alone does not explain it: a reader
   * seeing "Sightings 1/12" learns that the column barely separates sectors,
   * not that 98.6% of the rows behind it are a cross-product. These are
   * measured statements, not hedges.
   */
  explainer: ReactNode;
}

const SORT_OPTIONS: readonly SortOption[] = [
  {
    value: 'lift',
    label: 'Lift',
    column: 'LIFT',
    score: 12,
    blurb: 'All twelve sectors rank a different top six — the only column that measures sector fit rather than volume.',
    explainer: (
      <>
        Lift compares how often this sector&apos;s attributed groups use a technique with how often
        all tracked groups use it. 1.00x is the dataset average; above 1.00x is{' '}
        <span className="font-semibold text-[var(--text-primary)]">over-represented</span> here. It is a <span className="font-semibold text-[var(--text-primary)]">ratio over a small sample</span>, and its
        ceiling is reached by any technique with a single attributing group — so bands ranked by
        lift exclude techniques used by fewer than three of the sector&apos;s groups. Which groups
        count as this sector&apos;s is decided by <span className="font-semibold text-[var(--text-primary)]">keyword matching</span> on ATT&amp;CK group
        descriptions, with no analyst confirmation, so a mis-tagged group shifts every lift figure
        here.
      </>
    ),
  },
  {
    value: 'kev',
    label: 'KEV',
    column: 'KEV',
    score: 10,
    blurb: 'Ten of twelve sectors rank a different top six.',
    explainer: (
      <>
        KEV counts the CVEs inferred for a technique that appear in CISA&apos;s Known Exploited
        Vulnerabilities catalogue. The link is an <span className="font-semibold text-[var(--text-primary)]">inference</span> along technique &rarr; CWE
        &rarr; CAPEC &rarr; CVE, so it is a <span className="font-semibold text-[var(--text-primary)]">presence signal</span> rather than a count of
        incidents in this sector, and a technique with no CWE path carries zero however often it is
        used.
      </>
    ),
  },
  {
    value: 'cv',
    label: 'CVEs',
    column: 'CVE',
    score: 8,
    blurb: 'Eight of twelve sectors rank a different top six.',
    explainer: (
      <>
        CVEs counts every vulnerability inferred for a technique along the same technique &rarr; CWE
        &rarr; CAPEC &rarr; CVE chain. It measures <span className="font-semibold text-[var(--text-primary)]">vulnerability surface</span>, <span className="font-semibold text-[var(--text-primary)]">not</span>{' '}
        how often the technique is used, so broad generic weaknesses score far above specific
        tradecraft.
      </>
    ),
  },
  {
    value: 'rp',
    label: 'Reports',
    column: 'REPORTS',
    score: 2,
    blurb: 'Two of twelve sectors rank a different top six. CTI report volume is near-identical across sectors.',
    explainer: (
      <>
        Reports counts mentions of a technique across the CTI reporting held here. Every mapping
        comes from <span className="font-semibold text-[var(--text-primary)]">OTX pulse tags</span> — the vendor blogs ingested alongside them publish no
        machine-readable technique IDs and contribute none — and the count is{' '}
        <span className="font-semibold text-[var(--text-primary)]">corpus-wide</span> rather than sector-specific. It says what was written about, not
        what targeted this sector.
      </>
    ),
  },
  {
    value: 'io',
    label: 'Sightings',
    column: 'SIGHTINGS',
    score: 1,
    blurb: 'One of twelve. Ordering by IOC sightings collapses the twelve sectors onto a single list: it measures activity, not sector focus.',
    explainer: (
      <>
        Sightings counts indicators linked to a technique. That link is almost entirely inferred:{' '}
        <span className="font-semibold text-[var(--text-primary)]">98.6%</span> of these rows come from a <span className="font-semibold text-[var(--text-primary)]">cross-product</span> that attributes every
        technique of a malware family to every indicator of that family, so the number tracks feed
        volume for a handful of families rather than observation of the technique itself. It is the
        weakest column here, and scores as such.
      </>
    ),
  },
];

const SORT_BY_KEY: ReadonlyMap<SortKey, SortOption> = new Map(SORT_OPTIONS.map((o) => [o.value, o]));

/** Matches `sortKeySchema`'s own `.default('kev')` in app/api/v1/lib/validate.ts. */
const DEFAULT_SORT: SortKey = 'kev';

/** Ties every pill's (i) to the one panel it expands. */
const EXPLAINER_ID = 'profile-sort-explainer';


/* ────────────────────────────────────────────────────────────────────────────
 * Known-value sets
 *
 * Built from the shared option lists, so a 400 can name the offending
 * parameter instead of shrugging. Never re-declared here and never imported
 * from app/api/v1/lib/validate.ts — that module imports zod, and this is a
 * 'use client' component (see the header comment in
 * src/lib/profile-options.ts).
 * ──────────────────────────────────────────────────────────────────────────── */

const KNOWN_SECTORS: ReadonlySet<string> = new Set(SECTOR_OPTIONS.map((o) => o.value));
/** Every platform the API will ACCEPT — not the ones this page offers. The
 *  picker below is built per-domain (`platformsForDomain`), but a pasted URL
 *  can legally carry any of the 20, so the 400 diagnostic must recognise all
 *  of them or it would blame a value the API did not reject. */
const KNOWN_PLATFORMS: ReadonlySet<string> = new Set<string>(PLATFORMS);
const KNOWN_SORTS: ReadonlySet<string> = new Set<string>(SORT_OPTIONS.map((o) => o.value));

/**
 * Mirrors `VALID_DOMAINS` in app/api/v1/lib/validate.ts. Four real domains —
 * `'all'`, which the site-wide dropdown can put in the URL, is NOT one of
 * them and would 400 if forwarded, so it is handled separately below.
 */
const KNOWN_DOMAINS: ReadonlySet<string> = new Set([
  'enterprise-attack',
  'mobile-attack',
  'ics-attack',
  'atlas-attack',
]);

/** `submissionSchema.platforms` / `platformsParam` both cap at 24. */
const MAX_PLATFORMS = 24;

const SECTOR_NAME_BY_SLUG: ReadonlyMap<string, string> = new Map(
  SECTOR_OPTIONS.map((o) => [o.value, o.label]),
);

/* ────────────────────────────────────────────────────────────────────────────
 * Small presentational pieces
 *
 * `Card`, `Notice`, `Metric` and `num` live in
 * src/components/profile/BriefingPrimitives.tsx: the OT briefing renders the
 * same cards, the same notices and the same right-aligned labelled cells, and
 * two copies of them would have drifted the first time either page was
 * restyled. `epss` stays here — the OT path has no EPSS to format, measured
 * zero for every live ICS technique.
 * ──────────────────────────────────────────────────────────────────────────── */

function epss(v: number | null): string {
  if (v === null) return '—';
  return `${Math.round(v * 100)}%`;
}

/**
 * The brief's chip: `max_epss >= 0.9 && kev_count > 0`. Both halves matter —
 * KEV alone says "someone was exploited", high EPSS alone says "prediction";
 * together they say confirmed AND broadly predicted.
 */
function isWide(t: BandItem): boolean {
  return t.maxEpss !== null && t.maxEpss >= 0.9 && t.kevCount > 0;
}

function TechniqueRow({
  rank,
  item,
  sortKey,
  showLift,
}: {
  rank: number;
  item: BandItem;
  sortKey: SortKey;
  showLift: boolean;
}) {
  return (
    <li className="flex flex-col gap-2 px-4 py-3 border-t border-[var(--border-faint)] sm:flex-row sm:items-center sm:justify-between sm:gap-4">
      <div className="flex min-w-0 items-center gap-2">
        <span className="w-4 shrink-0 text-xs tabular-nums text-[var(--text-secondary)]">{rank}</span>
        <EntityLink type="technique" attackId={item.attackId} name={item.name} />
        {isWide(item) && (
          <span
            className="inline-flex shrink-0 items-center rounded-full border border-[var(--orange-dim)] bg-[var(--orange-faint)] px-1.5 py-px text-[10px] font-semibold uppercase tracking-wider text-[var(--accent-orange)]"
            title="At least one CVE inferred for this technique is KEV-listed AND scores EPSS >= 0.90 — confirmed exploitation plus a high predicted exploitation rate."
          >
            Wide
          </span>
        )}
      </div>

      <dl className="flex flex-wrap items-start gap-x-4 gap-y-2 sm:shrink-0 sm:justify-end">
        <Metric
          label="Sightings"
          value={num(item.iocs)}
          emphasis={sortKey === 'io'}
          title="IOC sightings linked to this technique, across all sectors."
        />
        <Metric
          label="Reports"
          value={num(item.reports)}
          emphasis={sortKey === 'rp'}
          title="CTI reports mentioning this technique, across all sectors."
        />
        <Metric
          label="KEV"
          value={num(item.kevCount)}
          emphasis={sortKey === 'kev'}
          title="CVEs on the CISA KEV catalogue that reach this technique through CWE -> CAPEC inference. A presence signal, not a count of incidents."
        />
        <Metric
          label="EPSS"
          value={epss(item.maxEpss)}
          title="Highest EPSS score among the CVEs inferred for this technique — the predicted probability that CVE is exploited in the next 30 days."
        />
        {/* The four columns above are the brief's evidence strip. Two sort
            keys rank on a figure that is NOT among them — `cv` on the CVE
            count and `lift` on lift — and a list ordered by a number the
            reader cannot see reads as arbitrary. Add exactly the missing
            column, only when it is the active key, so the default four-column
            strip is unchanged. Band B already shows lift, hence the guard. */}
        {sortKey === 'cv' && (
          <Metric
            label="CVE"
            value={num(item.cveCount)}
            emphasis
            title="CVEs that reach this technique through CWE -> CAPEC inference. A breadth signal for the technique, not a count of incidents in this sector."
          />
        )}
        {sortKey === 'lift' && !showLift && (
          <Metric
            label="Lift"
            value={`${item.lift.toFixed(2)}x`}
            emphasis
            title="How much more this sector's attributed groups use this technique than tracked groups as a whole. 1.00x is average."
          />
        )}
        {showLift && (
          <>
            <Metric
              label="Lift"
              value={`${item.lift.toFixed(2)}x`}
              emphasis
              title="How much more this sector's attributed groups use this technique than tracked groups as a whole. 1.00x is average."
            />
            <Metric
              label="Groups"
              value={num(item.groupCount)}
              title="Groups attributed to this sector that use this technique. Sector fit requires at least three."
            />
          </>
        )}
      </dl>
    </li>
  );
}

function BandCard({
  eyebrow,
  title,
  explain,
  items,
  sortKey,
  showLift,
  empty,
}: {
  eyebrow: string;
  title: string;
  explain: ReactNode;
  items: BandItem[];
  sortKey: SortKey;
  showLift: boolean;
  empty: ReactNode;
}) {
  const headingId = `band-${eyebrow.toLowerCase().replace(/[^a-z0-9]+/g, '-')}`;
  return (
    <Card>
      <section aria-labelledby={headingId}>
        <div className="px-4 py-3">
          {/* The band's name sits in the top-right corner, on the title's own
              line: it is a label for the card, not a heading above it, and the
              two bands are read side by side so the names want to line up with
              each other rather than with their own titles. `shrink-0` and
              `min-w-0` keep "Sector fit" whole when a long title wraps. */}
          <div className="flex items-baseline justify-between gap-3">
            <h2 id={headingId} className="min-w-0 text-base font-semibold text-[var(--text-primary)]">
              {title}
            </h2>
            <p className="shrink-0 text-[10px] font-semibold uppercase tracking-wider text-[var(--accent-teal)]">
              {eyebrow}
            </p>
          </div>
          <p className="mt-1 text-xs leading-relaxed text-[var(--text-secondary)]">{explain}</p>
        </div>
        {items.length > 0 ? (
          <ol>
            {items.map((item, i) => (
              <TechniqueRow
                key={item.attackId}
                rank={i + 1}
                item={item}
                sortKey={sortKey}
                showLift={showLift}
              />
            ))}
          </ol>
        ) : (
          <div className="border-t border-[var(--border-faint)] px-4 py-4 text-sm text-[var(--text-primary)]">
            {empty}
          </div>
        )}
      </section>
    </Card>
  );
}

/**
 * One evidence count, linked to the CVE list filtered to exactly what it counts.
 *
 * A LINK, not a popover. The first build of this was a portal popover showing
 * the top ten; a page is better on every axis — the whole list rather than a
 * truncated ten, the list page's own sorting, severity and search controls, a
 * URL the reader can share or bookmark, and no positioning code to maintain.
 *
 * /cti/cves reads `technique`, `source` and `since` straight from the query
 * string, and /api/v1/cves applies the same three — and `source=cisa_kev` is
 * the very definition the assembler counts KEV with, so those three axes cannot
 * drift.
 *
 * `allSectors` IS LOAD-BEARING, and its absence was a real defect: every number
 * in this section linked to a SMALLER list. Three axes agreeing is not the same
 * as the page agreeing. A fourth parameter nobody put in the link arrived on its
 * own — `UrlSyncEffect` re-injects the stored sector on every path but /profile,
 * and this page is what wrote that value to sessionStorage. On /cti/cves
 * `sector=` is an unrelated relation (affected product → app technique groups →
 * groups → sector), which this count has no notion of, so it only ever subtracts:
 * production, financial, T1218.001 — the section says 29 CVEs and 5 KEV, the
 * page it linked to said 17 and 3, and T1003.006's "1" landed on "No CVEs
 * found." The earlier verification missed it because it was run against
 * /api/v1/cves directly, which never sees the injected param; the PAGE does.
 *
 * So the link now states its scope instead of leaving it to be filled in. This
 * count is sector-blind by construction — it counts every CVE on the technique —
 * and the URL now says so, which is also the only honest option: making the
 * count sector-aware would mean adopting a sector definition that has nothing to
 * do with what the section measures.
 *
 * A zero renders as plain text: there is nothing to navigate to, and a link
 * that lands on an empty list is a worse answer than the honest number.
 */
function EvidenceCount({
  attackId, count, kevOnly, sinceIso,
}: {
  attackId: string;
  count: number;
  kevOnly: boolean;
  sinceIso: string;
}) {
  // No window, no link. An empty `since` would be DROPPED from the query string
  // rather than defaulting to the same 12 months, so the list would answer for
  // all time — a number far larger than the one clicked. Unreachable in
  // practice (a row implies a window) and cheap to make impossible.
  if (count === 0 || !sinceIso) {
    return <span className="tabular-nums text-[var(--text-secondary)]">{count.toLocaleString()}</span>;
  }

  const qs = new URLSearchParams({
    technique: attackId,
    since: sinceIso,
    [ALL_SECTORS_PARAM]: '1',
  });
  if (kevOnly) qs.set('source', 'cisa_kev');

  return (
    <Link
      href={`/cti/cves?${qs.toString()}`}
      title={`${count.toLocaleString()} ${kevOnly ? 'KEV-listed ' : ''}CVEs for ${attackId} in the rolling 12 months`}
      className="tabular-nums text-[var(--accent-teal)] underline decoration-dotted underline-offset-2 hover:decoration-solid"
    >
      {count.toLocaleString()}
    </Link>
  );
}

/**
 * The honesty block. Not decoration and not a disclaimer to be shrunk: every
 * number above is an inference of some kind, and a reader who does not know
 * which kind will over-trust all of them equally.
 */
function Provenance() {
  return (
    <Card className="p-4">
      <h2 className="text-xs font-semibold uppercase tracking-wider text-[var(--text-secondary)]">
        Where these numbers come from
      </h2>
      <ul className="mt-2 space-y-2 text-xs leading-relaxed text-[var(--text-secondary)]">
        <li>
          <span className="font-semibold text-[var(--text-primary)]">
            Sector attribution is automated.
          </span>{' '}
          Every group-to-sector link in this dataset carries{' '}
          <code className="font-mono text-[11px]">source=&apos;auto&apos;</code> — derived from
          ATT&amp;CK group descriptions and CTI text, not confirmed by an analyst. The group list
          and every lift figure below inherit whatever that derivation got wrong.
        </li>
        <li>
          <span className="font-semibold text-[var(--text-primary)]">
            KEV and EPSS reach techniques by inference,
          </span>{' '}
          along the chain technique → CWE → CAPEC → CVE. They are{' '}
          <span className="font-semibold text-[var(--text-primary)]">presence signals</span> — &ldquo;at
          least one CVE inferred for this technique is KEV-listed&rdquo; — not counts of incidents,
          and not evidence that anyone in this sector was hit.
        </li>
        <li>
          <span className="font-semibold text-[var(--text-primary)]">
            Sightings and reports are global CTI volume,
          </span>{' '}
          not sector-specific. They indicate that a technique is active, not that it is directed at
          this sector — which is why they score 1/12 and 2/12 on differentiation.
        </li>
        <li>
          <span className="font-semibold text-[var(--text-primary)]">Lift</span> compares how often
          this sector&apos;s attributed groups use a technique against how often all tracked groups
          use it. 1.00x is average. It is the only figure here that measures sector fit — and it is
          computed from the automated attribution in the first bullet.
        </li>
      </ul>
    </Card>
  );
}

/* ────────────────────────────────────────────────────────────────────────────
 * The view
 * ──────────────────────────────────────────────────────────────────────────── */

export function ThreatProfile() {
  const router = useRouter();
  const searchParams = useSearchParams();
  const { syncStoredSector } = useSector();
  const { domains } = useDomain();

  /**
   * Which column's explainer is open, or null. One at a time: five panels
   * stacked under the control row would push the briefing off the screen, and
   * the question being answered is always "what is THIS column".
   *
   * Local, NOT a URL param. The definition is a reading aid; putting it in the
   * query string would make it part of every shared link and of the react-query
   * key, re-fetching the briefing to open a paragraph.
   */
  const [openSort, setOpenSort] = useState<SortKey | null>(null);
  /** The open column's definition, or null. Resolved once rather than in
   *  both the panel's guard and its body. */
  const openSortOption = openSort === null ? null : (SORT_BY_KEY.get(openSort) ?? null);

  /**
   * Read STRICTLY from the URL. Not from `useSector()`, not from
   * sessionStorage, not from a constant.
   *
   * This is the one rule the page cannot bend: a briefing headed "most
   * disproportionate for you" over a sector nobody chose is worse than no
   * briefing at all. With no `?sector=`, the API returns `reason: 'no-sector'`
   * and this page says so in as many words.
   *
   * `UrlSyncEffect` in app/providers.tsx deliberately EXCLUDES this path from
   * its stored-sector injection, so a bare `/profile` genuinely arrives with
   * no sector even for a visitor who picked one elsewhere. Everywhere else in
   * the app the sector is a view filter and carrying it forward is helpful;
   * here it would be a claim about who the reader is.
   */
  const sector = searchParams.get('sector');
  const rawPlatforms = searchParams.get('platforms');
  const rawSort = searchParams.get('sort');
  const rawDomain = searchParams.get('domain');

  const platforms = useMemo(() => parsePlatforms(rawPlatforms), [rawPlatforms]);

  const sortKey: SortKey =
    rawSort && KNOWN_SORTS.has(rawSort) ? (rawSort as SortKey) : DEFAULT_SORT;
  const sortOption = SORT_BY_KEY.get(sortKey) ?? SORT_OPTIONS[1];

  /**
   * Domain is NEVER allowed to be absent.
   *
   * The assembler reads `AND ($2::text IS NULL OR t.domain = $2)`, so an
   * omitted `domain` is not "enterprise" — it is NO FILTER AT ALL. Measured on
   * production: the `energy` pool is 219 techniques only because it is
   * 205 enterprise + 12 ics-attack + 2 mobile-attack mixed together. ICS and
   * mobile techniques carry essentially no CVE, KEV or EPSS evidence, so they
   * enter a briefing headed with one sector's name as permanent zeroes that
   * still consume Band A and Band B slots and still dilute lift.
   *
   * The param reaches this page only on the Apply path (`buildProfileUrl`
   * always writes it) — a bare `/profile`, a shared link or a back-button
   * landing has none. Hence the default here, and hence the domain is printed
   * in the subtitle unconditionally: if it is ever wrong again, it is at least
   * visible.
   *
   * `'all'` is the one legitimate absence. The site-wide dropdown can write
   * it, it is not an API value (it would 400), and coercing it to enterprise
   * would silently overrule an explicit choice. It becomes a real no-filter
   * request, disclosed on the page.
   *
   * The resolution itself lives in src/lib/profile-query.mjs, pure and
   * fixture-tested, precisely because it was an inline expression here when it
   * was wrong.
   */
  const { domain, allDomains } = resolveProfileDomain(rawDomain, DEFAULT_DOMAIN);
  const domainLabel = allDomains
    ? 'All domains'
    : (domains.find((d) => d.value === domain)?.label ?? domain ?? DEFAULT_DOMAIN);

  /**
   * The platform picker, DERIVED FROM THE DOMAIN.
   *
   * It used to switch to `OT_PLATFORMS` for ics-attack, which offered seven
   * values that match ZERO live ICS techniques (measured: every live ICS
   * technique carries the literal platform 'None' or no platforms array at
   * all). Picking one narrowed the pool to nothing, silently. That export is
   * gone and the ICS domain no longer reaches this component at all — it is
   * routed to `OtProfile`, which asks about assets and Purdue levels instead.
   *
   * A domain with no platform vocabulary (atlas-attack, measured: all 155 live
   * techniques carry no platforms array) gets an empty list, and the control is
   * not rendered — an empty picker is a question that cannot be answered.
   */
  /**
   * Canonical query string: only the four parameters this endpoint reads, in
   * a fixed order. Unrelated params the app carries around (`entity`, `tab`,
   * …) neither reach the API nor fragment the react-query cache.
   */
  const apiSearch = useMemo(
    () => buildProfileApiQuery({ sector, platforms, sort: sortKey, domain }),
    [sector, platforms, sortKey, domain],
  );

  const { data, isPending, error, refetch } = useQuery({
    queryKey: ['profile', apiSearch],
    queryFn: () => fetchProfile(apiSearch),
    // A 400 is a verdict on the query, not a transient failure — retrying it
    // twice just delays the error state by a second.
    retry: (failureCount, err) =>
      !(err instanceof ProfileRequestError && err.status >= 400 && err.status < 500) &&
      failureCount < 2,
  });

  /*
   * What each platform would narrow the pool to — "Windows · 271 of 368
   * techniques" — which turns a blind multi-select into a visible one.
   *
   * Declared HERE, after the query, not beside the other option lists above:
   * `data` is a `const` from `useQuery`, so reading it earlier in this function
   * body is a temporal-dead-zone ReferenceError, not merely an undefined value.
   *
   * `poolTotal`, never `poolSize`: `poolSize` is the pool Band B was drawn
   * from, which the platform answer itself narrows — so using it as the
   * denominator would make every count read "271 of 271" the moment Windows
   * was picked. `poolTotal` is the unfiltered sector pool and does not move.
   *
   * Shown only once a pool exists. Before the first response, and while a new
   * sector is in flight, there is no honest number, so the option carries no
   * `meta` line rather than a stale one. A platform the pool never mentions
   * shows 0 — the true answer, and the explanation for an empty briefing.
   *
   * HELD ACROSS A PLATFORM TOGGLE, which is the one in-flight window where
   * dropping the number is not honesty but churn. These counts are taken over
   * the pool BEFORE any platform filter (see the route), so they are invariant
   * under the platform answer: the value that arrives after a toggle is the
   * value that was already on screen. Without the hold, every toggle changes
   * the query key, `data` goes `undefined` (no `placeholderData` anywhere), all
   * eleven rows lose their second line, and the OPEN listbox — selecting does
   * not close it — collapses by ~8px per row under the cursor, so the next
   * click lands on a platform nobody aimed at. The hold is keyed on
   * sector+domain, the two answers the counts DO move with, so a sector change
   * still blanks them rather than showing another sector's numbers.
   *
   * Recorded in an EFFECT, not during render. A render-phase ref write would be
   * the shorter spelling and React asks you not to: it is a side effect in a
   * function React may call speculatively or discard. The effect is enough
   * here, and the one-commit lag costs nothing — on the render where `data`
   * exists the live value is used directly, and the cache is only ever read on
   * the renders where it does not.
   */
  const countsKey = `${sector ?? ''}|${domain}`;
  const heldCounts = useRef<{ key: string; counts: Record<string, number>; total: number } | null>(null);
  const liveCounts = data?.meta?.platformCounts;
  const liveTotal = data?.meta?.poolTotal;
  useEffect(() => {
    if (liveCounts && liveTotal) {
      heldCounts.current = { key: countsKey, counts: liveCounts, total: liveTotal };
    }
  }, [countsKey, liveCounts, liveTotal]);
  const held = heldCounts.current?.key === countsKey ? heldCounts.current : null;
  const platformCounts = liveCounts ?? held?.counts;
  const poolTotal = liveTotal ?? held?.total;
  const platformOptions = useMemo<MultiSelectOption[]>(
    () => platformsForDomain(domain).map((p) => {
      const n = platformCounts?.[p];
      return {
        value: p,
        label: p,
        ...(n === undefined || !poolTotal
          ? {}
          : { meta: `${n.toLocaleString()} of ${poolTotal.toLocaleString()} techniques` }),
      };
    }),
    [domain, platformCounts, poolTotal],
  );

  /**
   * Rewrite the URL from the four parameters this page owns, through the same
   * tested builder the panel's Apply uses (src/lib/profile-url.mjs). Built
   * fresh rather than patched onto the current query string, for the reason
   * that module exists: it writes `domain` unconditionally, so a control
   * change can never produce the domain-less URL that finding 1 was about.
   * It also drops params this page does not read, and caps lists at 24.
   */
  const navigate = useCallback(
    (next: { sector?: string | null; platforms?: string[]; sort?: SortKey }) => {
      router.replace(
        buildProfileUrl({
          sector: next.sector !== undefined ? next.sector : sector,
          // Preserves an explicit `all`; otherwise the resolved domain.
          domain: rawDomain ?? DEFAULT_DOMAIN,
          params: {
            platforms: next.platforms !== undefined ? next.platforms : platforms,
            sort: next.sort ?? sortKey,
          },
        }),
        { scroll: false },
      );
    },
    [router, sector, rawDomain, platforms, sortKey],
  );

  const onSectorChange = useCallback(
    (next: string | null) => {
      // Keep the app-wide sector dropdown and its sessionStorage backing
      // coherent with what this page is about to put in the URL, WITHOUT
      // `setSector` — that would fire its own router.push from a render-time
      // closure alongside the replace below (app/providers.tsx:10-45).
      syncStoredSector(next);
      navigate({ sector: next });
    },
    [navigate, syncStoredSector],
  );

  const onPlatformsChange = useCallback(
    (next: string[]) => {
      navigate({ platforms: next });
    },
    [navigate],
  );

  /* ── Controls: rendered in every state, including the error ones, so a bad
   *    parameter is always one click away from being fixed. ───────────────── */
  const controls = (
    <Card className="p-4">
      <div className="grid gap-4 md:grid-cols-2">
        <div>
          <label
            htmlFor="profile-sector"
            className="block text-[10px] font-semibold uppercase tracking-wider text-[var(--text-secondary)]"
          >
            Sector
          </label>
          <select
            id="profile-sector"
            value={sector ?? ''}
            onChange={(e) => onSectorChange(e.target.value || null)}
            /* `min-h-[44px]` rather than a pseudo-element: a <select> is a
               replaced control, so a ::before on it is not reliably rendered
               and could not be the hit region anyway. The panel's own sector
               <select> is already 44px, so this matches it rather than
               inventing a second size. */
            className="mt-1.5 w-full min-h-[44px] appearance-none rounded-md border border-[var(--border-color)] bg-[var(--surface-base)] px-2.5 py-1.5 text-sm text-[var(--text-primary)] focus:outline-none focus:ring-1 focus:ring-[var(--accent-teal)]"
          >
            <option value="">— none chosen —</option>
            {SECTOR_OPTIONS.map((o) => (
              <option key={o.value} value={o.value}>
                {o.label}
              </option>
            ))}
          </select>
        </div>

        {platformOptions.length > 0 && (
          <MultiSelect
            id="profile-platforms"
            label="Platforms"
            options={platformOptions}
            selected={platforms}
            onChange={onPlatformsChange}
            countNoun="platforms"
          />
        )}
      </div>

      <fieldset className="mt-4">
        <legend className="text-[10px] font-semibold uppercase tracking-wider text-[var(--text-secondary)]">
          Rank the evidence band by
        </legend>
        {/* `gap-y-5`, not `gap-y-2`: each pill carries a 44px-tall hit region
            as a pseudo-element (below), which bleeds ~9px above and below a
            26px pill. Two wrapped rows 8px apart would have overlapping
            targets, so a press near the edge could fire the row above. 20px
            of vertical gap keeps every target to its own pill. */}
        <div className="mt-1.5 flex flex-wrap items-center gap-x-2 gap-y-5">
          {SORT_OPTIONS.map((o) => {
            const active = o.value === sortKey;
            const open = openSort === o.value;
            return (
              /* The pill is a CONTAINER, not a button. It carries the border,
                 the rounding and the active background, and holds two separate
                 buttons: the sort itself, and the (i) that explains the column.
                 A button cannot nest inside a button, and the (i) previously sat
                 OUTSIDE the pill for that reason — which read as a stray circle
                 belonging to nothing. Splitting the pill keeps the markup valid
                 and puts the affordance where it belongs.

                 NO `overflow-hidden` here, deliberately. It was the obvious way
                 to keep the (i)'s background inside the rounded border, and it
                 silently destroyed both buttons' touch targets: each one's 44px
                 region is an absolutely-positioned `::before` whose containing
                 block is the button, so a clipping ancestor clips it — for
                 hit-testing as well as painting — back to the pill's own ~26px
                 box. That is the whole mechanism the pseudo-elements exist for,
                 and the `gap-y-5` above exists to separate. The (i) rounds its
                 own right corners instead (5px = the 6px outer radius less the
                 1px border), which costs one class and clips nothing. */
              <span
                key={o.value}
                className={`inline-flex items-stretch rounded-md border text-xs transition-colors ${
                  active
                    ? 'border-[var(--accent-teal)] bg-[var(--teal-ghost)] font-semibold text-[var(--accent-teal)]'
                    : 'border-[var(--border-color)] text-[var(--text-primary)] hover:border-[var(--border-hover)]'
                }`}
              >
                <button
                  type="button"
                  onClick={() => navigate({ sort: o.value })}
                  aria-pressed={active}
                  title={o.blurb}
                  /* Same pattern as MultiSelect's chip "x": the 44px target is
                     an absolutely-positioned pseudo-element, so the pill keeps
                     its own compact box and the control row does not become a
                     stack of 44px buttons. `inset-x-0` confines it to this
                     button's own width, so a stray press can only ever hit the
                     sort you aimed at — and never the (i) beside it. */
                  className="relative inline-flex items-center gap-2 px-2.5 py-1
                             before:content-[''] before:absolute before:inset-x-0 before:top-1/2 before:h-11 before:-translate-y-1/2"
                >
                  {o.label}
                </button>
                {/* Every column gets one, not just lift. Each names what it
                    measures AND what biases it, because the differentiation
                    badge does not: "Sightings 1/12" says the column barely
                    separates sectors, not that 98.6% of the rows behind it are
                    a cross-product. */}
                <button
                  type="button"
                  onClick={() => setOpenSort(open ? null : o.value)}
                  aria-expanded={open}
                  aria-controls={EXPLAINER_ID}
                  aria-label={open ? `Hide what ${o.label} measures` : `What ${o.label} measures`}
                  /* `left-0 -right-1`, never `-inset-x-1`: a symmetric negative
                     inset put 4px of this button's target ON TOP of the sort
                     button's right padding, and because this is the later
                     positioned sibling it won — a press on the last 4px of
                     "KEV" opened the explainer instead of sorting, which is
                     exactly what the comment above promises cannot happen. The
                     widening now goes outward only, past the pill's edge, where
                     there is nothing to steal from. */
                  className={`relative inline-flex w-6 items-center justify-center rounded-r-[5px] border-l text-[10px] font-semibold italic transition-colors
                              before:content-[''] before:absolute before:left-0 before:-right-1 before:top-1/2 before:h-11 before:-translate-y-1/2 ${
                    active ? 'border-[var(--accent-teal)]' : 'border-[var(--border-color)]'
                  } ${
                    open
                      ? 'bg-[var(--accent-teal)] text-[var(--surface-card)]'
                      : 'text-[var(--text-secondary)] hover:bg-[var(--hover-overlay)] hover:text-[var(--text-primary)]'
                  }`}
                >
                  i
                </button>
              </span>
            );
          })}
        </div>
        {/* The score lives HERE and nowhere else. On the pill it was a bare
            `10/12` chip, which cannot be read without already knowing there are
            twelve sectors and that the comparison is over each one's top six —
            a methodology statistic in the place a reader looks for a threat
            one. Below the pills there is room to say it in a sentence. */}
        <p className="mt-2 text-xs leading-relaxed text-[var(--text-secondary)]">
          <span className="font-semibold text-[var(--text-primary)]">
            {sortOption.score} of 12 sectors
          </span>{' '}
          get a <span className="font-semibold">different</span> top six when ranked by{' '}
          {sortOption.column.toLowerCase()}.{' '}
          {sortOption.score === 12
            ? 'No two sectors see the same list.'
            : sortOption.score <= 2
              ? 'So nearly every sector sees the list below — this ordering describes the data, not this sector.'
              : ''}{' '}
          It says how specific the ordering is, not how severe anything is.
        </p>

        {openSortOption && (
          <div
            id={EXPLAINER_ID}
            className="mt-2 rounded-md border border-[var(--border-color)] bg-[var(--surface-base)] p-3 text-xs leading-relaxed text-[var(--text-secondary)]"
          >
            <span className="font-semibold text-[var(--text-primary)]">
              {openSortOption.label}
            </span>{' '}
            &middot; {openSortOption.explainer}
          </div>
        )}
      </fieldset>
    </Card>
  );

  /**
   * One shell for every state: header, then the controls, then whatever the
   * results region has to say.
   *
   * The controls are OUTSIDE the swap deliberately. Every sort, sector or
   * platform change mints a new react-query key, so `isPending` goes true and
   * a full-page loader would unmount the very control the visitor just
   * clicked — the selection appears to vanish, the focused element is
   * destroyed, and the page jumps. Only the results region below changes.
   */
  const urlSectorName =
    sector && KNOWN_SECTORS.has(sector) ? (SECTOR_NAME_BY_SLUG.get(sector) ?? sector) : null;

  const shell = (subtitle: ReactNode, body: ReactNode) => (
    <div className="space-y-6">
      <PageHeader
        title={urlSectorName ? `Threat profile — ${urlSectorName}` : 'Threat profile'}
        subtitle={subtitle}
        breadcrumb={[{ label: 'Threat profile' }]}
      />
      {controls}
      {body}
    </div>
  );

  /**
   * Shown in every successful state, and never conditionally: a domain that is
   * missing from the page is exactly how the cross-domain pool went unnoticed.
   */
  const domainLine = (
    <>
      {' '}
      · <span className="font-semibold text-[var(--text-primary)]">{domainLabel}</span>
    </>
  );

  /**
   * Takes the flag rather than reading `allDomains` directly, so the server's
   * own `meta.mixedDomain` can raise it too. The page infers the mixed pool
   * from the URL; the response confirms it from the pool actually ranked, and
   * either is enough to say so.
   */
  const mixedDomainNotice = (mixed: boolean) =>
    mixed ? (
    <Notice tone="warn" title="All domains — the pool is mixed">
      You have the site-wide domain filter on <span className="font-semibold">All Domains</span>, so
      enterprise, mobile, ICS and ATLAS techniques are ranked together under one sector heading.
      Mobile, ICS and ATLAS techniques carry close to no CVE, KEV or EPSS evidence, so they sit at
      zero in every evidence column while still occupying band slots and still diluting lift. Pick a
      single domain in the sidebar for a briefing that compares like with like.
    </Notice>
    ) : null;

  /* ── Failure states ───────────────────────────────────────────────────── */

  if (error) {
    const err = error instanceof ProfileRequestError ? error : null;

    if (err && err.status === 400) {
      const badSector = sector && !KNOWN_SECTORS.has(sector) ? sector : null;
      const badPlatforms = platforms.filter((p) => !KNOWN_PLATFORMS.has(p));
      const badSort = rawSort && !KNOWN_SORTS.has(rawSort) ? rawSort : null;
      const badDomain =
        rawDomain && rawDomain !== ALL_DOMAINS && !KNOWN_DOMAINS.has(rawDomain) ? rawDomain : null;
      const identified =
        badSector || badPlatforms.length > 0 || badSort || badDomain || platforms.length > MAX_PLATFORMS;

      return shell(
        'The API rejected this request — nothing was ranked.',
        <Notice tone="warn" title="Invalid profile query (HTTP 400)">
          <p>
            Nothing below is a threat finding. The request never reached the ranking engine, so an
            empty page here would mean &ldquo;we could not ask&rdquo; — never &ldquo;nothing targets
            you&rdquo;.
          </p>
          <ul className="mt-2 list-disc space-y-1 pl-5">
            {badSector && (
              <li>
                <code className="font-mono text-xs">sector={badSector}</code> is not one of the
                twelve sectors this dataset tracks.
              </li>
            )}
            {badPlatforms.map((p) => (
              <li key={p}>
                <code className="font-mono text-xs">{p}</code> is not an ATT&amp;CK platform with
                live techniques.
              </li>
            ))}
            {badSort && (
              <li>
                <code className="font-mono text-xs">sort={badSort}</code> is not a ranking key.
              </li>
            )}
            {badDomain && (
              <li>
                <code className="font-mono text-xs">domain={badDomain}</code> is not an ATT&amp;CK
                domain.
              </li>
            )}
            {platforms.length > MAX_PLATFORMS && (
              <li>
                {platforms.length} platforms were sent; the limit is {MAX_PLATFORMS}.
              </li>
            )}
            {!identified && (
              <li>
                The rejected parameter is not one this page can identify. The API said:{' '}
                <span className="italic">{err.message}</span>
              </li>
            )}
          </ul>
          <p className="mt-2">Pick a valid combination above and the briefing will load.</p>
        </Notice>,
      );
    }

    return shell(
      'The briefing could not be loaded.',
      <ErrorState
        message={`Could not load the threat profile — ${err ? `HTTP ${err.status}: ` : ''}${
          error instanceof Error ? error.message : 'request failed'
        }`}
        onRetry={() => void refetch()}
      />,
    );
  }

  /* ── Pending: controls stay, results region swaps ─────────────────────── */

  if (isPending || !data) {
    return shell(
      <span>
        Ranking{urlSectorName ? ` for ${urlSectorName}` : ''}…{domainLine}
      </span>,
      <Card className="py-8">
        <DiamondLoader text="Ranking techniques..." />
      </Card>,
    );
  }

  /* ── The valid "no sector" state ──────────────────────────────────────── */

  if (data.meta.reason === 'no-sector' || !data.profile.sector) {
    return shell(
      <span>No sector chosen — nothing has been ranked.{domainLine}</span>,
      <>
        <Notice tone="info" title="Reach and sector fit are absent, on purpose">
          <p>
            This page ranks techniques by how disproportionately the{' '}
            <span className="font-semibold">selected</span> sector&apos;s attributed threat groups
            use them. Without a sector there is no group set, no technique pool and no lift to rank
            by — so there is nothing here rather than a guess.
          </p>
          <p className="mt-2">
            No sector has been substituted — not even one selected elsewhere in the app. A briefing
            headed &ldquo;most disproportionate&rdquo; over a sector nobody chose is worse than an
            empty page, so this one stays empty until a sector is selected above.
          </p>
        </Notice>
        <Provenance />
      </>,
    );
  }

  /* ── The briefing ─────────────────────────────────────────────────────── */

  const { profile, groups, bandA, bandB, meta } = data;
  const sectorName =
    profile.sectorName ?? SECTOR_NAME_BY_SLUG.get(profile.sector ?? '') ?? profile.sector;
  const appliedPlatforms = profile.platforms ?? [];
  const groupsShown = groups.length;
  const moreGroups = Math.max(0, meta.groupCount - groupsShown);
  const platformList = (appliedPlatforms.length > 0 ? appliedPlatforms : platforms).join(', ');

  /**
   * Three states that the previous rendering explained as something they are
   * not. Each is read defensively (`=== true`) because the flags are optional
   * on the wire.
   *
   *   • `emptyPool` — nothing was ranked AT ALL. The degeneracy and Band-B
   *     notices below both describe a pool that exists and is thin, so over an
   *     empty pool they said "fewer than six distinct lift values exist across
   *     the 0 techniques in this pool" and "no technique carries any KEV
   *     evidence": an evidence-spread explanation for a missing pool. They are
   *     suppressed here and replaced by the one that is true.
   *   • `platformPoolEmpty` — that empty pool is the platform answer's doing,
   *     which is a different sentence from "this sector has no techniques".
   *   • `evidenceUnavailable` — the pool is fine but the sort column is all
   *     zero, so Band A is an arbitrary slice presented as "most evidence".
   */
  /**
   * The evidence section's rows, and the window start its links carry.
   *
   * TAKEN FROM THE RESPONSE, never recomputed here. This used to derive the
   * date from `meta.evidenceWindowDays` and `Date.now()`, which looked like it
   * could not drift — same constant, same arithmetic — and drifted anyway,
   * because the two sides were not the same window: the counts come from a cut
   * on the database's clock, this ran on the reader's, and the reader's clock is
   * an hour or a day or a year off whenever it is. The response is also cached
   * for an hour while this re-ran every render, so the gap changed sign at UTC
   * midnight. The date now ships with the numbers it belongs to.
   *
   * The fallback is for the shape, not for correctness: `evidenceSince` is
   * present whenever a row is, so an empty window start means an empty section
   * and no link to build.
   */
  const evidence = data.evidence ?? [];
  const evidenceSinceIso = meta.evidenceSince ?? '';

  const emptyPool = meta.poolSize === 0;
  const platformPoolEmpty = meta.platformPoolEmpty === true;
  const evidenceUnavailable = meta.evidenceUnavailable === true;

  /**
   * Where the other 356 are.
   *
   * The briefing shows twelve techniques — six per band — out of a pool that is
   * routinely in the hundreds, and until now it stated the pool size and then
   * offered nothing to do with it. /techniques reproduces this pool EXACTLY,
   * provided sub-techniques are switched on: same `group_sectors` join, same
   * domain equality, same revoked/deprecated exclusion. Verified 2026-10-02
   * against production for seven sectors — `meta.poolSize` equalled
   * `pagination.total` on every one (financial 368, healthcare 300, energy 205,
   * government 398, technology 432, defense 357, retail 211).
   *
   * `subs=1` is not optional: without it /techniques lists parent techniques
   * only and financial comes back 130, so the link would land on a third of the
   * number it was labelled with.
   *
   * The platform constraint is the one thing the destination cannot always
   * carry. `platform` there is a single enum value and 400s on a comma-joined
   * list (measured), while this page's answer is a SET tested for overlap. One
   * platform passes through exactly; two or more would make the destination
   * wider than the pool, so the count stops being a link and the offer below
   * Band B drops its number rather than quoting one it cannot honour.
   */
  const linkPlatforms = meta.platformDropped ? [] : appliedPlatforms;
  const poolExact = linkPlatforms.length <= 1;
  const poolHref = profile.sector
    ? `/techniques?${new URLSearchParams({
        sector: profile.sector,
        subs: '1',
        ...(allDomains || !domain ? {} : { domain }),
        ...(linkPlatforms.length === 1 ? { platform: linkPlatforms[0] } : {}),
      }).toString()}`
    : null;

  return shell(
    <span>
      <span className="font-semibold text-[var(--text-primary)] tabular-nums">
        {meta.groupCount.toLocaleString()}
      </span>{' '}
      threat {meta.groupCount === 1 ? 'group' : 'groups'} attributed to this sector ·{' '}
      {poolHref && poolExact && !emptyPool ? (
        <Link href={poolHref} className="text-[var(--accent-teal)] hover:underline">
          <span className="font-semibold tabular-nums">{meta.poolSize.toLocaleString()}</span>{' '}
          techniques in the ranked pool
        </Link>
      ) : (
        <>
          <span className="font-semibold text-[var(--text-primary)] tabular-nums">
            {meta.poolSize.toLocaleString()}
          </span>{' '}
          techniques in the ranked pool
        </>
      )}
      {appliedPlatforms.length > 0 && !meta.platformDropped && (
        // The assembler keeps a technique if it runs on ANY selected platform.
        // "filtered to Windows, Linux" reads as a conjunction and would mean a
        // far narrower pool than the one actually ranked.
        <> · running on any of: {platformList}</>
      )}
      {domainLine}
    </span>,
    <>
      {mixedDomainNotice(allDomains || meta.mixedDomain === true)}

      {/* An empty pool is its own state and gets its own sentence. Everything
          below it that explains a THIN pool is suppressed while it is up —
          two explanations of the same absence, one of them false, is worse
          than one. */}
      {emptyPool && (
        <Notice
          tone="warn"
          title={
            platformPoolEmpty
              ? 'Your platform selection matched nothing'
              : 'There is no pool to rank'
          }
        >
          {platformPoolEmpty ? (
            <p>
              No technique attributed to {sectorName} runs on{' '}
              {platforms.length > 0 ? (
                <span className="font-semibold">{platformList}</span>
              ) : (
                'the platforms you picked'
              )}
              , so the ranked pool is empty and both bands below are empty with it. Nothing about
              this says the evidence is thin or that {sectorName} is not targeted — it says the
              platform answer ruled every technique out. Widen it, or clear it, above.
            </p>
          ) : (
            <p>
              {sectorName} resolved to <span className="font-semibold tabular-nums">0</span>{' '}
              techniques in {domainLabel}, so nothing was ranked and no evidence, lift or band
              figure below was computed over anything. This is a gap in the data behind the sector
              — no rows for it in the lift matview yet, or an empty attribution set feeding it —
              not a finding about the sector. Try another sector or another domain; the numbers
              below are zeroes because the pool is empty, not because the threat is low.
            </p>
          )}
        </Notice>
      )}

      {/* Each of these conditions is rendered independently. They are not
          mutually exclusive — `bandBShort` is recomputed AFTER the platform
          widening, so it and `platformDropped` are routinely true together,
          and suppressing one of them left a short Band B on screen with
          nothing at all saying why. */}
      {evidenceUnavailable && !emptyPool && (
        <Notice tone="warn" title={`Nothing in this pool carries ${sortOption.column} evidence`}>
          Every one of the {meta.poolSize.toLocaleString()}{' '}
          {meta.poolSize === 1 ? 'technique' : 'techniques'} in this pool sits at zero{' '}
          <span className="font-semibold">{sortOption.column}</span>, so reach below is{' '}
          <span className="font-semibold">not</span> ranked by it — six of an all-zero column in
          whatever order the pool arrived in. {domainLabel} carries close to no CVE, KEV, EPSS,
          report or IOC evidence at all, so every evidence sort reads the same way here. Sector fit,
          which is always lift-ranked, is the half of this page that still says something.
        </Notice>
      )}

      {/* How Band A was CUT — the ratio floor and a tie at the boundary. One
          notice for both because under `sort=lift` both are usually true at
          once, and they are the same kind of fact: a statement about the
          selection rather than about the data.

          The floor is gated on the sort key, not on `bandAEligible <
          poolSize`: `poolSize` is the pool BAND B came from, which the platform
          fallback widens to the full sector pool while Band A stays on the
          narrow one — so that comparison is true for an evidence sort too
          whenever `platformDropped` fired. The text quotes no second number for
          the same reason.

          The `> 0` below is why this needs a companion: at exactly ZERO the
          floor has emptied the band, which is when the reader most needs the
          explanation — and the old gate suppressed it there, leaving the card
          to say "no technique in this pool carries any lift evidence", which
          was false. `?sector=financial&domain=mobile-attack&sort=lift` is the
          live case: a pool of two techniques, both carrying lift (2.17 and
          0.72), both used by one group. Reachable on mobile for 9 of the 12
          sectors. */}
      {!emptyPool && sortKey === 'lift' && (meta.bandAEligible ?? 0) === 0 && (
        <Notice tone="warn" title="Every technique here is below the floor">
          Lift is a ratio, so it needs a sample: reach is drawn only from techniques used by at
          least three of {sectorName}&apos;s groups
          {platforms.length > 0 && ' and running on the selected platforms'}, and in this pool{' '}
          <span className="font-semibold">no technique clears that</span>. The band is empty for
          that reason and no other — the techniques here do carry lift, each on a single
          attribution, which is exactly the evidence the floor exists to refuse. Switch the
          selector to an evidence column to rank this pool without a floor.
        </Notice>
      )}

      {!emptyPool && sortKey === 'lift' && (meta.bandAEligible ?? 0) > 0
        && (meta.bandAEligible as number) < meta.poolSize && (
        <Notice tone="info" title="Lift needs a sample, so reach has a floor">
          Lift is a ratio — this sector&apos;s share of a technique over every group&apos;s share —
          and its ceiling is reached by <span className="font-semibold">any</span> technique used by
          exactly one group that happens to be attributed here, with no evidence behind it at all.
          Ranked raw, this band came back as six such techniques in alphabetical order. So on this
          sort reach is chosen from the{' '}
          <span className="font-semibold tabular-nums text-[var(--text-primary)]">
            {(meta.bandAEligible as number).toLocaleString()}
          </span>{' '}
          techniques used by at least three of {sectorName}&apos;s groups
          {platforms.length > 0 && ' and running on the selected platforms'} — the same floor sector
          fit has always applied. Switch the selector to an evidence column and reach uses the whole
          pool: a KEV or CVE count is an absolute number and needs no floor.
        </Notice>
      )}

      {!emptyPool && (meta.bandATied ?? 0) > 0 && (
        <Notice tone="info" title="The last reach slot was a tie">
          <span className="font-semibold tabular-nums">{meta.bandATied}</span> further{' '}
          {meta.bandATied === 1 ? 'technique ties' : 'techniques tie'} with the sixth entry on{' '}
          <span className="font-semibold">{sortOption.column}</span> and lost the slot to a stable
          sort, not to a lower score. Read the bottom of the band as a boundary rather than a
          ranking.
        </Notice>
      )}

      {meta.degenerate && !emptyPool && (
        <Notice tone="warn" title="Lift cannot rank this selection">
          Fewer than six distinct lift values exist across the {meta.poolSize.toLocaleString()}{' '}
          {meta.poolSize === 1 ? 'technique' : 'techniques'} in this pool, so sector fit below is ordered
          but the order is close to arbitrary. Read it as &ldquo;these are attributed to your
          sector&rdquo;, not as &ldquo;these are disproportionately aimed at this sector&rdquo;. Widening the
          platform filter, or dropping it, usually restores a real spread.
        </Notice>
      )}

      {meta.platformDropped && (
        <Notice tone="warn" title="Platform filter dropped">
          Fewer than six techniques cleared the three-group floor with{' '}
          {platforms.length > 0 ? platforms.join(', ') : 'the platform filter'} applied, so the{' '}
          <span className="font-semibold">whole</span> platform constraint was removed and{' '}
          {platformPoolEmpty ? 'both bands were' : 'sector fit was'} re-selected over the full sector
          pool. {platformPoolEmpty
            ? 'The rows below are not filtered to the selected platforms.'
            : 'Reach still reflects the platform selection; sector fit does not.'}
        </Notice>
      )}

      {meta.bandBShort && !emptyPool && (
        <Notice tone="info" title={bandB.length === 0 ? 'Sector fit is empty' : 'Sector fit is short'}>
          Sector fit holds {bandB.length === 0 ? 'no technique' : `only ${bandB.length} of six`}
          {meta.platformDropped ? ', even after the platform filter was dropped' : ''}. It draws only
          from techniques attributed to at least three of this sector&apos;s groups{' '}
          <span className="font-semibold">and not already under reach</span>, so either the pool holds
          too few that clear the three-group floor, or reach has taken them. A technique used
          by one or two groups is one sighting away from noise, so the floor is not lowered to pad
          the list.
        </Notice>
      )}

      <div className="grid gap-6 lg:grid-cols-2">
        <BandCard
          eyebrow="Reach"
          // The heading must not claim a ranking the column cannot support.
          // With an all-zero sort column "Most KEV evidence" over six zeroes
          // is the single most misleading thing this page could say.
          // Lift is not evidence, so it does not take the evidence wording —
          // "Most lift evidence" was the literal output of the template.
          title={
            evidenceUnavailable
              ? `No ${sortOption.label.toLowerCase()} evidence to rank by`
              : sortKey === 'lift'
                ? 'Highest lift'
                : `Most ${sortOption.label.toLowerCase()} evidence`
          }
          explain={
            evidenceUnavailable ? (
              <>
                Every technique in this pool sits at zero{' '}
                <span className="font-semibold">{sortOption.column}</span>, so these six are{' '}
                <span className="font-semibold">not</span> the top six by anything — they are the
                pool&apos;s own incoming order, shown so the band is not silently empty. Read them
                as &ldquo;in this pool&rdquo;, nothing more.
              </>
            ) : (
              <>
                {/* The floor is metric-scoped: it applies to lift and to
                    nothing else, because only a ratio can be maximised by a
                    single sighting. This sentence used to say "with no
                    group-count floor" unconditionally, which on the lift sort
                    contradicted the notice directly above it — the one
                    explaining the floor it denied. */}
                Top six by <span className="font-semibold">{sortOption.column}</span>{' '}
                {sortKey === 'lift'
                  ? `across the techniques used by at least three of ${sectorName}'s groups`
                  : `across the whole ${sectorName} pool, with no group-count floor`}
                . This is what is loudest — reach, not sector fit — and at {sortOption.score}/12
                differentiation it is{' '}
                {sortOption.score <= 2
                  ? 'very nearly the list every other sector sees'
                  : 'largely specific to this sector'}
                .
              </>
            )
          }
          items={bandA}
          sortKey={sortKey}
          showLift={false}
          empty={
            emptyPool ? (
              <>
                <span className="font-semibold">The pool is empty.</span> There is no technique here
                to rank — see above for why. This is not &ldquo;no evidence found&rdquo;; it is
                &ldquo;nothing was searched&rdquo;.
              </>
            ) : sortKey === 'lift' && (meta.bandAEligible ?? 0) === 0 ? (
              /* NOT "carries no lift evidence" — the pool does carry lift, and
                 saying otherwise blamed the data for a decision this page made.
                 The floor emptied the band; the notice above gives the numbers. */
              <>
                <span className="font-semibold">Nothing clears the floor.</span> Every technique in
                this pool is attributed to fewer than three of {sectorName}&apos;s groups, so lift
                has too little behind it to rank on — see above.
              </>
            ) : (
              <>No technique in this pool carries any {sortOption.column.toLowerCase()} evidence.</>
            )
          }
        />

        <BandCard
          eyebrow="Sector fit"
          title={`Most disproportionate for ${sectorName}`}
          explain={
            <>
              Top six by <span className="font-semibold">lift</span> among techniques attributed to
              at least three of this sector&apos;s groups, with reach excluded. Always lift-ranked —
              the selector above changes reach only.
            </>
          }
          items={bandB}
          sortKey={sortKey}
          showLift
          empty={
            emptyPool ? (
              <>
                <span className="font-semibold">The pool is empty.</span> No technique reached
                either band, so there is nothing here to be disproportionate about — see above.
                Nothing has been substituted in its place.
              </>
            ) : (
              <>
                <span className="font-semibold">Sector fit is absent.</span> Nothing in this pool is
                both attributed to at least three of {sectorName}&apos;s groups and absent from
                reach, so there is nothing that can honestly be called disproportionately aimed at
                this sector. Nothing has been substituted in its place.
              </>
            )
          }
        />
      </div>

      {/* The twelve are a briefing, not the pool. Stated HERE, at the bottom of
          Band B, because that is where the question occurs to the reader — the
          subtitle's count is the same link, but it is read before anyone knows
          how many techniques the page is going to show them. */}
      {poolHref && !emptyPool && (
        <p className="text-xs text-[var(--text-secondary)]">
          {bandA.length + bandB.length === meta.poolSize ? (
            <>Those are every technique in the pool.</>
          ) : (
            <>
              Those are{' '}
              <span className="font-semibold tabular-nums text-[var(--text-primary)]">
                {(bandA.length + bandB.length).toLocaleString()}
              </span>{' '}
              of{' '}
              {poolExact ? (
                <span className="font-semibold tabular-nums text-[var(--text-primary)]">
                  {meta.poolSize.toLocaleString()}
                </span>
              ) : (
                'the'
              )}{' '}
              techniques this sector&apos;s groups are on record using — the two bands rank the
              pool, they do not bound it.
            </>
          )}{' '}
          <Link href={poolHref} className="text-[var(--accent-teal)] hover:underline">
            {poolExact ? 'Browse the whole pool' : "Browse this sector's techniques"} →
          </Link>
        </p>
      )}

      {/*
        RECENT EVIDENCE — the bottom section.

        Ordered by LIFT, which is the entire design and was not a preference.
        Six rankings were measured against production first and every
        alternative collapsed: by CVE volume, energy and healthcare returned an
        IDENTICAL top five; by CRITICAL count, identical again; by max CVSS, 15
        techniques tie at 10.0 so the order is alphabetical; and blending lift
        with KEV or CRITICAL counts dragged energy and healthcare back to
        sharing four of five. Lift keeps them disjoint because it is the one
        column that separates all twelve sectors. The vulnerability figures are
        therefore EVIDENCE on the row and never ranking inputs — which is also
        why they are not combined into a score.

        It renders only with rows. No ICS, mobile or ATLAS technique is
        reachable through CWE/CAPEC, so on those domains the section is absent
        rather than empty — the same rule the bands use for a missing column.
      */}
      {evidence.length > 0 && (
        <Card className="p-4">
          <div className="flex flex-wrap items-baseline gap-x-2 gap-y-1">
            <h2 className="text-xs font-semibold uppercase tracking-wider text-[var(--text-secondary)]">
              Recent evidence on distinctive techniques
            </h2>
            <span className="rounded-full border border-[var(--teal-dim)] bg-[var(--teal-faint)] px-2 py-0.5 text-xs font-semibold tabular-nums text-[var(--accent-teal)]">
              {evidence.length}
            </span>
          </div>
          <p className="mt-1 text-xs leading-relaxed text-[var(--text-secondary)]">
            The techniques most disproportionately used by {sectorName}&apos;s attributed groups
            that also carry a vulnerability published in the{' '}
            <span className="font-semibold text-[var(--text-primary)]">rolling 12 months</span>.
            Ordered by lift, the only column here that separates all twelve sectors — the CVE and
            KEV figures describe each row rather than rank it.{' '}
            {evidence.length < 10 && (
              <>
                Only {evidence.length} of this sector&apos;s techniques qualify, so the list is
                short rather than padded.{' '}
              </>
            )}
            Counts are inferred along technique &rarr; CWE &rarr; CAPEC &rarr; CVE and overlap
            between rows, so they do not sum.{' '}
            {/* Said rather than silently done. Everything above this section
                narrows to the platform answer and this does not, which left the
                bands showing only SaaS techniques above a table of ten that
                carried none. Filtering here would be the other repair, and a
                worse one: this list is already cut twice (the three-group floor
                and a CVE in the window), so a narrow platform pick would empty
                it, and the claim the section makes is about the sector's groups,
                not about the estate. So it keeps its scope and states it. */}
            {platforms.length > 0 && (
              <>
                This section is <span className="font-semibold">not</span> narrowed to{' '}
                {platformList}: it ranks the sector&apos;s groups, and the bands above are where
                the platform answer applies.
              </>
            )}
          </p>

          <div className="mt-3 overflow-x-auto">
            <table className="w-full text-xs">
              <thead>
                <tr className="text-left text-[10px] uppercase tracking-wider text-[var(--text-secondary)]">
                  <th scope="col" className="py-1 pr-3 font-semibold">Lift</th>
                  <th scope="col" className="py-1 pr-3 font-semibold">Technique</th>
                  <th scope="col" className="py-1 pr-3 text-right font-semibold">KEV</th>
                  <th scope="col" className="py-1 text-right font-semibold">CVEs</th>
                </tr>
              </thead>
              <tbody>
                {evidence.map((e) => (
                  <tr key={e.attackId} className="border-t border-[var(--border-faint)]">
                    <td className="whitespace-nowrap py-1.5 pr-3 font-semibold tabular-nums text-[var(--accent-teal)]">
                      {e.lift.toFixed(2)}x
                    </td>
                    <td className="py-1.5 pr-3">
                      <EntityLink type="technique" attackId={e.attackId} name={e.name} useMap />
                    </td>
                    <td className="py-1.5 pr-3 text-right">
                      <EvidenceCount
                        attackId={e.attackId}
                        count={e.kevCount}
                        kevOnly
                        sinceIso={evidenceSinceIso}
                      />
                    </td>
                    <td className="py-1.5 text-right">
                      <EvidenceCount
                        attackId={e.attackId}
                        count={e.cveCount}
                        kevOnly={false}
                        sinceIso={evidenceSinceIso}
                      />
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>

          <p className="mt-2 text-[11px] leading-relaxed text-[var(--text-secondary)]">
            A count links to those CVEs on the vulnerability list. This is{' '}
            <span className="font-semibold text-[var(--text-primary)]">not</span> a severity
            ranking: a technique appears here because this sector&apos;s groups use it
            disproportionately and something on it was published recently, not because it is the
            most dangerous.
          </p>
        </Card>
      )}

      <Card className="p-4">
        <div className="flex flex-wrap items-baseline gap-x-2 gap-y-1">
          <h2 className="text-xs font-semibold uppercase tracking-wider text-[var(--text-secondary)]">
            Threat groups in scope
          </h2>
          <span className="rounded-full border border-[var(--teal-dim)] bg-[var(--teal-faint)] px-2 py-0.5 text-xs font-semibold tabular-nums text-[var(--accent-teal)]">
            {meta.groupCount.toLocaleString()}
          </span>
          <span className="text-xs text-[var(--text-secondary)]">
            attributed to {sectorName} in {domainLabel} — every lift figure above is computed from
            this set.
          </span>
        </div>

        {groupsShown > 0 ? (
          <>
            <div className="mt-3 flex flex-wrap gap-2">
              {groups.map((g) => (
                <EntityLink key={g.attackId} type="group" attackId={g.attackId} name={g.name} />
              ))}
            </div>
            {moreGroups > 0 && (
              <p className="mt-2 text-xs text-[var(--text-secondary)]">
                Showing the first {groupsShown} by name; {moreGroups.toLocaleString()} more are in
                scope and counted above.
              </p>
            )}
          </>
        ) : (
          <p className="mt-3 text-sm text-[var(--text-primary)]">
            No group is attributed to this sector in {domainLabel} — which means the lift figures
            above rest on an empty attribution set. Treat both bands as unsupported.
          </p>
        )}
      </Card>

      <ProfileMatrix
        sector={profile.sector}
        sectorName={profile.sectorName}
        domain={profile.domain}
        techniqueIds={[...bandA, ...bandB].map((t) => t.attackId)}
      />

      <Provenance />
    </>,
  );
}
