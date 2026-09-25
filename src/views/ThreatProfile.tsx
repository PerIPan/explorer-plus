'use client';

import { useCallback, useMemo, type ReactNode } from 'react';
import { useRouter, useSearchParams } from 'next/navigation';
import { useQuery } from '@tanstack/react-query';

import { PageHeader } from '../components/layout/PageHeader';
import { EntityLink } from '../components/shared/EntityLink';
import { DiamondLoader } from '../components/shared/FoldingDiamond';
import { ErrorState } from '../components/shared/ErrorState';
import { MultiSelect, type MultiSelectOption } from '../components/profile/MultiSelect';
// Value imports come from the zod-free shared module, NOT from ProfilePanel:
// that module also builds a picker from `SCF_FRAMEWORK_REGISTRY` (254 entries)
// and importing it here for two arrays pulled the whole registry into this
// page's bundle. `ProfileVariant` is a type-only import below, which is erased
// at compile time and costs nothing.
import { SECTOR_OPTIONS, IT_PLATFORMS, OT_PLATFORMS } from '../lib/profile-options';
import type { ProfileVariant } from '../components/profile/ProfilePanel';
import { buildProfileUrl } from '../lib/profile-url.mjs';
import {
  resolveProfileDomain,
  parsePlatforms,
  buildProfileApiQuery,
  ALL_DOMAINS,
} from '../lib/profile-query.mjs';
import { useSector } from '../contexts/SectorContext';
import { DEFAULT_DOMAIN, useDomain } from '../contexts/DomainContext';

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
  meta: {
    poolSize: number;
    groupCount: number;
    degenerate: boolean;
    bandBShort: boolean;
    platformDropped: boolean;
    /** Present ONLY on the valid, non-error "no sector chosen" response. */
    reason?: string;
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
}

const SORT_OPTIONS: readonly SortOption[] = [
  {
    value: 'lift',
    label: 'Lift',
    column: 'LIFT',
    score: 12,
    blurb: 'All twelve sectors get a different top six. This is the only column that measures sector fit rather than volume.',
  },
  {
    value: 'kev',
    label: 'KEV',
    column: 'KEV',
    score: 10,
    blurb: 'Ten of twelve sectors get a different top six.',
  },
  {
    value: 'cv',
    label: 'CVEs',
    column: 'CVE',
    score: 8,
    blurb: 'Eight of twelve sectors get a different top six.',
  },
  {
    value: 'rp',
    label: 'Reports',
    column: 'REPORTS',
    score: 2,
    blurb: 'Only two of twelve sectors get a different top six — CTI report volume is near-identical whoever you are.',
  },
  {
    value: 'io',
    label: 'Sightings',
    column: 'SIGHTINGS',
    score: 1,
    blurb: 'One of twelve. Ordering by IOC sightings collapses the twelve sectors onto the same list; this tells you what is busy, not what is aimed at you.',
  },
];

const SORT_BY_KEY: ReadonlyMap<SortKey, SortOption> = new Map(SORT_OPTIONS.map((o) => [o.value, o]));

/** Matches `sortKeySchema`'s own `.default('kev')` in app/api/v1/lib/validate.ts. */
const DEFAULT_SORT: SortKey = 'kev';

/** Amber at <=2, green at >=8 — everything between stays neutral. */
function scoreTone(score: number): { text: string; bg: string; border: string } {
  if (score <= 2) {
    return {
      text: 'text-[var(--accent-orange)]',
      bg: 'bg-[var(--orange-faint)]',
      border: 'border-[var(--orange-dim)]',
    };
  }
  if (score >= 8) {
    return {
      text: 'text-[var(--accent-green)]',
      bg: 'bg-[var(--green-faint)]',
      border: 'border-[var(--green-dim)]',
    };
  }
  return {
    text: 'text-[var(--text-secondary)]',
    bg: 'bg-[var(--hover-overlay)]',
    border: 'border-[var(--border-color)]',
  };
}

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
const KNOWN_PLATFORMS: ReadonlySet<string> = new Set<string>([...IT_PLATFORMS, ...OT_PLATFORMS]);
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
 * ──────────────────────────────────────────────────────────────────────────── */

function Card({ children, className = '' }: { children: ReactNode; className?: string }) {
  return (
    <div
      className={`bg-[var(--surface-card)] border border-[var(--border-color)] rounded-lg ${className}`.trim()}
    >
      {children}
    </div>
  );
}

function Notice({
  tone,
  title,
  children,
}: {
  tone: 'warn' | 'info';
  title: string;
  children: ReactNode;
}) {
  const styles =
    tone === 'warn'
      ? 'border-[var(--orange-dim)] bg-[var(--orange-faint)] text-[var(--accent-orange)]'
      : 'border-[var(--border-color)] bg-[var(--hover-overlay)] text-[var(--text-secondary)]';
  return (
    <div className={`rounded-lg border px-4 py-3 ${styles}`} role="note">
      <p className="text-xs font-semibold uppercase tracking-wider">{title}</p>
      <div className="mt-1 text-sm text-[var(--text-primary)]">{children}</div>
    </div>
  );
}

/**
 * One evidence cell. The label ships with every row rather than living in a
 * header the phone layout would have to drop — six labelled cells wrap
 * cleanly, a headerless six-column table does not.
 */
function Metric({
  label,
  value,
  emphasis = false,
  title,
}: {
  label: string;
  value: string;
  emphasis?: boolean;
  title?: string;
}) {
  return (
    <div className="flex flex-col items-end min-w-[3.25rem]" title={title}>
      <dt
        className={`text-[9px] font-semibold uppercase tracking-wider ${
          emphasis ? 'text-[var(--accent-teal)]' : 'text-[var(--text-secondary)]'
        }`}
      >
        {label}
      </dt>
      <dd
        className={`text-sm tabular-nums leading-tight ${
          emphasis
            ? 'font-semibold text-[var(--accent-teal)]'
            : value === '—'
              ? 'text-[var(--text-secondary)] opacity-60'
              : 'text-[var(--text-primary)]'
        }`}
      >
        {value}
      </dd>
    </div>
  );
}

function num(n: number): string {
  return n > 0 ? n.toLocaleString() : '—';
}

/** EPSS is a probability of exploitation in the next 30 days — a percentage
 *  reads more honestly than a raw 0.99999. */
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
              title="Groups attributed to this sector that use this technique. Band B requires at least three."
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
          <p className="text-[10px] font-semibold uppercase tracking-wider text-[var(--accent-teal)]">
            {eyebrow}
          </p>
          <h2 id={headingId} className="mt-0.5 text-base font-semibold text-[var(--text-primary)]">
            {title}
          </h2>
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
          not sector-specific. They say a technique is busy; they do not say it is aimed at you.
          That is exactly why they score 1/12 and 2/12 on differentiation.
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

  /** OT variant when the visitor is in the ICS domain — same split the panel makes. */
  const variant: ProfileVariant = domain === 'ics-attack' ? 'v1-6q-ot' : 'v1-4q';
  const platformOptions = useMemo<MultiSelectOption[]>(
    () =>
      (variant === 'v1-6q-ot' ? OT_PLATFORMS : IT_PLATFORMS).map((p) => ({ value: p, label: p })),
    [variant],
  );

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
            className="mt-1.5 w-full appearance-none rounded-md border border-[var(--border-color)] bg-[var(--surface-base)] px-2.5 py-1.5 text-sm text-[var(--text-primary)] focus:outline-none focus:ring-1 focus:ring-[var(--accent-teal)]"
          >
            <option value="">— none chosen —</option>
            {SECTOR_OPTIONS.map((o) => (
              <option key={o.value} value={o.value}>
                {o.label}
              </option>
            ))}
          </select>
        </div>

        <MultiSelect
          id="profile-platforms"
          label={variant === 'v1-6q-ot' ? 'OT platforms' : 'Platforms'}
          options={platformOptions}
          selected={platforms}
          onChange={onPlatformsChange}
          placeholder="Any platform"
        />
      </div>

      <fieldset className="mt-4">
        <legend className="text-[10px] font-semibold uppercase tracking-wider text-[var(--text-secondary)]">
          Rank the evidence band by
        </legend>
        <div className="mt-1.5 flex flex-wrap gap-2">
          {SORT_OPTIONS.map((o) => {
            const active = o.value === sortKey;
            const tone = scoreTone(o.score);
            return (
              <button
                key={o.value}
                type="button"
                onClick={() => navigate({ sort: o.value })}
                aria-pressed={active}
                title={o.blurb}
                className={`inline-flex items-center gap-2 rounded-md border px-2.5 py-1 text-xs transition-colors ${
                  active
                    ? 'border-[var(--accent-teal)] bg-[var(--teal-ghost)] font-semibold text-[var(--accent-teal)]'
                    : 'border-[var(--border-color)] text-[var(--text-primary)] hover:border-[var(--border-hover)]'
                }`}
              >
                {o.label}
                <span
                  className={`rounded-full border px-1.5 py-px text-[10px] font-semibold tabular-nums ${tone.text} ${tone.bg} ${tone.border}`}
                >
                  {o.score}/12
                </span>
              </button>
            );
          })}
        </div>
        <p className="mt-2 text-xs leading-relaxed text-[var(--text-secondary)]">
          <span className="font-semibold text-[var(--text-primary)]">
            {sortOption.score}/12 differentiation.
          </span>{' '}
          {sortOption.blurb} The badge counts how many of the twelve sectors get a different top six
          under that sort — it is a measure of how much the ranking distinguishes you from everyone
          else, not of how dangerous anything is.
        </p>
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

  const allDomainsNotice = allDomains ? (
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
        <Notice tone="info" title="Band A and Band B are absent, on purpose">
          <p>
            This page ranks techniques by how disproportionately{' '}
            <span className="font-semibold">your</span> sector&apos;s attributed threat groups use
            them. Without a sector there is no group set, no technique pool and no lift to rank by —
            so there is nothing here rather than a guess.
          </p>
          <p className="mt-2">
            No sector has been substituted for you — not even one you picked elsewhere in the app.
            A briefing headed &ldquo;most disproportionate for you&rdquo; over somebody else&apos;s
            sector is worse than an empty page, so this one stays empty until you choose above.
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

  return shell(
    <span>
      <span className="font-semibold text-[var(--text-primary)] tabular-nums">
        {meta.groupCount.toLocaleString()}
      </span>{' '}
      threat {meta.groupCount === 1 ? 'group' : 'groups'} attributed to this sector ·{' '}
      <span className="font-semibold text-[var(--text-primary)] tabular-nums">
        {meta.poolSize.toLocaleString()}
      </span>{' '}
      techniques in the ranked pool
      {appliedPlatforms.length > 0 && !meta.platformDropped && (
        // The assembler keeps a technique if it runs on ANY selected platform.
        // "filtered to Windows, Linux" reads as a conjunction and would mean a
        // far narrower pool than the one actually ranked.
        <> · running on any of: {platformList}</>
      )}
      {domainLine}
    </span>,
    <>
      {allDomainsNotice}

      {/* Each of these four conditions is rendered independently. They are not
          mutually exclusive — `bandBShort` is recomputed AFTER the platform
          widening, so it and `platformDropped` are routinely true together,
          and suppressing one of them left a short Band B on screen with
          nothing at all saying why. */}
      {meta.degenerate && (
        <Notice tone="warn" title="Lift cannot rank this selection">
          Fewer than six distinct lift values exist across the {meta.poolSize.toLocaleString()}{' '}
          {meta.poolSize === 1 ? 'technique' : 'techniques'} in this pool, so Band B below is ordered
          but the order is close to arbitrary. Read it as &ldquo;these are attributed to your
          sector&rdquo;, not as &ldquo;these are disproportionately aimed at you&rdquo;. Widening the
          platform filter, or dropping it, usually restores a real spread.
        </Notice>
      )}

      {meta.platformDropped && (
        <Notice tone="warn" title="Platform filter dropped">
          Fewer than six techniques cleared the three-group floor with{' '}
          {platforms.length > 0 ? platforms.join(', ') : 'the platform filter'} applied, so the{' '}
          <span className="font-semibold">whole</span> platform constraint was removed and both bands
          were re-selected over the full sector pool. The rows below are{' '}
          <span className="font-semibold">not</span> filtered to your platforms.
        </Notice>
      )}

      {meta.bandBShort && (
        <Notice tone="info" title={bandB.length === 0 ? 'Band B is empty' : 'Band B is short'}>
          Band B holds {bandB.length === 0 ? 'no technique' : `only ${bandB.length} of six`}
          {meta.platformDropped ? ', even after the platform filter was dropped' : ''}. It draws only
          from techniques attributed to at least three of this sector&apos;s groups{' '}
          <span className="font-semibold">and not already in Band A</span>, so either the pool holds
          too few that clear the three-group floor, or Band A above has taken them. A technique used
          by one or two groups is one sighting away from noise, so the floor is not lowered to pad
          the list.
        </Notice>
      )}

      <div className="grid gap-6 lg:grid-cols-2">
        <BandCard
          eyebrow="Band A · reach"
          title={`Most ${sortOption.label.toLowerCase()} evidence`}
          explain={
            <>
              Top six by <span className="font-semibold">{sortOption.column}</span> across the whole{' '}
              {sectorName} pool, with no group-count floor. This is what is loudest — reach, not
              sector fit — and at {sortOption.score}/12 differentiation it is{' '}
              {sortOption.score <= 2
                ? 'very nearly the list every other sector sees'
                : 'largely specific to this sector'}
              .
            </>
          }
          items={bandA}
          sortKey={sortKey}
          showLift={false}
          empty={<>No technique in this pool carries any {sortOption.column.toLowerCase()} evidence.</>}
        />

        <BandCard
          eyebrow="Band B · sector fit"
          title={`Most disproportionate for ${sectorName}`}
          explain={
            <>
              Top six by <span className="font-semibold">lift</span> among techniques attributed to
              at least three of this sector&apos;s groups, with Band A excluded. Always lift-ranked —
              the selector above changes Band A only.
            </>
          }
          items={bandB}
          sortKey={sortKey}
          showLift
          empty={
            <>
              <span className="font-semibold">Band B is absent.</span> Nothing in this pool is both
              attributed to at least three of {sectorName}&apos;s groups and absent from Band A, so
              there is nothing that can honestly be called disproportionately aimed at this sector.
              Nothing has been substituted in its place.
            </>
          }
        />
      </div>

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

      <Provenance />
    </>,
  );
}
