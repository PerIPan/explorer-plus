'use client';

import { useCallback, useMemo, type ReactNode } from 'react';
import Link from 'next/link';
import { useRouter, useSearchParams } from 'next/navigation';
import { useQuery } from '@tanstack/react-query';

import { PageHeader } from '../components/layout/PageHeader';
import { Badge } from '../components/shared/Badge';
import { EntityLink } from '../components/shared/EntityLink';
import { DiamondLoader } from '../components/shared/FoldingDiamond';
import { ErrorState } from '../components/shared/ErrorState';
import { Card, Notice, Metric, num } from '../components/profile/BriefingPrimitives';
import { PurdueAssetPickerLoader } from '../components/profile/PurdueAssetPicker';
import { buildProfileUrl } from '../lib/profile-url.mjs';
import { buildProfileApiQuery, parseCsvParam } from '../lib/profile-query.mjs';
import { levelDisplay } from '../lib/profile-ot.mjs';

/* ════════════════════════════════════════════════════════════════════════════
 * The OT (ICS) briefing.
 *
 * A different page from the IT briefing, not a variant of it, because the
 * engine behind it ranks on something else entirely. ATT&CK for ICS models
 * ASSETS (A0001-A0018), which this repo places on the Purdue model, and the
 * engine ranks techniques by how much of the visitor's own asset surface each
 * one reaches. There is no sector, no platform filter and no evidence column —
 * see `DetectionAbsence` below, which is a requirement of this page and not a
 * disclaimer.
 *
 * Reached from `/profile?domain=ics-attack`. src/views/ThreatProfile.tsx routes
 * here on the domain alone.
 * ════════════════════════════════════════════════════════════════════════════ */

/* ────────────────────────────────────────────────────────────────────────────
 * Wire types — mirrors the OT branch of app/api/v1/profile/route.ts
 * ──────────────────────────────────────────────────────────────────────────── */

/**
 * A ranked OT technique. A strict SUPERSET of the IT band item: `iocs`,
 * `reports`, `cveCount`, `kevCount` and `maxEpss` ride along as the measured
 * ZEROES they are for every live ICS technique, so a shared row renderer
 * cannot crash on them. This page does not render them — see `DetectionAbsence`
 * for why showing five permanent zeroes would be worse than saying so once.
 */
interface OtBandItem {
  attackId: string;
  name: string;
  /** Assets in YOUR selection that this technique targets. */
  exposure: number;
  /** Assets in the whole ATT&CK ICS catalogue that it targets. */
  reach: number;
  lift: number;
  groupCount: number;
  mitigationCount: number;
  d3fendCount: number;
}

/** An Impact technique. No exposure, no reach, no lift — it has no asset rows
 *  at all, which is exactly why it is listed unranked. */
interface OtImpactItem {
  attackId: string;
  name: string;
  tactics: string[];
  mitigationCount: number;
  d3fendCount: number;
}

interface EffectiveAsset {
  attackId: string;
  name: string;
  primaryLevel: string;
  spansLevels: string[];
  isBoundary: boolean;
}

/** `meta.reason` — four distinct visitor-facing states that must NOT collapse
 *  into one message. `null` is the ordinary ranked briefing. */
type OtReason = 'no-assets' | 'empty-selection' | 'degenerate-lift' | null;

interface OtProfileResponse {
  profile: {
    domain: string;
    assets: string[] | null;
    levels: string[] | null;
    sector: string | null;
    platforms: string[] | null;
    sort: 'exposure';
  };
  bandA: OtBandItem[];
  bandB: OtBandItem[];
  impact: OtImpactItem[];
  effectiveAssets: EffectiveAsset[];
  meta: {
    poolSize: number;
    assetCount: number;
    totalAssets: number;
    degenerate: boolean;
    bandBShort: boolean;
    bandBSuppressed: boolean;
    subTechniquesExcluded: boolean;
    minReach: number;
    ignoredParams: string[];
    reason: OtReason;
    reasonDetail: string | null;
  };
}

const ENDPOINT = '/api/v1/profile';
const ICS_DOMAIN = 'ics-attack';

class OtRequestError extends Error {
  readonly status: number;
  constructor(status: number, message: string) {
    super(message);
    this.name = 'OtRequestError';
    this.status = status;
  }
}

async function fetchOtProfile(search: string): Promise<OtProfileResponse> {
  const res = await fetch(search ? `${ENDPOINT}?${search}` : ENDPOINT);
  if (!res.ok) {
    const body = (await res.json().catch(() => null)) as { error?: string } | null;
    throw new OtRequestError(res.status, body?.error ?? `HTTP ${res.status}`);
  }
  return (await res.json()) as OtProfileResponse;
}

/* ────────────────────────────────────────────────────────────────────────────
 * The honesty block this page cannot ship without
 * ──────────────────────────────────────────────────────────────────────────── */

/**
 * Why this briefing's columns differ from the IT one's.
 *
 * Rendered UNCONDITIONALLY, in every state including the empty ones. An OT
 * visitor who sees no Sightings, no Reports, no KEV and no EPSS column will
 * otherwise reach one of two conclusions, and both are wrong: that their
 * selection was too narrow to turn anything up, or that their plant is
 * un-monitorable. The truth is neither — ATT&CK for ICS carries none of those
 * signals for ANY technique, however wide the selection.
 *
 * Measured against production 2026-09-26 over the 97 live ICS techniques: IOC
 * sightings 0, CTI report mentions 0, CVE evidence 0, KEV 0, EPSS 0 (the single
 * ICS row in `technique_cve_evidence` is T0812, which is revoked). What ICS
 * DOES carry is defensive mapping: 96 of 97 techniques have at least one
 * mitigation and 65 have a D3FEND countermeasure — so those two columns are
 * real data, not filler put where the evidence strip used to be.
 */
function DetectionAbsence() {
  return (
    <Notice tone="info" title="Why there are no detection columns here">
      <p>
        <span className="font-semibold">ATT&amp;CK for ICS carries no detection evidence at all</span>{' '}
        — no Sigma rules, no IOC sightings, no CTI report mentions, no KEV entries and no EPSS
        scores, for any of the 97 live ICS techniques. Not for this selection: for every selection.
        Those columns are absent because the dataset is silent, not because you chose narrowly, and
        not because your plant cannot be monitored.
      </p>
      <p className="mt-2">
        What ICS does carry is defensive mapping, so that is what this page ranks alongside your
        exposure: <span className="font-semibold">96 of 97</span> ICS techniques have at least one
        ATT&amp;CK mitigation and <span className="font-semibold">65</span> have a D3FEND
        countermeasure.
      </p>
    </Notice>
  );
}

/* ────────────────────────────────────────────────────────────────────────────
 * Rows and cards
 * ──────────────────────────────────────────────────────────────────────────── */

function OtTechniqueRow({
  rank,
  item,
  assetCount,
  totalAssets,
  emphasis,
}: {
  rank: number;
  item: OtBandItem;
  assetCount: number;
  totalAssets: number;
  /** Which of the two ranking figures this band is ordered by. */
  emphasis: 'exposure' | 'lift';
}) {
  return (
    <li className="flex flex-col gap-2 px-4 py-3 border-t border-[var(--border-faint)] sm:flex-row sm:items-center sm:justify-between sm:gap-4">
      <div className="flex min-w-0 items-center gap-2">
        <span className="w-4 shrink-0 text-xs tabular-nums text-[var(--text-secondary)]">{rank}</span>
        <EntityLink type="technique" attackId={item.attackId} name={item.name} />
        {/* Context, never a ranking input: the OT engine floors Band B on
            `reach`, not on group attribution. 37 of the 97 live ICS techniques
            do carry a named group, and hiding that would be its own kind of
            lie — but it is not what put this row here. */}
        {item.groupCount > 0 && (
          <Badge
            label={`${item.groupCount} ${item.groupCount === 1 ? 'group' : 'groups'}`}
            variant="neutral"
            className="shrink-0"
          />
        )}
      </div>

      <dl className="flex flex-wrap items-start gap-x-4 gap-y-2 sm:shrink-0 sm:justify-end">
        <Metric
          label="Exposure"
          value={`${item.exposure}/${assetCount}`}
          emphasis={emphasis === 'exposure'}
          title={`This technique targets ${item.exposure} of the ${assetCount} assets you selected. Across all ${totalAssets} ATT&CK ICS assets it targets ${item.reach} — that wider figure is its reach, and lift is the ratio of the two.`}
        />
        <Metric
          label="Lift"
          value={`${item.lift.toFixed(2)}x`}
          emphasis={emphasis === 'lift'}
          title={`How concentrated this technique is on YOUR surface rather than the ICS catalogue as a whole: (${item.exposure}/${assetCount}) ÷ (${item.reach}/${totalAssets}). 1.00x means it reaches your plant no more than it reaches any plant.`}
        />
        <Metric
          label="Mitigations"
          value={num(item.mitigationCount)}
          title="ATT&CK mitigations published for this technique. 96 of the 97 live ICS techniques have at least one."
        />
        <Metric
          label="D3FEND"
          value={num(item.d3fendCount)}
          title="Distinct D3FEND countermeasures mapped to this technique. 65 of the 97 live ICS techniques have at least one."
        />
      </dl>
    </li>
  );
}

function OtBandCard({
  eyebrow,
  title,
  explain,
  items,
  assetCount,
  totalAssets,
  emphasis,
  empty,
}: {
  eyebrow: string;
  title: string;
  explain: ReactNode;
  items: OtBandItem[];
  assetCount: number;
  totalAssets: number;
  emphasis: 'exposure' | 'lift';
  empty: ReactNode;
}) {
  const headingId = `ot-band-${emphasis}`;
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
              <OtTechniqueRow
                key={item.attackId}
                rank={i + 1}
                item={item}
                assetCount={assetCount}
                totalAssets={totalAssets}
                emphasis={emphasis}
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
 * The unranked Impact panel. NOT optional, and not a footnote.
 *
 * These twelve techniques are the entire Impact tactic for ICS — Loss of
 * Safety, Loss of Control, Loss of View, Damage to Property, Denial of Control
 * among them — and MITRE maps none of them to an asset, because a consequence
 * is not something a device exposes. Measured: 12 live ICS techniques have no
 * `asset_techniques` row at all. So exposure ranking can never surface one,
 * however wide the selection, and a page that only ever showed ranked bands
 * would omit precisely what a plant operator cares about most while looking
 * complete.
 *
 * Rendered separately and visibly unranked — no rank numbers, no exposure, no
 * lift, ATT&CK id order — and framed as consequences rather than entry points.
 * Mitigation and D3FEND counts are shown because those are real for these
 * techniques and are the only actionable thing on the row.
 */
function ImpactPanel({ items }: { items: OtImpactItem[] }) {
  if (items.length === 0) return null;
  return (
    <Card className="border-[var(--orange-dim)]">
      <section aria-labelledby="ot-impact">
        <div className="px-4 py-3">
          <p className="text-[10px] font-semibold uppercase tracking-wider text-[var(--accent-orange)]">
            Unranked · consequences
          </p>
          <h2 id="ot-impact" className="mt-0.5 text-base font-semibold text-[var(--text-primary)]">
            What a compromise costs you
          </h2>
          <p className="mt-1 text-xs leading-relaxed text-[var(--text-secondary)]">
            The {items.length} techniques of the ICS{' '}
            <span className="font-semibold text-[var(--text-primary)]">Impact</span> tactic. They are{' '}
            <span className="font-semibold text-[var(--text-primary)]">deliberately unranked</span>:
            MITRE maps none of them to an asset — a consequence is not something a device exposes —
            so exposure ranking can never reach them, whatever you select above. Their absence from
            the bands is not a judgement that they are unlikely. These are the outcomes the bands are
            routes to.
          </p>
        </div>
        <ul>
          {items.map((item) => (
            <li
              key={item.attackId}
              className="flex flex-col gap-2 px-4 py-3 border-t border-[var(--border-faint)] sm:flex-row sm:items-center sm:justify-between sm:gap-4"
            >
              <div className="flex min-w-0 items-center gap-2">
                <EntityLink type="technique" attackId={item.attackId} name={item.name} />
                {item.tactics.map((t) => (
                  <Badge key={t} label={t} variant="orange" className="shrink-0" />
                ))}
              </div>
              <dl className="flex flex-wrap items-start gap-x-4 gap-y-2 sm:shrink-0 sm:justify-end">
                <Metric
                  label="Mitigations"
                  value={num(item.mitigationCount)}
                  title="ATT&CK mitigations published for this technique."
                />
                <Metric
                  label="D3FEND"
                  value={num(item.d3fendCount)}
                  title="Distinct D3FEND countermeasures mapped to this technique."
                />
              </dl>
            </li>
          ))}
        </ul>
      </section>
    </Card>
  );
}

/**
 * What the selection actually resolved to, as the ENGINE resolved it.
 *
 * The picker shows its own client-side expansion while you are choosing; this
 * is the authoritative set that came back with the ranking, and the two are
 * shown separately on purpose — if they ever disagree, the page says what was
 * ranked rather than what was asked for.
 */
function EffectiveAssetsCard({
  assets,
  totalAssets,
  levels,
}: {
  assets: EffectiveAsset[];
  totalAssets: number;
  levels: string[];
}) {
  const boundary = assets.filter((a) => a.isBoundary);
  return (
    <Card className="p-4">
      <div className="flex flex-wrap items-baseline gap-x-2 gap-y-1">
        <h2 className="text-xs font-semibold uppercase tracking-wider text-[var(--text-secondary)]">
          The surface being ranked
        </h2>
        <span className="rounded-full border border-[var(--teal-dim)] bg-[var(--teal-faint)] px-2 py-0.5 text-xs font-semibold tabular-nums text-[var(--accent-teal)]">
          {assets.length} of {totalAssets}
        </span>
        {boundary.length > 0 && (
          <span className="text-xs text-[var(--text-secondary)]">
            <span className="font-semibold text-[var(--accent-yellow)] tabular-nums">
              {boundary.length}
            </span>{' '}
            boundary {boundary.length === 1 ? 'asset' : 'assets'} — where IT and OT cross
          </span>
        )}
      </div>

      {levels.length > 0 && (
        <p className="mt-2 text-xs leading-relaxed text-[var(--text-secondary)]">
          {/* The expansion, stated after the fact as well as during the choice.
              Picking a level is one click that selects up to eight assets, and
              this is the list it came to. */}
          You picked{' '}
          <span className="font-semibold text-[var(--text-primary)]">
            {levels.map(levelDisplay).join(', ')}
          </span>
          , which {levels.length === 1 ? 'resolves' : 'resolve'} to the{' '}
          <span className="tabular-nums">{assets.length}</span> assets below. An asset present at
          more than one level you picked is counted once — the count is what divides every lift
          figure above, so a double count would scale all of them.
        </p>
      )}

      <ul className="mt-3 flex flex-col gap-1.5">
        {assets.map((a) => (
          <li key={a.attackId} className="flex flex-wrap items-center gap-2 text-sm">
            <Link
              href={`/assets/${a.attackId}`}
              className="text-[var(--accent-teal)] hover:underline"
            >
              {a.name}
            </Link>
            <span className="text-[11px] text-[var(--text-secondary)]">
              {a.spansLevels.map(levelDisplay).join(' · ')}
            </span>
            {a.isBoundary && <Badge label="boundary" variant="yellow" />}
          </li>
        ))}
      </ul>
    </Card>
  );
}

/** The OT provenance block. Different claims from the IT one, so a different
 *  block — nothing here comes from group attribution or CVE inference. */
function OtProvenance({ minReach }: { minReach: number }) {
  return (
    <Card className="p-4">
      <h2 className="text-xs font-semibold uppercase tracking-wider text-[var(--text-secondary)]">
        Where these numbers come from
      </h2>
      <ul className="mt-2 space-y-2 text-xs leading-relaxed text-[var(--text-secondary)]">
        <li>
          <span className="font-semibold text-[var(--text-primary)]">
            Purdue placement is curated, not published by MITRE.
          </span>{' '}
          ATT&amp;CK names the 18 ICS assets; which Purdue level each sits at — and which levels it
          spans — is this project&apos;s reading of NIST SP 800-82r3 and ISA-95. Selecting a level is
          therefore trusting that reading, and every asset it resolved to is listed above so you can
          check it.
        </li>
        <li>
          <span className="font-semibold text-[var(--text-primary)]">Exposure is a count</span> of
          your selected assets that a technique targets, straight from
          ATT&amp;CK&apos;s own asset mappings. It is valid at any selection size.{' '}
          <span className="font-semibold text-[var(--text-primary)]">Lift is a ratio</span> and is
          not: selecting most of the catalogue makes exposure and reach move together and collapses
          every lift toward 1.00x, which is why Band B is suppressed rather than shown meaningless.
        </li>
        <li>
          <span className="font-semibold text-[var(--text-primary)]">
            Sub-techniques are excluded from the pool.
          </span>{' '}
          In ICS a sub-technique&apos;s asset mappings are identical to its parent&apos;s, so it adds
          nothing to an engine whose only signal is that mapping — and without the exclusion one
          finding fills four of six Band B slots as a parent plus its three children, all tied.
          Band B also requires a reach of at least {minReach}, so a single asset mapping cannot mint
          a top-six entry at maximum lift.
        </li>
        <li>
          <span className="font-semibold text-[var(--text-primary)]">
            Sector and platform are not used, and could not be.
          </span>{' '}
          Per-sector ICS technique counts are an artefact of automated group attribution rather than
          OT exposure — technology and government outrank energy and manufacturing, and
          transportation has none at all — and every live ICS technique carries the literal platform
          &lsquo;None&rsquo; or no platform at all. Neither question is asked here because neither
          answer could change this ranking.
        </li>
      </ul>
    </Card>
  );
}

/* ────────────────────────────────────────────────────────────────────────────
 * The view
 * ──────────────────────────────────────────────────────────────────────────── */

export function OtProfile() {
  const router = useRouter();
  const searchParams = useSearchParams();

  /**
   * Read strictly from the URL, like the IT briefing does — and note the param
   * name: the page URL carries `purdue_levels`, the API takes `levels`. The
   * translation lives in `buildProfileApiQuery`. `levels` is accepted as an
   * alias on the way IN so an API-shaped URL pasted into the address bar still
   * resolves to the same briefing instead of silently ranking nothing.
   */
  const rawAssets = searchParams.get('assets');
  const rawLevels = searchParams.get('purdue_levels') ?? searchParams.get('levels');

  const assets = useMemo(() => parseCsvParam(rawAssets), [rawAssets]);
  const levels = useMemo(() => parseCsvParam(rawLevels), [rawLevels]);

  const apiSearch = useMemo(
    () => buildProfileApiQuery({ assets, levels, domain: ICS_DOMAIN }),
    [assets, levels],
  );

  const { data, isPending, error, refetch } = useQuery({
    queryKey: ['ot-profile', apiSearch],
    queryFn: () => fetchOtProfile(apiSearch),
    retry: (failureCount, err) =>
      !(err instanceof OtRequestError && err.status >= 400 && err.status < 500) && failureCount < 2,
  });

  /**
   * Rewrite the URL from the two parameters this page owns, through the same
   * tested builder Apply uses. Built fresh rather than patched onto the current
   * query string, so `domain` is written unconditionally — on `/profile` an
   * absent domain is no filter at all, which would rank enterprise, mobile, ICS
   * and ATLAS techniques together under a plant heading.
   */
  const navigate = useCallback(
    (next: { assets?: string[]; levels?: string[] }) => {
      router.replace(
        buildProfileUrl({
          sector: null,
          domain: ICS_DOMAIN,
          params: {
            assets: next.assets ?? assets,
            purdue_levels: next.levels ?? levels,
          },
        }),
        { scroll: false },
      );
    },
    [router, assets, levels],
  );

  /* ── Controls, rendered in every state including the failures, so a bad
   *    parameter is always one click away from being fixed. ──────────────── */
  const controls = (
    <Card className="p-4">
      <PurdueAssetPickerLoader
        id="ot-profile-plant"
        selectedAssets={assets}
        selectedLevels={levels}
        onAssetsChange={(next) => navigate({ assets: next })}
        onLevelsChange={(next) => navigate({ levels: next })}
      />
      <p className="mt-3 text-xs text-[var(--text-secondary)]">
        Asking about the corporate network instead?{' '}
        <button
          type="button"
          onClick={() => router.push(buildProfileUrl({ sector: null, domain: 'enterprise-attack' }))}
          className="font-semibold text-[var(--accent-teal)] underline underline-offset-2 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[var(--accent-teal)] rounded"
        >
          Switch to the IT estate briefing
        </button>
        , which ranks ATT&amp;CK Enterprise on your sector and platforms.
      </p>
    </Card>
  );

  const shell = (subtitle: ReactNode, body: ReactNode) => (
    <div className="space-y-6">
      <PageHeader
        title="Threat profile — OT plant"
        subtitle={subtitle}
        breadcrumb={[{ label: 'Threat profile' }]}
      />
      {controls}
      {body}
    </div>
  );

  /* ── Failure states ───────────────────────────────────────────────────── */

  if (error) {
    const err = error instanceof OtRequestError ? error : null;

    if (err && err.status === 400) {
      // The only two things this page can put in the query, so the only two it
      // can be blamed for. Bounded rather than guessed: asset ids are
      // A0001-A0018 and level keys are the seven `purdue_levels.level_key`
      // values, both enforced by the API's own schema.
      const badAssets = assets.filter((a) => !/^A00(0[1-9]|1[0-8])$/.test(a));
      const badLevels = levels.filter(
        (l) => !['l0', 'l1', 'l2', 'l3', 'l3_5', 'l4', 'l5'].includes(l),
      );
      return shell(
        'The API rejected this request — nothing was ranked.',
        <>
          <Notice tone="warn" title="Invalid OT profile query (HTTP 400)">
            <p>
              Nothing below is a finding. The request never reached the ranking engine, so an empty
              page here would mean &ldquo;we could not ask&rdquo; — never &ldquo;nothing reaches your
              plant&rdquo;.
            </p>
            <ul className="mt-2 list-disc space-y-1 pl-5">
              {badAssets.map((a) => (
                <li key={a}>
                  <code className="font-mono text-xs">{a}</code> is not an ATT&amp;CK ICS asset.
                  There are eighteen, A0001 to A0018.
                </li>
              ))}
              {badLevels.map((l) => (
                <li key={l}>
                  <code className="font-mono text-xs">{l}</code> is not a Purdue level key.
                </li>
              ))}
              {badAssets.length === 0 && badLevels.length === 0 && (
                <li>
                  The rejected parameter is not one this page can identify. The API said:{' '}
                  <span className="italic">{err.message}</span>
                </li>
              )}
            </ul>
            <p className="mt-2">Pick a level or an asset above and the briefing will load.</p>
          </Notice>
          <DetectionAbsence />
        </>,
      );
    }

    return shell(
      'The briefing could not be loaded.',
      <ErrorState
        message={`Could not load the OT threat profile — ${err ? `HTTP ${err.status}: ` : ''}${
          error instanceof Error ? error.message : 'request failed'
        }`}
        onRetry={() => void refetch()}
      />,
    );
  }

  /* ── Pending ──────────────────────────────────────────────────────────── */

  if (isPending || !data) {
    return shell(
      <span>Ranking your plant surface… · ATT&amp;CK for ICS</span>,
      <Card className="py-8">
        <DiamondLoader text="Ranking techniques..." />
      </Card>,
    );
  }

  const { bandA, bandB, impact, effectiveAssets, meta } = data;
  const { assetCount, totalAssets, reason } = meta;

  /* ── The two empty states, which must NOT read alike ──────────────────── */

  if (reason === 'no-assets' || reason === 'empty-selection') {
    const chose = reason === 'empty-selection';
    return shell(
      <span>
        {chose ? 'That selection holds no ATT&CK ICS asset.' : 'Nothing selected — nothing ranked.'}{' '}
        · ATT&amp;CK for ICS
      </span>,
      <>
        <Notice
          tone={chose ? 'warn' : 'info'}
          title={chose ? 'That level carries no assets' : 'Nothing has been ranked, on purpose'}
        >
          {chose ? (
            <>
              <p>
                {meta.reasonDetail ??
                  'The selected Purdue levels carry no ATT&CK assets, so there is no surface to rank against.'}
              </p>
              <p className="mt-2">
                This is an honest absence rather than missing data: MITRE publishes assets for the
                ICS domain alone, so Enterprise IT genuinely has none. If the corporate network is
                what you meant, the IT estate briefing is the one that covers it.
              </p>
            </>
          ) : (
            <>
              <p>
                This briefing ranks ICS techniques by how much of{' '}
                <span className="font-semibold">your</span> plant each one reaches. With no level and
                no asset chosen there is no surface, no exposure and nothing to rank — so there is
                nothing here rather than a guess.
              </p>
              <p className="mt-2">
                Nothing has been selected for you. An empty selection is not treated as &ldquo;all
                eighteen assets&rdquo;, which would hand someone asking about one cell a briefing for
                a whole plant.
              </p>
            </>
          )}
        </Notice>

        <DetectionAbsence />

        {/* The Impact tactic does not depend on the selection — it has no asset
            rows to depend on it — so it is shown even here. It is the one part
            of this page that is true before you have answered anything. */}
        <ImpactPanel items={impact} />

        <OtProvenance minReach={meta.minReach} />
      </>,
    );
  }

  /* ── The briefing ─────────────────────────────────────────────────────── */

  return shell(
    <span>
      <span className="font-semibold text-[var(--text-primary)] tabular-nums">{assetCount}</span> of{' '}
      <span className="tabular-nums">{totalAssets}</span> ATT&amp;CK ICS assets selected ·{' '}
      <span className="font-semibold text-[var(--text-primary)] tabular-nums">
        {meta.poolSize.toLocaleString()}
      </span>{' '}
      techniques in the ranked pool · ATT&amp;CK for ICS
    </span>,
    <>
      <DetectionAbsence />

      {meta.bandBSuppressed && (
        <Notice tone="warn" title="Lift cannot rank this selection">
          <p>
            {meta.reasonDetail ??
              'Every technique in this pool has the same lift, or nearly so, so Band B is suppressed.'}
          </p>
          <p className="mt-2">
            Band B is <span className="font-semibold">absent, not empty</span>: a lift ordering that
            means nothing would still look like a ranking. Band A below is unaffected — exposure is
            a count, not a ratio, and stays valid at any selection size.
          </p>
        </Notice>
      )}

      {meta.bandBShort && !meta.bandBSuppressed && (
        <Notice tone="info" title={bandB.length === 0 ? 'Band B is empty' : 'Band B is short'}>
          Band B holds {bandB.length === 0 ? 'no technique' : `only ${bandB.length} of six`}. It
          draws only from techniques that reach at least {meta.minReach} ICS assets{' '}
          <span className="font-semibold">and are not already in Band A</span>. A technique with a
          single asset mapping would score maximum lift on a narrow selection while telling you
          almost nothing, so the floor is not lowered to pad the list.
        </Notice>
      )}

      <div className="grid gap-6 lg:grid-cols-2">
        <OtBandCard
          eyebrow="Band A · exposure"
          title="Reaches most of what you run"
          explain={
            <>
              Top six by <span className="font-semibold">EXPOSURE</span> — how many of your{' '}
              {assetCount} selected assets each technique targets. This is the only ordering this
              page offers, because on the OT path Band A <span className="font-semibold">is</span>{' '}
              exposure: there is no evidence column to sort by instead.
            </>
          }
          items={bandA}
          assetCount={assetCount}
          totalAssets={totalAssets}
          emphasis="exposure"
          empty={
            <>
              No ICS technique targets any of the assets you selected. Nothing has been substituted
              in its place.
            </>
          }
        />

        <OtBandCard
          eyebrow="Band B · concentration"
          title="Aimed at your surface more than at ICS generally"
          explain={
            <>
              Top six by <span className="font-semibold">LIFT</span>, among techniques reaching at
              least {meta.minReach} assets, with Band A excluded. Lift compares the share of{' '}
              <span className="font-semibold">your</span> surface a technique reaches against the
              share of all {totalAssets} ICS assets it reaches — 1.00x means it is no more
              concentrated on your plant than on anyone&apos;s.
            </>
          }
          items={bandB}
          assetCount={assetCount}
          totalAssets={totalAssets}
          emphasis="lift"
          empty={
            meta.bandBSuppressed ? (
              <>
                <span className="font-semibold">Band B is suppressed.</span> Lift cannot separate
                this selection — see the notice above. Nothing has been ranked in its place.
              </>
            ) : (
              <>
                <span className="font-semibold">Band B is absent.</span> Nothing in this pool both
                reaches at least {meta.minReach} assets and is missing from Band A, so there is
                nothing that can honestly be called disproportionately aimed at your surface.
              </>
            )
          }
        />
      </div>

      <EffectiveAssetsCard
        assets={effectiveAssets}
        totalAssets={totalAssets}
        levels={levels}
      />

      <ImpactPanel items={impact} />

      <OtProvenance minReach={meta.minReach} />
    </>,
  );
}
