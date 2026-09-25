// src/lib/profile-ot.mjs — pure, no React, no DOM. Tested by
// scripts/lib/profile-ot.test.mjs.
//
// The OT selection model: how a visitor's Purdue-level and asset answers
// resolve into the effective asset set the ranking engine is called with, and
// how that resolution is DESCRIBED back to them.
//
// It is a module rather than inline view code for the same reason
// src/lib/profile-url.mjs is: the rules here are correctness requirements with
// measured consequences, not formatting. Two of them in particular:
//
//   1. Level membership is `spans_levels` overlap, NEVER `primary_level`.
//      Measured on production 2026-09-26: `primary_level = 'l3'` is three
//      assets (A0006, A0008, A0014); `spans_levels && ARRAY['l3']` is seven
//      (A0001, A0006, A0008, A0009, A0014, A0015, A0016). Naive matching drops
//      over half the real L3 surface, including the boundary assets someone
//      asking about L3 most cares about. app/api/v1/profile/route.ts does the
//      overlap form in SQL; this is the client-side mirror of it, and the two
//      MUST agree or the picker would promise a set the engine does not rank.
//
//   2. Selection is DE-DUPLICATED, because the count feeds the lift
//      denominator. Measured: l2 holds 7 assets and l3 holds 7, but l2+l3 is
//      10 distinct, not 14 — A0001, A0009, A0014 and A0015 span both.
//
// And one honesty requirement, which is why `describeSelection` exists at all:
// selecting a level quietly resolves to assets the label does not name (L3 ->
// seven, four of them not obvious from "Site Operations"). Silent expansion is
// as dishonest as a silent default, so the view is given the material to show
// what a level actually resolved to.

/**
 * A Purdue level, as `GET /api/v1/frameworks/purdue` returns it.
 *
 * @typedef {Object} PurdueLevel
 * @property {string} levelKey
 * @property {string} label
 * @property {'ot' | 'dmz' | 'it'} zone
 * @property {string} description
 * @property {number} sortOrder
 */

/**
 * An ATT&CK ICS asset with its curated Purdue placement, as that same endpoint
 * returns it.
 *
 * @typedef {Object} PlacedAsset
 * @property {string} attackId
 * @property {string} name
 * @property {string} primaryLevel
 * @property {string[]} spansLevels
 * @property {boolean} isBoundary
 */

/**
 * Zone display order and labels.
 *
 * Plant floor first. An OT defender reads their network from the process
 * outward, and the zone that decides whether a breach moves physical things is
 * the one to lead with — the same reasoning src/views/PurdueModel.tsx gives for
 * its zone colours.
 */
export const OT_ZONE_ORDER = /** @type {const} */ (['ot', 'dmz', 'it']);

/** @type {Record<string, { label: string; blurb: string }>} */
export const OT_ZONE_META = {
  ot: {
    label: 'OT — plant floor',
    blurb: 'Where a compromise moves physical things.',
  },
  dmz: {
    label: 'DMZ — the enforced buffer',
    blurb: 'All external access terminates here; DMZ hosts must not initiate into OT.',
  },
  it: {
    label: 'IT — business network',
    blurb: 'Site business systems, and the corporate network above them.',
  },
};

/**
 * The level's display key: `l3_5` -> `L3.5`, `l0` -> `L0`.
 *
 * Purdue levels are spoken as numbers ("we terminate everything at three and a
 * half"), and `l3_5` is a database key, not a thing anyone says. Derived rather
 * than tabled so a new level key needs no second edit here.
 *
 * @param {string} levelKey
 * @returns {string}
 */
export function levelDisplay(levelKey) {
  return `L${String(levelKey).replace(/^l/, '').replace('_', '.')}`;
}

/**
 * Assets present at one level.
 *
 * `spansLevels` overlap, not `primaryLevel` — see rule 1 in the header. An
 * asset that spans four levels is returned at all four, which is correct: the
 * question a level row answers is "what is exposed here?", not "what is filed
 * here?".
 *
 * @param {readonly PlacedAsset[]} assets
 * @param {string} levelKey
 * @returns {PlacedAsset[]}
 */
export function assetsAtLevel(assets, levelKey) {
  return assets.filter((a) => Array.isArray(a.spansLevels) && a.spansLevels.includes(levelKey));
}

/**
 * The picker's tree: zones in `OT_ZONE_ORDER`, levels within a zone by
 * `sortOrder`, assets within a level by `attackId`.
 *
 * Every level is returned, INCLUDING the ones that hold no asset. A level with
 * an empty `assets` array is not a level to hide — `l5` (Enterprise IT) is
 * measured at zero, and the visitor who is looking for their enterprise network
 * needs to be told that ATT&CK places no ICS asset there, not left wondering
 * where the row went. The view renders it disabled with that sentence; it must
 * never be a live option, because selecting it can only ever produce the
 * engine's `empty-selection` state.
 *
 * @param {readonly PurdueLevel[]} levels
 * @param {readonly PlacedAsset[]} assets
 * @returns {Array<{ zone: string; label: string; blurb: string;
 *                   levels: Array<PurdueLevel & { assets: PlacedAsset[] }> }>}
 */
export function groupLevelsByZone(levels, assets) {
  const groups = [];
  for (const zone of OT_ZONE_ORDER) {
    const inZone = levels
      .filter((l) => l.zone === zone)
      .sort((a, b) => a.sortOrder - b.sortOrder)
      .map((l) => ({
        ...l,
        assets: assetsAtLevel(assets, l.levelKey).sort((a, b) => a.attackId.localeCompare(b.attackId)),
      }));
    if (inZone.length === 0) continue;
    const meta = OT_ZONE_META[zone] ?? { label: zone.toUpperCase(), blurb: '' };
    groups.push({ zone, label: meta.label, blurb: meta.blurb, levels: inZone });
  }
  return groups;
}

/**
 * Resolve a selection to its effective asset set: explicit asset picks UNION
 * every asset overlapping a picked level, DISTINCT, in `attackId` order.
 *
 * This is the client-side mirror of `EFFECTIVE_ASSETS_SQL` in
 * app/api/v1/profile/route.ts. The view uses it to decide whether Apply is
 * allowed and to show what the selection came to BEFORE navigating; the
 * authoritative set still comes back from the API as `effectiveAssets`, and the
 * page renders that one.
 *
 * @param {readonly PlacedAsset[]} assets every live placed asset
 * @param {readonly string[]} selectedAssets explicitly ticked asset ids
 * @param {readonly string[]} selectedLevels ticked level keys
 * @returns {PlacedAsset[]}
 */
export function resolveEffectiveAssets(assets, selectedAssets, selectedLevels) {
  const explicit = new Set(selectedAssets);
  const levels = new Set(selectedLevels);
  return assets
    .filter(
      (a) =>
        explicit.has(a.attackId) ||
        (Array.isArray(a.spansLevels) && a.spansLevels.some((l) => levels.has(l))),
    )
    .sort((a, b) => a.attackId.localeCompare(b.attackId));
}

/**
 * Everything the view needs to SHOW the resolution rather than perform it
 * silently.
 *
 * `overlapDropped` is the honest version of the de-duplication: picking L2 and
 * L3 is 14 level memberships and 10 distinct assets, and a visitor who sees
 * "7 + 7" and then "10" deserves to be told why rather than left to assume
 * something was lost. `viaLevels` carries, per picked level, exactly which
 * assets that one word resolved to — the four non-obvious L3 members are the
 * whole reason this field exists.
 *
 * @param {readonly PlacedAsset[]} assets
 * @param {readonly string[]} selectedAssets
 * @param {readonly string[]} selectedLevels
 * @param {readonly PurdueLevel[]} [levels] for level labels; ids are used without it
 * @returns {{ effective: PlacedAsset[]; effectiveIds: string[]; boundaryCount: number;
 *             explicitOnly: string[]; memberships: number; overlapDropped: number;
 *             viaLevels: Array<{ levelKey: string; label: string; assetIds: string[] }> }}
 */
export function describeSelection(assets, selectedAssets, selectedLevels, levels = []) {
  const effective = resolveEffectiveAssets(assets, selectedAssets, selectedLevels);
  const labelFor = new Map(levels.map((l) => [l.levelKey, l.label]));

  const viaLevels = selectedLevels.map((levelKey) => ({
    levelKey,
    label: labelFor.get(levelKey) ?? levelKey,
    assetIds: assetsAtLevel(assets, levelKey).map((a) => a.attackId).sort(),
  }));

  // Level memberships summed WITHOUT de-duplication — the number the visitor
  // would arrive at by adding the per-level counts they can see.
  const memberships = viaLevels.reduce((n, v) => n + v.assetIds.length, 0);
  const fromLevels = new Set(viaLevels.flatMap((v) => v.assetIds));

  const effectiveIds = effective.map((a) => a.attackId);
  return {
    effective,
    effectiveIds,
    boundaryCount: effective.filter((a) => a.isBoundary).length,
    // Ticked by hand and not reachable through any picked level — so the view
    // can say which picks the levels did not already cover.
    explicitOnly: [...new Set(selectedAssets)].filter((id) => !fromLevels.has(id)).sort(),
    memberships,
    overlapDropped: Math.max(0, memberships - fromLevels.size),
    viaLevels,
  };
}

/**
 * Levels that hold no asset at all and must therefore never be a live option.
 *
 * Derived from the data, not hardcoded to `l5`: if MITRE ever places an asset
 * at Enterprise IT the row becomes selectable on its own, and if some other
 * level empties out it stops being offered without anyone remembering to
 * change a constant here.
 *
 * @param {readonly PurdueLevel[]} levels
 * @param {readonly PlacedAsset[]} assets
 * @returns {string[]} level keys
 */
export function emptyLevelKeys(levels, assets) {
  return levels.filter((l) => assetsAtLevel(assets, l.levelKey).length === 0).map((l) => l.levelKey);
}
