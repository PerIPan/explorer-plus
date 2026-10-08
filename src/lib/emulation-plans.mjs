// src/lib/emulation-plans.mjs — pure, no I/O. Tested by
// scripts/lib/emulation-plans.test.mjs; used by scripts/sync-emulation.mjs and the
// /frameworks/emulation page.
//
// The CTID Adversary Emulation Library, as plan files -> ATT&CK groups.
//
// WHY A HAND-CURATED REGISTRY
// The plan files carry `adversary_name` as free text ("APT29", "Sandworm Team
// (G0034)", "Turla - Snake") and only one of ten carries a group id. Matching
// names against `threat_groups.aliases` would be a fuzzy join we would then
// present as fact, so the file -> group link is written down here instead,
// one line per plan, where a reviewer can check it against
// attack.mitre.org/groups. All ten resolved on the live site on 2026-10-08.
//
// WHAT IS NOT INGESTED, AND WHY (rendered on /frameworks/emulation)
// Blind Eagle (G0099) and OceanLotus (G0050) ship their plans as Markdown
// scenarios with no machine-readable step list, and the micro emulation plans
// are READMEs whose technique mentions are prose, not steps. Scraping T-numbers
// out of prose would turn "see also T1055" into "this plan exercises T1055".
//
// WHAT IS NOT STORED
// Executor commands and payload names. A plan step's command only runs inside
// CTID's kit (its C2 server, its payload binaries, its input arguments), so on
// its own it is live attack code with no use to a reader. Each step links to
// its file upstream instead.

export const EMULATION_REPO = 'center-for-threat-informed-defense/adversary_emulation_library';
export const EMULATION_BRANCH = 'master';
export const EMULATION_LICENSE = 'Apache-2.0';

/**
 * @typedef {Object} PlanEntry
 * @property {string} planKey        URL slug, `^[a-z0-9-]+$`.
 * @property {string} path           File path inside the repo.
 * @property {string} attackGroupId  ATT&CK group, `^G\d{4}$`.
 */

/** @type {readonly PlanEntry[]} */
export const EMULATION_PLANS = Object.freeze([
  { planKey: 'apt29', path: 'apt29/Emulation_Plan/yaml/APT29.yaml', attackGroupId: 'G0016' },
  { planKey: 'carbanak', path: 'carbanak/Emulation_Plan/yaml/Carbanak.yaml', attackGroupId: 'G0008' },
  { planKey: 'fin6', path: 'fin6/Emulation_Plan/yaml/FIN6.yaml', attackGroupId: 'G0037' },
  { planKey: 'fin7', path: 'fin7/Emulation_Plan/yaml/Fin7.yaml', attackGroupId: 'G0046' },
  { planKey: 'menupass', path: 'menu_pass/Emulation_Plan/yaml/menupass.yaml', attackGroupId: 'G0045' },
  { planKey: 'oilrig', path: 'oilrig/Emulation_Plan/yaml/oilrig.yaml', attackGroupId: 'G0049' },
  { planKey: 'sandworm', path: 'sandworm/Emulation_Plan/yaml/sandworm.yaml', attackGroupId: 'G0034' },
  { planKey: 'turla-carbon', path: 'turla/Emulation_Plan/yaml/turla_carbon.yaml', attackGroupId: 'G0010' },
  { planKey: 'turla-snake', path: 'turla/Emulation_Plan/yaml/turla_snake.yaml', attackGroupId: 'G0010' },
  { planKey: 'wizard-spider', path: 'wizard_spider/Emulation_Plan/yaml/wizard_spider.yaml', attackGroupId: 'G0102' },
]);

/** Plans that exist upstream but are deliberately not ingested — see header. */
export const NOT_INGESTED = Object.freeze([
  { label: 'Blind Eagle', attackGroupId: 'G0099', path: 'blind_eagle', reason: 'Markdown scenario only; no machine-readable step list.' },
  { label: 'OceanLotus', attackGroupId: 'G0050', path: 'ocean_lotus', reason: 'Markdown scenario only; no machine-readable step list.' },
  { label: 'Micro emulation plans (11)', attackGroupId: null, path: 'micro_emulation_plans', reason: 'Technique-focused READMEs, not adversary plans; technique mentions are prose, not steps.' },
]);

const TECHNIQUE_RE = /^T\d{4}(\.\d{3})?$/;

/**
 * @typedef {Object} NormalizedStep
 * @property {string} stepUid
 * @property {number} ordinal         1-based, file order.
 * @property {string | null} procedureStep
 * @property {string} name
 * @property {string | null} description
 * @property {string | null} tacticRaw
 * @property {string | null} attackTechniqueId   As written upstream, trimmed (may be junk).
 * @property {string | null} validTechniqueId    Same, only when it is a T-number.
 * @property {string[]} platforms
 * @property {string | null} ctiSource
 *
 * @typedef {Object} NormalizedPlan
 * @property {{ name: string; upstreamPlanId: string | null; attackVersion: string | null }} plan
 * @property {NormalizedStep[]} steps
 * @property {string[]} warnings
 */

/** @param {unknown} v */
function text(v) {
  if (v == null) return null;
  const s = String(v).trim();
  return s.length > 0 ? s : null;
}

/**
 * Turn one parsed plan file (the YAML document as a JS value) into rows.
 *
 * Pure over an already-parsed document so the tests need no YAML parser and
 * the ingest script owns the only dependency. Never throws on a bad step: a
 * step with a junk technique id ("x", "7.A.5") is kept with
 * `validTechniqueId: null` — it is still a step in the plan, and dropping it
 * would renumber the procedure. Throws only when the file is not a plan at all.
 *
 * Duplicate step ids are suffixed (`<id>#2`) rather than dropped, because the
 * table's UNIQUE (plan_id, step_uid) would otherwise abort the whole ingest on
 * an upstream copy-paste; the suffix is reported in `warnings`.
 *
 * @param {unknown} doc
 * @returns {NormalizedPlan}
 */
export function normalizePlan(doc) {
  if (!Array.isArray(doc) || doc.length === 0) {
    throw new Error('plan file is not a YAML list');
  }
  const header = doc.find((el) => el && typeof el === 'object' && 'emulation_plan_details' in el);
  if (!header) throw new Error('plan file has no emulation_plan_details element');
  const details = /** @type {Record<string, unknown>} */ (header.emulation_plan_details ?? {});

  const name = text(details.adversary_name);
  if (!name) throw new Error('emulation_plan_details.adversary_name is empty');

  /** @type {string[]} */
  const warnings = [];
  /** @type {NormalizedStep[]} */
  const steps = [];
  /** @type {Map<string, number>} */
  const seen = new Map();

  for (const el of doc) {
    if (!el || typeof el !== 'object' || 'emulation_plan_details' in el) continue;
    const raw = /** @type {Record<string, any>} */ (el);
    const id = text(raw.id);
    const stepName = text(raw.name);
    if (!id || !stepName) {
      warnings.push(`skipped an element without id/name at position ${steps.length + 1}`);
      continue;
    }

    const n = (seen.get(id) ?? 0) + 1;
    seen.set(id, n);
    const stepUid = n === 1 ? id : `${id}#${n}`;
    if (n > 1) warnings.push(`duplicate step id ${id} kept as ${stepUid}`);

    const attackTechniqueId = text(raw.technique?.attack_id);
    const validTechniqueId = attackTechniqueId && TECHNIQUE_RE.test(attackTechniqueId) ? attackTechniqueId : null;

    const platforms =
      raw.platforms && typeof raw.platforms === 'object' && !Array.isArray(raw.platforms)
        ? Object.keys(raw.platforms).map((p) => p.trim().toLowerCase()).filter(Boolean).sort()
        : [];

    steps.push({
      stepUid,
      ordinal: steps.length + 1,
      procedureStep: text(raw.procedure_step),
      name: stepName,
      description: text(raw.description),
      tacticRaw: text(raw.tactic),
      attackTechniqueId,
      validTechniqueId,
      platforms,
      ctiSource: text(raw.cti_source),
    });
  }

  return {
    plan: {
      name,
      upstreamPlanId: text(details.id),
      attackVersion: text(details.attack_version),
    },
    steps,
    warnings,
  };
}

/**
 * Upstream link for a plan file at a commit (or the branch when no commit is
 * recorded).
 *
 * @param {string} path
 * @param {string | null | undefined} commit
 * @returns {string}
 */
export function upstreamUrl(path, commit) {
  return `https://github.com/${EMULATION_REPO}/blob/${commit || EMULATION_BRANCH}/${path}`;
}
